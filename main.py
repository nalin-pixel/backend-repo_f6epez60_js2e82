import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db
from schemas import User as UserSchema, Product as ProductSchema, Cart as CartSchema

# JWT Config
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    _id = doc.get("_id")
    if isinstance(_id, ObjectId):
        doc["id"] = str(_id)
        del doc["_id"]
    # Convert ObjectId in nested fields if any
    for k, v in list(doc.items()):
        if isinstance(v, ObjectId):
            doc[k] = str(v)
    return doc


# Auth models
class RegisterInput(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


# Dependency to get current user

def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)


# Routes
@app.get("/")
def read_root():
    return {"message": "Fashion Shop API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["database_url"] = "✅ Set"
            response["database_name"] = db.name
            response["collections"] = db.list_collection_names()
        else:
            response["database"] = "❌ Not Available"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterInput):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_model = UserSchema(
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role="customer",
    )
    result = db["user"].insert_one(user_model.model_dump())
    user_id = str(result.inserted_id)
    token = create_access_token({"sub": user_id})
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    user = serialize_doc(user)
    # Never send password hash
    user.pop("password_hash", None)
    return TokenResponse(access_token=token, user=user)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginInput):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    user_id = str(user["_id"]) if isinstance(user.get("_id"), ObjectId) else user.get("_id")
    token = create_access_token({"sub": user_id})
    user = serialize_doc(user)
    user.pop("password_hash", None)
    return TokenResponse(access_token=token, user=user)


@app.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return current_user


# Products
class ProductIn(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    images: List[str] = []
    tags: List[str] = []
    in_stock: bool = True
    colors: List[str] = []
    sizes: List[str] = []


@app.post("/products")
def create_product(data: ProductIn, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    product = ProductSchema(**data.model_dump())
    res = db["product"].insert_one(product.model_dump())
    created = db["product"].find_one({"_id": res.inserted_id})
    return serialize_doc(created)


@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, min_price: Optional[float] = None, max_price: Optional[float] = None, in_stock: Optional[bool] = None, sort: Optional[str] = None, limit: int = 20, page: int = 1):
    query: Dict[str, Any] = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
            {"category": {"$regex": q, "$options": "i"}},
        ]
    if category:
        query["category"] = category
    price_filter: Dict[str, Any] = {}
    if min_price is not None:
        price_filter["$gte"] = float(min_price)
    if max_price is not None:
        price_filter["$lte"] = float(max_price)
    if price_filter:
        query["price"] = price_filter
    if in_stock is not None:
        query["in_stock"] = in_stock

    collection = db["product"]
    cursor = collection.find(query)
    if sort:
        if sort == "price_asc":
            cursor = cursor.sort("price", 1)
        elif sort == "price_desc":
            cursor = cursor.sort("price", -1)
        elif sort == "new":
            cursor = cursor.sort("created_at", -1)

    total = cursor.count() if hasattr(cursor, 'count') else collection.count_documents(query)

    skip = max(page - 1, 0) * limit
    cursor = cursor.skip(skip).limit(limit)
    items = [serialize_doc(d) for d in cursor]
    return {"items": items, "total": total, "page": page, "limit": limit}


@app.get("/products/{product_id}")
def get_product(product_id: str):
    try:
        obj_id = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product id")
    product = db["product"].find_one({"_id": obj_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return serialize_doc(product)


class ProductUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    images: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    in_stock: Optional[bool] = None
    colors: Optional[List[str]] = None
    sizes: Optional[List[str]] = None


@app.put("/products/{product_id}")
def update_product(product_id: str, data: ProductUpdate, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    try:
        obj_id = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product id")
    update_dict = {k: v for k, v in data.model_dump(exclude_unset=True).items()}
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")
    update_dict["updated_at"] = datetime.now(timezone.utc)
    res = db["product"].update_one({"_id": obj_id}, {"$set": update_dict})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    product = db["product"].find_one({"_id": obj_id})
    return serialize_doc(product)


@app.delete("/products/{product_id}")
def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    try:
        obj_id = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product id")
    res = db["product"].delete_one({"_id": obj_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}


# Cart
class CartItem(BaseModel):
    product_id: str
    quantity: int = 1
    size: Optional[str] = None
    color: Optional[str] = None


@app.get("/cart")
def get_cart(current_user: dict = Depends(get_current_user)):
    cart = db["cart"].find_one({"user_id": current_user["id"]})
    if not cart:
        cart = {"user_id": current_user["id"], "items": []}
        db["cart"].insert_one(cart)
    # attach product details
    items = []
    for it in cart.get("items", []):
        prod = db["product"].find_one({"_id": ObjectId(it["product_id"])}) if ObjectId.is_valid(it.get("product_id", "")) else None
        items.append({**it, "product": serialize_doc(prod) if prod else None})
    return {"id": str(cart.get("_id")) if cart.get("_id") else None, "user_id": cart["user_id"], "items": items}


@app.post("/cart")
def add_to_cart(item: CartItem, current_user: dict = Depends(get_current_user)):
    # ensure product exists
    if not ObjectId.is_valid(item.product_id):
        raise HTTPException(status_code=400, detail="Invalid product id")
    prod = db["product"].find_one({"_id": ObjectId(item.product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    cart = db["cart"].find_one({"user_id": current_user["id"]})
    if not cart:
        cart = {"user_id": current_user["id"], "items": []}
        db["cart"].insert_one(cart)
        cart = db["cart"].find_one({"user_id": current_user["id"]})
    # merge if same spec
    items = cart.get("items", [])
    merged = False
    for it in items:
        if it["product_id"] == item.product_id and it.get("size") == item.size and it.get("color") == item.color:
            it["quantity"] = int(it.get("quantity", 1)) + int(item.quantity)
            merged = True
            break
    if not merged:
        items.append(item.model_dump())
    db["cart"].update_one({"_id": cart["_id"]}, {"$set": {"items": items, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


class UpdateCartItem(BaseModel):
    product_id: str
    quantity: Optional[int] = None
    size: Optional[str] = None
    color: Optional[str] = None
    remove: Optional[bool] = False


@app.patch("/cart")
def update_cart(item: UpdateCartItem, current_user: dict = Depends(get_current_user)):
    cart = db["cart"].find_one({"user_id": current_user["id"]})
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    items = cart.get("items", [])
    new_items = []
    for it in items:
        if it["product_id"] == item.product_id and (item.size is None or it.get("size") == item.size) and (item.color is None or it.get("color") == item.color):
            if item.remove or (item.quantity is not None and item.quantity <= 0):
                continue
            if item.quantity is not None:
                it["quantity"] = int(item.quantity)
        new_items.append(it)
    db["cart"].update_one({"_id": cart["_id"]}, {"$set": {"items": new_items, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


@app.delete("/cart")
def clear_cart(current_user: dict = Depends(get_current_user)):
    db["cart"].update_one({"user_id": current_user["id"]}, {"$set": {"items": [], "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
