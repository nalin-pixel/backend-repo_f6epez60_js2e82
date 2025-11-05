"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Model name lowercased is the collection name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    role: str = Field("customer", description="Role: customer | admin")
    address: Optional[str] = None

class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category: str
    images: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    in_stock: bool = True
    colors: List[str] = Field(default_factory=list)
    sizes: List[str] = Field(default_factory=list)
    rating: float = Field(default=0, ge=0, le=5)

class Cart(BaseModel):
    user_id: str
    items: List[dict] = Field(default_factory=list, description="[{product_id, quantity, size?, color?}]")
