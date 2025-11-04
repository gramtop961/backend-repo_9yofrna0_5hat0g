from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

# Each class name lowercased corresponds to collection name

class User(BaseModel):
    id: Optional[str] = None
    name: str
    email: EmailStr
    password: Optional[str] = None  # hashed
    trust_score: float = 0.0
    avatar_url: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Item(BaseModel):
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    category: str
    condition: str = "Good"
    owner_id: str
    images: List[str] = []
    available_from: Optional[datetime] = None
    available_to: Optional[datetime] = None
    is_available: bool = True
    deposit: Optional[float] = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class BorrowRequest(BaseModel):
    id: Optional[str] = None
    item_id: str
    borrower_id: str
    owner_id: str
    start_date: datetime
    end_date: datetime
    status: str = "pending"  # pending | approved | rejected | returned | late
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Message(BaseModel):
    id: Optional[str] = None
    request_id: str
    sender_id: str
    receiver_id: str
    content: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
