from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from typing import Optional, List
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from bson import ObjectId
import os

from database import get_db, create_document, get_documents
from schemas import User, Item, BorrowRequest, Message

# JWT config
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Campus Resource Sharing Portal API")

# CORS
origins = [
    os.getenv("FRONTEND_URL", "*"),
    "*",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utils

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_from_token(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db = await get_db()
    user = await db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    return user

# Auth endpoints

@app.post("/auth/register")
async def register(name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    db = await get_db()
    existing = await db["user"].find_one({"email": email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = pwd_context.hash(password)
    user_doc = {
        "name": name,
        "email": email.lower(),
        "password": hashed,
        "trust_score": 0.0,
    }
    user_doc = await create_document("user", user_doc)
    token = create_access_token({"sub": str(user_doc["_id"])})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": str(user_doc["_id"]), "name": user_doc["name"], "email": user_doc["email"], "trust_score": user_doc["trust_score"]},
    }

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = await get_db()
    user = await db["user"].find_one({"email": form_data.username.lower()})
    if not user or not pwd_context.verify(form_data.password, user.get("password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "trust_score": user.get("trust_score", 0.0)},
    }

@app.get("/users/me")
async def me(current_user: dict = Depends(get_user_from_token)):
    return {
        "id": str(current_user["_id"]),
        "name": current_user["name"],
        "email": current_user["email"],
        "trust_score": current_user.get("trust_score", 0.0),
    }

# Items

@app.post("/items")
async def create_item(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    category: str = Form(...),
    condition: str = Form("Good"),
    available_from: Optional[str] = Form(None),
    available_to: Optional[str] = Form(None),
    deposit: Optional[float] = Form(0),
    current_user: dict = Depends(get_user_from_token),
):
    from datetime import datetime
    af = datetime.fromisoformat(available_from) if available_from else None
    at = datetime.fromisoformat(available_to) if available_to else None
    item_doc = {
        "title": title,
        "description": description,
        "category": category,
        "condition": condition,
        "owner_id": str(current_user["_id"]),
        "images": [],
        "available_from": af,
        "available_to": at,
        "is_available": True,
        "deposit": deposit,
    }
    item_doc = await create_document("item", item_doc)
    return {"id": str(item_doc["_id"]), **{k: v for k, v in item_doc.items() if k != "_id"}}

@app.get("/items")
async def list_items(q: Optional[str] = None, category: Optional[str] = None):
    db = await get_db()
    filter_q = {}
    if q:
        filter_q["title"] = {"$regex": q, "$options": "i"}
    if category:
        filter_q["category"] = category
    docs = await get_documents("item", filter_q)
    def map_doc(d):
        d["id"] = str(d.pop("_id"))
        return d
    return [map_doc(d) for d in docs]

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    db = await get_db()
    doc = await db["item"].find_one({"_id": ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    doc["id"] = str(doc.pop("_id"))
    return doc

@app.put("/items/{item_id}")
async def update_item(item_id: str, title: Optional[str] = Form(None), description: Optional[str] = Form(None), category: Optional[str] = Form(None), condition: Optional[str] = Form(None), current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    doc = await db["item"].find_one({"_id": ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    if str(doc["owner_id"]) != str(current_user["_id"]):
        raise HTTPException(403, "Not owner")
    updates = {k: v for k, v in {"title": title, "description": description, "category": category, "condition": condition}.items() if v is not None}
    updates["updated_at"] = datetime.utcnow()
    await db["item"].update_one({"_id": ObjectId(item_id)}, {"$set": updates})
    new_doc = await db["item"].find_one({"_id": ObjectId(item_id)})
    new_doc["id"] = str(new_doc.pop("_id"))
    return new_doc

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    doc = await db["item"].find_one({"_id": ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    if str(doc["owner_id"]) != str(current_user["_id"]):
        raise HTTPException(403, "Not owner")
    await db["item"].delete_one({"_id": ObjectId(item_id)})
    return {"ok": True}

# Borrow Requests

@app.post("/requests")
async def create_request(item_id: str = Form(...), start_date: str = Form(...), end_date: str = Form(...), current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    item = await db["item"].find_one({"_id": ObjectId(item_id)})
    if not item:
        raise HTTPException(404, "Item not found")
    if not item.get("is_available", True):
        raise HTTPException(400, "Item not available")
    start = datetime.fromisoformat(start_date)
    end = datetime.fromisoformat(end_date)
    req_doc = {
        "item_id": item_id,
        "borrower_id": str(current_user["_id"]),
        "owner_id": item["owner_id"],
        "start_date": start,
        "end_date": end,
        "status": "pending",
    }
    req_doc = await create_document("borrowrequest", req_doc)
    return {"id": str(req_doc["_id"]), **{k: v for k, v in req_doc.items() if k != "_id"}}

@app.get("/requests")
async def list_requests(view: str = "all", current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    if view == "sent":
        flt = {"borrower_id": str(current_user["_id"])}
    elif view == "received":
        flt = {"owner_id": str(current_user["_id"])}
    else:
        flt = {"$or": [{"borrower_id": str(current_user["_id"])}, {"owner_id": str(current_user["_id"])}]}
    docs = await get_documents("borrowrequest", flt)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs

@app.post("/requests/{req_id}/approve")
async def approve_request(req_id: str, current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    req = await db["borrowrequest"].find_one({"_id": ObjectId(req_id)})
    if not req:
        raise HTTPException(404, "Request not found")
    if str(req["owner_id"]) != str(current_user["_id"]):
        raise HTTPException(403, "Not owner")
    await db["borrowrequest"].update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "approved", "updated_at": datetime.utcnow()}})
    await db["item"].update_one({"_id": ObjectId(req["item_id"])}, {"$set": {"is_available": False, "updated_at": datetime.utcnow()}})
    return {"ok": True}

@app.post("/requests/{req_id}/reject")
async def reject_request(req_id: str, current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    req = await db["borrowrequest"].find_one({"_id": ObjectId(req_id)})
    if not req:
        raise HTTPException(404, "Request not found")
    if str(req["owner_id"]) != str(current_user["_id"]):
        raise HTTPException(403, "Not owner")
    await db["borrowrequest"].update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "rejected", "updated_at": datetime.utcnow()}})
    return {"ok": True}

@app.post("/requests/{req_id}/return")
async def return_request(req_id: str, current_user: dict = Depends(get_user_from_token)):
    db = await get_db()
    req = await db["borrowrequest"].find_one({"_id": ObjectId(req_id)})
    if not req:
        raise HTTPException(404, "Request not found")
    if str(req["borrower_id"]) != str(current_user["_id"]) and str(req["owner_id"]) != str(current_user["_id"]):
        raise HTTPException(403, "Not participant")
    status_val = "returned"
    late = datetime.utcnow() > req["end_date"]
    if late:
        status_val = "late"
    await db["borrowrequest"].update_one({"_id": ObjectId(req_id)}, {"$set": {"status": status_val, "updated_at": datetime.utcnow()}})
    await db["item"].update_one({"_id": ObjectId(req["item_id"])}, {"$set": {"is_available": True, "updated_at": datetime.utcnow()}})
    # Update trust score of borrower
    borrower = await db["user"].find_one({"_id": ObjectId(req["borrower_id"])})
    score = borrower.get("trust_score", 0.0)
    score = max(0.0, score - 0.2) if late else score + 0.5
    await db["user"].update_one({"_id": ObjectId(req["borrower_id"])}, {"$set": {"trust_score": round(score, 2), "updated_at": datetime.utcnow()}})
    return {"ok": True, "late": late}

# Messaging (basic)

@app.post("/messages")
async def send_message(request_id: str = Form(...), receiver_id: str = Form(...), content: str = Form(...), current_user: dict = Depends(get_user_from_token)):
    msg = {
        "request_id": request_id,
        "sender_id": str(current_user["_id"]),
        "receiver_id": receiver_id,
        "content": content,
    }
    msg = await create_document("message", msg)
    return {"id": str(msg["_id"]), **{k: v for k, v in msg.items() if k != "_id"}}

@app.get("/messages/{request_id}")
async def list_messages(request_id: str, current_user: dict = Depends(get_user_from_token)):
    docs = await get_documents("message", {"request_id": request_id})
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs

@app.get("/test")
async def test_connection():
    db = await get_db()
    # A simple ping to ensure we can talk to the database
    await db.command("ping")
    return {"ok": True, "message": "Database connected"}
