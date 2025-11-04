import os
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "campus_resource_sharing")

_client: AsyncIOMotorClient | None = None
_db = None

async def get_db():
    global _client, _db
    if _client is None:
        _client = AsyncIOMotorClient(DATABASE_URL)
        _db = _client[DATABASE_NAME]
    return _db

async def create_document(collection_name: str, data: dict):
    db = await get_db()
    now = datetime.utcnow()
    data["created_at"] = now
    data["updated_at"] = now
    res = await db[collection_name].insert_one(data)
    data["_id"] = res.inserted_id
    return data

async def get_documents(collection_name: str, filter_dict: dict | None = None, limit: int | None = None):
    db = await get_db()
    cursor = db[collection_name].find(filter_dict or {}).sort("created_at", -1)
    if limit:
        cursor = cursor.limit(limit)
    return [doc async for doc in cursor]
