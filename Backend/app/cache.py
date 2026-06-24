import hashlib
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

# In-memory cache: { sha256_hash: analysis_dict }
_memory_cache: dict = {}
_cache_lock = threading.Lock()


def compute_cache_key(content: str) -> str:
    """
    Generates a SHA256 hash of the input content for use as a cache key.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_from_memory_cache(key: str) -> dict | None:
    """
    Check in-memory cache for a previously stored analysis response.
    """
    with _cache_lock:
        return _memory_cache.get(key)


async def get_from_cache(key: str, db) -> dict | None:
    """
    Two-tier cache lookup:
    1. Check in-memory dict (fastest)
    2. If miss, check MongoDB ai_cache collection (persistent)
    On MongoDB hit, warm the in-memory cache for future lookups.
    """
    # Tier 1: In-memory
    result = get_from_memory_cache(key)
    if result:
        logger.info(f"Cache HIT (in-memory) for key {key[:12]}...")
        return result

    # Tier 2: MongoDB
    doc = await db.ai_cache.find_one({"cache_key": key})
    if doc:
        doc.pop("_id", None)
        data = doc.get("response")
        with _cache_lock:
            _memory_cache[key] = data  # Warm in-memory cache
        logger.info(f"Cache HIT (MongoDB) for key {key[:12]}...")
        return data

    logger.info(f"Cache MISS for key {key[:12]}...")
    return None


async def store_in_cache(key: str, response: dict, db):
    """
    Stores analysis response in both in-memory cache and MongoDB.
    Uses upsert to handle duplicates gracefully.
    """
    with _cache_lock:
        _memory_cache[key] = response

    await db.ai_cache.update_one(
        {"cache_key": key},
        {"$set": {
            "cache_key": key,
            "response": response,
            "created_at": datetime.utcnow()
        }},
        upsert=True
    )
    logger.info(f"Cache STORED for key {key[:12]}...")
