import logging
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

logger = logging.getLogger(__name__)

# Module-level MongoDB client and database references
client: AsyncIOMotorClient = None
db = None


async def init_db():
    """
    Initialize MongoDB connection and create indexes.
    Called on FastAPI startup event.
    """
    global client, db
    try:
        # Set a short timeout so Vercel doesn't block forever if the MongoDB URI is unreachable
        client = AsyncIOMotorClient(settings.MONGODB_URI, serverSelectionTimeoutMS=2000)
        db = client[settings.MONGODB_DATABASE]

        # Create indexes for performance (this will trigger a connection attempt)
        await db.analyses.create_index("analysis_id", unique=True)
        await db.analyses.create_index("timestamp")
        await db.analyses.create_index("risk_level")
        await db.analyses.create_index("input_type")
        await db.ai_cache.create_index("cache_key", unique=True)

        logger.info(f"MongoDB connected: {settings.MONGODB_URI} / {settings.MONGODB_DATABASE}")
    except Exception as e:
        logger.error(f"Failed to initialize/index MongoDB (is the database unreachable?): {str(e)}")


async def close_db():
    """
    Close MongoDB connection.
    Called on FastAPI shutdown event.
    """
    global client
    if client:
        client.close()
        logger.info("MongoDB connection closed.")


def get_db():
    """
    Returns the database instance for use in routes/services.
    """
    return db


async def save_analysis(analysis_data: dict):
    """
    Upsert an analysis document into the analyses collection.
    MongoDB stores nested dicts/lists natively — no JSON serialization needed.
    """
    doc = {**analysis_data}
    await db.analyses.update_one(
        {"analysis_id": doc["analysis_id"]},
        {"$set": doc},
        upsert=True
    )


async def get_analyses_history(
    page: int = 1,
    page_size: int = 20,
    risk_level: str = None,
    input_type: str = None,
    sort_order: str = "desc"
):
    """
    Retrieves paginated analysis history with optional filters.
    Returns (items_list, total_count).
    """
    query = {}
    if risk_level:
        query["risk_level"] = risk_level
    if input_type:
        query["input_type"] = input_type

    sort_dir = -1 if sort_order == "desc" else 1
    total = await db.analyses.count_documents(query)

    cursor = (
        db.analyses
        .find(query, {"_id": 0})
        .sort("timestamp", sort_dir)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    items = await cursor.to_list(length=page_size)

    # Truncate raw_input to 200 chars in list view for preview
    for item in items:
        if "raw_input" in item and item["raw_input"]:
            item["raw_input"] = item["raw_input"][:200]

    return items, total


async def get_analysis_by_id(analysis_id: str):
    """
    Retrieves a single analysis document by its analysis_id.
    Returns the full document (including un-truncated raw_input).
    """
    doc = await db.analyses.find_one(
        {"analysis_id": analysis_id},
        {"_id": 0}
    )
    return doc


async def check_db_health() -> bool:
    """
    Quick health check — pings MongoDB to verify connectivity.
    """
    try:
        await db.command("ping")
        return True
    except Exception:
        return False
