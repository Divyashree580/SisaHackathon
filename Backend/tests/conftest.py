import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient

# Mock MongoDB globally before importing app components that might trigger database logic
@pytest.fixture(autouse=True)
def mock_mongodb(mocker):
    # Mock db and client
    mock_db = MagicMock()
    mock_client = MagicMock()
    
    # Mock collection objects
    mock_analyses = MagicMock()
    mock_ai_cache = MagicMock()
    
    # Mock async database calls
    mock_analyses.create_index = AsyncMock()
    mock_analyses.update_one = AsyncMock()
    mock_analyses.count_documents = AsyncMock()
    mock_analyses.delete_many = AsyncMock()
    
    # Mock cursors for find/sort/skip/limit pagination flow
    mock_cursor = MagicMock()
    mock_cursor.to_list = AsyncMock(return_value=[])
    mock_analyses.find.return_value = mock_cursor
    mock_cursor.sort.return_value = mock_cursor
    mock_cursor.skip.return_value = mock_cursor
    mock_cursor.limit.return_value = mock_cursor
    
    mock_analyses.find_one = AsyncMock(return_value=None)
    mock_ai_cache.create_index = AsyncMock()
    mock_ai_cache.find_one = AsyncMock(return_value=None)
    mock_ai_cache.update_one = AsyncMock()
    mock_ai_cache.delete_many = AsyncMock()
    
    mock_db.analyses = mock_analyses
    mock_db.ai_cache = mock_ai_cache
    mock_db.command = AsyncMock(return_value={"ok": 1.0})
    
    # Patch module variables in app.database
    mocker.patch("app.database.db", mock_db)
    mocker.patch("app.database.client", mock_client)
    
    # Patch init_db and close_db to prevent real Motor client initialization
    mocker.patch("app.database.init_db", AsyncMock())
    mocker.patch("app.database.close_db", AsyncMock())
    mocker.patch("app.database.check_db_health", AsyncMock(return_value=True))
    
    return mock_db

@pytest.fixture
def test_client():
    from app.main import app
    with TestClient(app) as client:
        yield client
