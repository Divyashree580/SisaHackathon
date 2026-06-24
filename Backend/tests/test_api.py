import pytest
from unittest.mock import AsyncMock, MagicMock

def test_health_endpoint(test_client):
    # Test health check connectivity and metrics
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert "metrics" in data
    assert data["dependencies"]["database"] is True


def test_analyze_threat_fresh_pipeline(test_client, mocker):
    # Test submission of new threat content running the full pipeline end-to-end
    mocker.patch("app.main.get_from_cache", AsyncMock(return_value=None))
    mocker.patch("app.main.store_in_cache", AsyncMock())
    mocker.patch("app.main.save_analysis", AsyncMock())
    
    # We patch fetch_nvd_cve and run_ai_analysis to prevent outgoing calls
    mocker.patch("app.services.enrichment.fetch_nvd_cve", AsyncMock(return_value=None))
    mocker.patch("app.services.ai.settings.GROQ_API_KEY", None) # trigger local heuristics
    
    payload = {
        "content": "ALERT: LockBit ransomware payload executed. C2 IP is 185.220.101.5.",
        "input_type": "text",
        "options": {
            "mitre_mapping": True,
            "generate_rules": True,
            "risk_scoring": True
        }
    }
    
    response = test_client.post("/api/analyze-threat", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Verify elements of pipeline execution output
    assert "analysis_id" in data
    assert data["input_type"] == "text"
    assert data["risk_level"] == "Critical" # due to ransomware keyword and IP reputation
    assert data["risk_score"] > 80
    assert len(data["iocs"]) >= 1
    assert data["iocs"][0]["value"] == "185.220.101.5"
    assert "sigma" in data["detection_rules"]
    assert "yara" in data["detection_rules"]


def test_analyze_threat_cache_hit(test_client, mocker):
    # Test endpoint when cache hit occurs
    cached_response = {
        "analysis_id": "cached-uuid-12345",
        "timestamp": "2026-06-24T00:00:00",
        "input_type": "text",
        "raw_input": "cached content",
        "cached": True,
        "risk_score": 50,
        "risk_level": "Medium",
        "iocs": [],
        "enrichment": {},
        "mitre_mapping": [],
        "ai_report": {},
        "detection_rules": {}
    }
    
    mocker.patch("app.main.get_from_cache", AsyncMock(return_value=cached_response))
    
    payload = {
        "content": "cached content",
        "input_type": "text"
    }
    
    response = test_client.post("/api/analyze-threat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"] == "cached-uuid-12345"
    assert data["cached"] is True


def test_analyze_threat_upload_file(test_client, mocker):
    # Test multipart document file upload endpoint
    mocker.patch("app.main.get_from_cache", AsyncMock(return_value=None))
    mocker.patch("app.main.store_in_cache", AsyncMock())
    mocker.patch("app.main.save_analysis", AsyncMock())
    mocker.patch("app.services.ai.settings.GROQ_API_KEY", None) # local heuristics
    
    file_payload = {"file": ("report.txt", b"Malicious campaign logs containing 185.220.101.5.")}
    form_data = {"options": '{"mitre_mapping": true, "generate_rules": true, "risk_scoring": true}'}
    
    response = test_client.post("/api/analyze-threat/upload", files=file_payload, data=form_data)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "file"
    assert len(data["iocs"]) >= 1
    assert data["iocs"][0]["value"] == "185.220.101.5"


def test_get_analyses_history(test_client, mocker):
    # Mock database history response with valid schema parameters
    mock_history = (
        [{
            "analysis_id": "uuid-1",
            "timestamp": "2026-06-24T00:00:00",
            "input_type": "text",
            "risk_score": 75,
            "risk_level": "High",
            "raw_input": "Threat brief content..."
        }],
        1
    )
    mocker.patch("app.main.get_analyses_history", AsyncMock(return_value=mock_history))
    
    response = test_client.get("/api/analyses?page=1&pageSize=10")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["analysis_id"] == "uuid-1"


def test_get_analysis_detail_success(test_client, mocker):
    analysis_uuid = "26562007-c1b6-4ef1-9a6e-68516c8a54fc"
    mock_record = {
        "analysis_id": analysis_uuid,
        "timestamp": "2026-06-24T00:00:00",
        "input_type": "text",
        "risk_score": 75,
        "risk_level": "High",
        "raw_input": "Full raw threat context detail text."
    }
    
    mocker.patch("app.main.get_analysis_by_id", AsyncMock(return_value=mock_record))
    
    response = test_client.get(f"/api/analyses/{analysis_uuid}")
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"] == analysis_uuid
    assert data["raw_input"] == "Full raw threat context detail text."


def test_get_analysis_detail_not_found(test_client, mocker):
    analysis_uuid = "00000000-0000-0000-0000-000000000000"
    mocker.patch("app.main.get_analysis_by_id", AsyncMock(return_value=None))
    
    response = test_client.get(f"/api/analyses/{analysis_uuid}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis record not found"


def test_get_analysis_detail_invalid_uuid(test_client):
    # Invalid UUID format should immediately fail with 400 Bad Request
    response = test_client.get("/api/analyses/invalid-uuid-format")
    assert response.status_code == 400
    assert "Invalid analysis_id format" in response.json()["detail"]
