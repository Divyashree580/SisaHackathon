import pytest
from unittest.mock import MagicMock
from app.services.ai import run_ai_analysis, generate_fallback_ai_report

def test_fallback_ai_report_ransomware():
    text = "Incident showing encrypted files and vssadmin shadow deletions."
    iocs = [
        {"type": "IPv4", "value": "1.1.1.1"},
        {"type": "CVE ID", "value": "CVE-2023-4966"}
    ]
    res = generate_fallback_ai_report(text, iocs, mitre_enabled=True)
    
    report = res["ai_report"]
    assert "ransomware" in report["summary"].lower()
    assert "vssadmin" in report["attack_scenario"]
    assert "CRITICAL" in report["business_impact"]
    assert any("1.1.1.1" in act for act in report["immediate_actions"])
    
    # Check mitre mappings
    assert len(res["mitre_mapping"]) > 0
    assert any(m["technique_id"] == "T1486" for m in res["mitre_mapping"]) # Data Encrypted for Impact


def test_fallback_ai_report_phishing():
    text = "Urgent phishing email sent containing attachment."
    iocs = [
        {"type": "Domain", "value": "security-update-microsoft.com"}
    ]
    res = generate_fallback_ai_report(text, iocs, mitre_enabled=True)
    
    report = res["ai_report"]
    assert "phishing" in report["summary"].lower()
    assert "security-update-microsoft.com" in report["summary"]
    assert "HIGH" in report["business_impact"]
    assert any("security-update-microsoft.com" in act for act in report["immediate_actions"])


def test_ai_analysis_missing_key(mocker):
    # Temporarily set API key to None
    mocker.patch("app.services.ai.settings.GROQ_API_KEY", None)
    
    text = "Vulnerability CVE-2023-4966 Citrus Bleed."
    iocs = []
    
    # Should run fallback report directly
    res = run_ai_analysis(text, iocs, mitre_enabled=True)
    assert res is not None
    assert "ai_report" in res
    assert "mitre_mapping" in res


def test_ai_analysis_success(mocker):
    # Mock settings GROQ_API_KEY
    mocker.patch("app.services.ai.settings.GROQ_API_KEY", "mock_key")
    
    # Mock Groq client and its completions response
    mock_choice = MagicMock()
    mock_choice.message.content = """
    ```json
    {
      "mitre_mapping": [
        {
          "tactic": "Initial Access",
          "technique": "Exploit Public-Facing Application",
          "technique_id": "T1190",
          "confidence": "High"
        }
      ],
      "ai_report": {
        "summary": "Successful mock summary.",
        "attack_scenario": "1. Scan -> 2. Exploit",
        "business_impact": "High business damage.",
        "immediate_actions": ["Action A"],
        "long_term_remediation": ["Remediation B"],
        "monitoring": ["Monitor C"]
      }
    }
    ```
    """
    
    mock_completions = MagicMock()
    mock_completions.create.return_value = MagicMock(choices=[mock_choice])
    
    mock_client = MagicMock()
    mock_client.chat.completions = mock_completions
    
    mocker.patch("app.services.ai.Groq", return_value=mock_client)
    
    res = run_ai_analysis("Some threat text", [], mitre_enabled=True)
    
    assert res["ai_report"]["summary"] == "Successful mock summary."
    assert res["mitre_mapping"][0]["technique_id"] == "T1190"


def test_ai_analysis_parse_error_fallback(mocker):
    # Mock settings GROQ_API_KEY
    mocker.patch("app.services.ai.settings.GROQ_API_KEY", "mock_key")
    
    # Return invalid JSON from Groq API
    mock_choice = MagicMock()
    mock_choice.message.content = "Invalid JSON response"
    
    mock_completions = MagicMock()
    mock_completions.create.return_value = MagicMock(choices=[mock_choice])
    
    mock_client = MagicMock()
    mock_client.chat.completions = mock_completions
    
    mocker.patch("app.services.ai.Groq", return_value=mock_client)
    
    # Should fallback to heuristic report since JSON parsing fails
    res = run_ai_analysis("Active ransomware attack.", [], mitre_enabled=True)
    assert "ai_report" in res
    assert "ransomware" in res["ai_report"]["summary"].lower()
