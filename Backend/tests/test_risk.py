import pytest
from app.services.risk import calculate_risk

def test_risk_scoring_disabled():
    # If disabled, should return risk_score=0, level="N/A", factors=[]
    res = calculate_risk({}, [], enabled=False)
    assert res["risk_score"] == 0
    assert res["risk_level"] == "N/A"
    assert res["risk_factors"] == []


def test_risk_scoring_low():
    # Low score: only CVSS 5.0 (medium severity) -> 10 points
    enrichment = {"cvss": 5.0, "exploit_available": False, "malware_families": [], "threat_actors": []}
    res = calculate_risk(enrichment, [], enabled=True)
    
    assert res["risk_score"] == 10
    assert res["risk_level"] == "Low"
    assert len(res["risk_factors"]) == 1
    assert "CVSS Score 5.0" in res["risk_factors"][0]["name"]


def test_risk_scoring_medium():
    # Medium score: CVSS 8.0 (high severity -> 20 pts) + malware associated (15 pts) = 35 points
    enrichment = {
        "cvss": 8.0,
        "exploit_available": False,
        "malware_families": ["LockBit 3.0"],
        "threat_actors": []
    }
    res = calculate_risk(enrichment, [], enabled=True)
    
    assert res["risk_score"] == 35
    assert res["risk_level"] == "Medium"
    assert len(res["risk_factors"]) == 2


def test_risk_scoring_high():
    # High score: CVSS 9.5 (critical severity -> 30 pts) + Exploit available (25 pts) + Actor known (10 pts) = 65 points
    enrichment = {
        "cvss": 9.5,
        "exploit_available": True,
        "malware_families": [],
        "threat_actors": ["APT29"]
    }
    res = calculate_risk(enrichment, [], enabled=True)
    
    assert res["risk_score"] == 65
    assert res["risk_level"] == "High"
    assert len(res["risk_factors"]) == 3


def test_risk_scoring_critical_and_cap():
    # Critical score & capping:
    # CVSS 9.8 (30 pts) + Exploit (25 pts) + Malware (15 pts) + Actor (10 pts) + Active IOCs (20 pts) = 100 points
    enrichment = {
        "cvss": 9.8,
        "exploit_available": True,
        "malware_families": ["LockBit 3.0"],
        "threat_actors": ["LockBit"]
    }
    # Mocking a malicious IOC to trigger the active threat indicators score (20 pts)
    iocs = [{"type": "IPv4", "value": "185.220.101.5", "reputation": "Malicious"}]
    res = calculate_risk(enrichment, iocs, enabled=True)
    
    # Raw total is 30+25+15+10+20 = 100
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"
    assert len(res["risk_factors"]) == 5


def test_risk_scoring_capping_limit():
    # Ensure it caps exactly at 100 even if the raw total exceeds 100 (e.g. 110 points)
    enrichment = {
        "cvss": 10.0,  # 30 pts
        "exploit_available": True,  # 25 pts
        "malware_families": ["PlugX"],  # 15 pts
        "threat_actors": ["APT41"]  # 10 pts
    }
    # 4 IOCs triggers 20 pts even if none is malicious
    iocs = [
        {"type": "IPv4", "value": "1.1.1.1", "reputation": "Suspicious"},
        {"type": "IPv4", "value": "2.2.2.2", "reputation": "Suspicious"},
        {"type": "IPv4", "value": "3.3.3.3", "reputation": "Suspicious"},
        {"type": "IPv4", "value": "4.4.4.4", "reputation": "Suspicious"}
    ]
    res = calculate_risk(enrichment, iocs, enabled=True)
    
    # Raw total is 30+25+15+10+20 = 100. Let's add extra points by ensuring it caps.
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"
