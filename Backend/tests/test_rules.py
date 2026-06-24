import pytest
from app.services.rules import generate_detection_rules

def test_rules_disabled():
    # If disabled, should return empty strings for all rule types
    res = generate_detection_rules([], {}, "High", enabled=False)
    assert res == {"sigma": "", "yara": "", "splunk": "", "kql": ""}


def test_rules_empty_iocs():
    # If no IOCs are passed, it should return placeholder instructions in all rules
    enrichment = {"malware_families": ["LockBit 3.0"]}
    res = generate_detection_rules([], enrichment, "Critical", enabled=True)
    
    assert "No network or file IOCs were extracted" in res["sigma"]
    assert "No network or file IOCs were extracted" in res["yara"]
    assert "No network or file IOCs were extracted" in res["splunk"]
    assert "No network or file IOCs were extracted" in res["kql"]


def test_rule_generation_full():
    iocs = [
        {"type": "IPv4", "value": "185.220.101.5", "reputation": "Malicious"},
        {"type": "Domain", "value": "update.cloudservices-api.com", "reputation": "Malicious"},
        {"type": "SHA256", "value": "6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678", "reputation": "Malicious"}
    ]
    enrichment = {
        "malware_families": ["ShadowPad"],
        "threat_actors": ["APT41"]
    }
    
    res = generate_detection_rules(iocs, enrichment, "Critical", enabled=True)
    
    # 1. Check Sigma rule contents
    assert "File Hash Detection" in res["sigma"]
    assert "Network IOC Detection" in res["sigma"]
    assert "6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678" in res["sigma"]
    assert "update.cloudservices-api.com" in res["sigma"]
    assert "185.220.101.5" in res["sigma"]
    assert "level: critical" in res["sigma"]
    
    # 2. Check YARA rule contents
    assert "rule Sentinel_Auto_ShadowPad" in res["yara"]
    assert "$hash_1 = \"6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678\"" in res["yara"]
    assert "$domain_2 = \"update.cloudservices-api.com\"" in res["yara"]
    assert "$ip_3 = \"185.220.101.5\"" in res["yara"]
    
    # 3. Check Splunk SPL
    assert "index=security" in res["splunk"]
    assert "dest_ip=\"185.220.101.5\"" in res["splunk"]
    assert "query=\"*update.cloudservices-api.com*\"" in res["splunk"]
    assert "file_hash=\"6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678\"" in res["splunk"]
    
    # 4. Check Sentinel KQL
    assert "DeviceNetworkEvents" in res["kql"]
    assert "RemoteIP in (\"185.220.101.5\")" in res["kql"]
    assert "DomainName has_any (\"update.cloudservices-api.com\")" in res["kql"]
    assert "SHA256 in (\"6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678\")" in res["kql"]
