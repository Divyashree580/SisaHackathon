import pytest
from app.services.extractor import extract_iocs

def test_extract_ips():
    # Test malicious IP, private IP, benign IP, and plain IP
    text = (
        "Malicious connection to C2 IP 185.220.101.5. "
        "Internal IP 192.168.1.100 was scanning port 80. "
        "Also saw Shodan crawler at 198.51.100.42. "
        "Random IP is 8.8.8.8."
    )
    iocs = extract_iocs(text)
    
    ips = [i for i in iocs if i["type"] == "IPv4"]
    assert len(ips) == 4
    
    # Check reputation assignment
    malicious_ip = next(i for i in ips if i["value"] == "185.220.101.5")
    assert malicious_ip["reputation"] == "Malicious"
    assert malicious_ip["enriched"] is True
    
    internal_ip = next(i for i in ips if i["value"] == "192.168.1.100")
    assert internal_ip["reputation"] == "Internal/RFC1918"
    assert internal_ip["enriched"] is True
    
    benign_ip = next(i for i in ips if i["value"] == "198.51.100.42")
    assert benign_ip["reputation"] == "Benign/Scanner"
    assert benign_ip["enriched"] is True

    random_ip = next(i for i in ips if i["value"] == "8.8.8.8")
    assert random_ip["reputation"] == "Suspicious"
    assert random_ip["enriched"] is False


def test_extract_hashes_longest_match():
    # Longest match wins deduplication test
    # SHA256 has 64 chars. A SHA256 hash shouldn't trigger MD5 (32 chars) or SHA1 (40 chars) matches inside it.
    sha256_hash = "6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678"
    text = f"Malicious executable SHA256: {sha256_hash}"
    iocs = extract_iocs(text)
    
    hashes = [i for i in iocs if i["type"] in ("MD5", "SHA1", "SHA256")]
    assert len(hashes) == 1
    assert hashes[0]["type"] == "SHA256"
    assert hashes[0]["value"] == sha256_hash


def test_extract_hashes_individual():
    text = (
        "MD5: c4ca4238a0b923820dcc509a6f75849b and "
        "SHA1: 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e"
    )
    iocs = extract_iocs(text)
    
    md5_ioc = next(i for i in iocs if i["type"] == "MD5")
    assert md5_ioc["value"] == "c4ca4238a0b923820dcc509a6f75849b"
    
    sha1_ioc = next(i for i in iocs if i["type"] == "SHA1")
    assert sha1_ioc["value"] == "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e"


def test_extract_domains_and_exclusions():
    # Test exclusions: google.com (benign), file.exe (looks like domain but is extension)
    text = (
        "Visited google.com, download.exe, update.cloudservices-api.com. "
        "Also malicious-site.org was accessed."
    )
    iocs = extract_iocs(text)
    domains = [i for i in iocs if i["type"] == "Domain"]
    
    # google.com and download.exe should be filtered out
    assert not any(d["value"] == "google.com" for d in domains)
    assert not any(d["value"] == "download.exe" for d in domains)
    
    # update.cloudservices-api.com should be extracted as malicious
    mal_dom = next(d for d in domains if d["value"] == "update.cloudservices-api.com")
    assert mal_dom["reputation"] == "Malicious"
    
    # malicious-site.org should be extracted as suspicious
    susp_dom = next(d for d in domains if d["value"] == "malicious-site.org")
    assert susp_dom["reputation"] == "Suspicious"


def test_extract_cves():
    text = "We are checking vulnerability cve-2023-4966 and CVE-2023-46604."
    iocs = extract_iocs(text)
    cves = [i for i in iocs if i["type"] == "CVE ID"]
    
    assert len(cves) == 2
    assert any(c["value"] == "CVE-2023-4966" for c in cves)
    assert any(c["value"] == "CVE-2023-46604" for c in cves)


def test_empty_text():
    assert extract_iocs("") == []
    assert extract_iocs(None) == []
