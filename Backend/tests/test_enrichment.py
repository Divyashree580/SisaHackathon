import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.enrichment import enrich_analysis, fetch_nvd_cve

@pytest.mark.asyncio
async def test_enrich_cve_local_catalog():
    # CVE-2023-4966 is in the local catalog
    iocs = [{"type": "CVE ID", "value": "CVE-2023-4966", "enriched": False}]
    res = await enrich_analysis(iocs, "Citrix Bleed vulnerability exploited by LockBit.")
    
    assert res["cve_id"] == "CVE-2023-4966"
    assert res["cvss"] == 9.8
    assert res["severity"] == "Critical"
    assert "LockBit 3.0" in res["malware_families"]
    assert "LockBit" in res["threat_actors"]
    
    # Verify the CVE IOC was marked as enriched
    assert iocs[0]["enriched"] is True


@pytest.mark.asyncio
async def test_enrich_cve_nvd_api_mock(mocker):
    # Mocking fetch_nvd_cve for a CVE that is not in the local catalog (e.g. CVE-2022-99999)
    mock_nvd_res = {
        "cve_id": "CVE-2022-99999",
        "cvss": 8.5,
        "severity": "High",
        "description": "Mocked NVD description.",
        "exploit_available": False,
        "malware_families": [],
        "threat_actors": []
    }
    
    mocker.patch("app.services.enrichment.fetch_nvd_cve", return_value=mock_nvd_res)
    
    iocs = [{"type": "CVE ID", "value": "CVE-2022-99999", "enriched": False}]
    res = await enrich_analysis(iocs, "Vulnerability CVE-2022-99999 detected.")
    
    assert res["cve_id"] == "CVE-2022-99999"
    assert res["cvss"] == 8.5
    assert res["severity"] == "High"
    assert res["description"] == "Mocked NVD description."


@pytest.mark.asyncio
async def test_enrich_cve_nvd_api_failure_fallback(mocker):
    # If NVD lookup fails, it should fallback to generic details
    mocker.patch("app.services.enrichment.fetch_nvd_cve", return_value=None)
    
    iocs = [{"type": "CVE ID", "value": "CVE-2022-88888", "enriched": False}]
    res = await enrich_analysis(iocs, "Vulnerability CVE-2022-88888 detected.")
    
    assert res["cve_id"] == "CVE-2022-88888"
    assert res["cvss"] == 5.0  # fallback CVSS
    assert res["severity"] == "Medium"
    assert "details not available" in res["description"]


@pytest.mark.asyncio
async def test_enrich_no_cve_keyword_matching():
    # If no CVE is present, it should parse actor/malware keywords and make a general profile
    iocs = [{"type": "IPv4", "value": "8.8.8.8", "reputation": "Suspicious", "enriched": False}]
    res = await enrich_analysis(
        iocs,
        "Active ransomware campaign involving Cozy Bear actors and Cobalt Strike beacons. "
        "Critical RCE vulnerability details."
    )
    
    assert res["cve_id"] == "N/A"
    assert "APT29 / Nobelium / Cozy Bear" in res["threat_actors"]
    assert "Cobalt Strike Beacon" in res["malware_families"]
    assert res["severity"] == "Critical"  # due to 'ransomware' and 'rce' keywords
    assert res["cvss"] == 9.0


@pytest.mark.asyncio
async def test_enrich_known_ioc_reputation():
    # Test that common bad IPs/domains are assigned their context
    iocs = [
        {"type": "IPv4", "value": "185.220.101.5", "reputation": "Suspicious", "enriched": False},
        {"type": "Domain", "value": "update.cloudservices-api.com", "reputation": "Suspicious", "enriched": False}
    ]
    
    await enrich_analysis(iocs, "IOC logs.")
    
    ip_ioc = next(i for i in iocs if i["value"] == "185.220.101.5")
    assert ip_ioc["reputation"] == "Malicious"
    assert "Tor Exit Node" in ip_ioc["context"]
    assert ip_ioc["enriched"] is True
    
    dom_ioc = next(i for i in iocs if i["value"] == "update.cloudservices-api.com")
    assert dom_ioc["reputation"] == "Malicious"
    assert "ShadowPad" in dom_ioc["context"]
    assert dom_ioc["enriched"] is True


@pytest.mark.asyncio
async def test_fetch_nvd_cve_network_mock(mocker):
    # Mock httpx.AsyncClient response for fetch_nvd_cve
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-4966",
                    "descriptions": [{"lang": "en", "value": "Citrix Bleed vulnerability description."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }
    
    # Mocking httpx.AsyncClient instance
    mock_client = MagicMock()
    # Mock the get call as a coroutine
    mock_client.get = AsyncMock(return_value=mock_response)
    
    # Mock the context manager __aenter__ to return the mock client
    mocker.patch("httpx.AsyncClient.__aenter__", return_value=mock_client)
    
    res = await fetch_nvd_cve("CVE-2023-4966")
    
    assert res is not None
    assert res["cve_id"] == "CVE-2023-4966"
    assert res["cvss"] == 9.8
    assert res["severity"] == "Critical"
    assert "Citrix Bleed" in res["description"]
