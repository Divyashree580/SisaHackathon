import logging
import httpx
from typing import Dict, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# LOCAL CVE CATALOG (NVD fallback — expanded to 15 well-known CVEs)
# ──────────────────────────────────────────────────────────────────────────────
CVE_CATALOG = {
    "CVE-2023-4966": {
        "cve_id": "CVE-2023-4966",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Citrix NetScaler ADC and NetScaler Gateway buffer overflow vulnerability allowing sensitive information disclosure, leading to session hijacking (Citrix Bleed).",
        "exploit_available": True,
        "malware_families": ["LockBit 3.0", "LockBit Black"],
        "threat_actors": ["LockBit", "Gold Southfield"]
    },
    "CVE-2023-46604": {
        "cve_id": "CVE-2023-46604",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Apache ActiveMQ OpenWire protocol remote code execution vulnerability allowing unauthenticated remote execution of arbitrary JRE commands.",
        "exploit_available": True,
        "malware_families": ["Kinsing", "HelloKitty Ransomware"],
        "threat_actors": ["Kinsing Actors", "Threat Group 3390"]
    },
    "CVE-2023-38831": {
        "cve_id": "CVE-2023-38831",
        "cvss": 7.8,
        "severity": "High",
        "description": "WinRAR security bypass vulnerability allowing attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive.",
        "exploit_available": True,
        "malware_families": ["GraphicalProton", "EnvyScout"],
        "threat_actors": ["APT29", "Nobelium", "Cozy Bear"]
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Palo Alto Networks PAN-OS GlobalProtect gateway command injection vulnerability allowing unauthenticated attackers to execute arbitrary OS commands with root privileges.",
        "exploit_available": True,
        "malware_families": ["UPSTYLE Backdoor"],
        "threat_actors": ["UTA0218"]
    },
    "CVE-2023-22515": {
        "cve_id": "CVE-2023-22515",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Atlassian Confluence Data Center and Server broken access control vulnerability allowing remote attackers to create unauthorized administrator accounts.",
        "exploit_available": True,
        "malware_families": ["Cerber Ransomware"],
        "threat_actors": ["Storm-0062"]
    },
    "CVE-2023-34362": {
        "cve_id": "CVE-2023-34362",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Progress MOVEit Transfer SQL injection vulnerability allowing unauthenticated attackers to gain access to the database and execute arbitrary code.",
        "exploit_available": True,
        "malware_families": ["LemurLoot Web Shell"],
        "threat_actors": ["Clop Ransomware Gang", "FIN11"]
    },
    "CVE-2024-21887": {
        "cve_id": "CVE-2024-21887",
        "cvss": 9.1,
        "severity": "Critical",
        "description": "Ivanti Connect Secure and Policy Secure command injection vulnerability in web components allowing authenticated administrators to execute arbitrary commands.",
        "exploit_available": True,
        "malware_families": ["WIREFIRE Web Shell", "BUSHWALK"],
        "threat_actors": ["UTA0178", "Volt Typhoon"]
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Apache Log4j2 JNDI lookup vulnerability (Log4Shell) allowing remote code execution via crafted log messages containing JNDI lookup expressions.",
        "exploit_available": True,
        "malware_families": ["Khonsari Ransomware", "Mirai Botnet", "Cobalt Strike"],
        "threat_actors": ["APT41", "Lazarus Group", "Hafnium"]
    },
    "CVE-2024-23897": {
        "cve_id": "CVE-2024-23897",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Jenkins CLI arbitrary file read vulnerability allowing unauthenticated attackers to read files on the controller file system through the built-in CLI.",
        "exploit_available": True,
        "malware_families": ["RansomEXX"],
        "threat_actors": ["IntelBroker"]
    },
    "CVE-2023-27997": {
        "cve_id": "CVE-2023-27997",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Fortinet FortiOS and FortiProxy heap-based buffer overflow vulnerability in SSL-VPN allowing unauthenticated remote code execution.",
        "exploit_available": True,
        "malware_families": ["BoldMove Backdoor"],
        "threat_actors": ["Volt Typhoon", "APT15"]
    },
    "CVE-2023-20198": {
        "cve_id": "CVE-2023-20198",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Cisco IOS XE Web UI privilege escalation vulnerability allowing unauthenticated remote attackers to create privileged accounts on affected systems.",
        "exploit_available": True,
        "malware_families": ["BadCandy Implant"],
        "threat_actors": ["Unknown State-Sponsored"]
    },
    "CVE-2024-1709": {
        "cve_id": "CVE-2024-1709",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "ConnectWise ScreenConnect authentication bypass vulnerability allowing attackers to create administrative users and execute remote commands.",
        "exploit_available": True,
        "malware_families": ["LockBit 3.0", "AsyncRAT", "Cobalt Strike"],
        "threat_actors": ["LockBit", "Black Basta"]
    },
    "CVE-2023-36884": {
        "cve_id": "CVE-2023-36884",
        "cvss": 8.3,
        "severity": "High",
        "description": "Microsoft Office and Windows HTML remote code execution vulnerability exploited in targeted attacks using specially crafted Office documents.",
        "exploit_available": True,
        "malware_families": ["RomCom RAT"],
        "threat_actors": ["Storm-0978", "RomCom Group"]
    },
    "CVE-2023-23397": {
        "cve_id": "CVE-2023-23397",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Microsoft Outlook elevation of privilege vulnerability allowing attackers to steal NTLM hashes via specially crafted email messages without user interaction.",
        "exploit_available": True,
        "malware_families": [],
        "threat_actors": ["APT28", "Fancy Bear", "Forest Blizzard"]
    },
    "CVE-2023-44228": {
        "cve_id": "CVE-2023-44228",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Log4Shell variant — Apache Log4j JNDI injection vulnerability allowing remote code execution through crafted input strings containing malicious JNDI references.",
        "exploit_available": True,
        "malware_families": ["Cobalt Strike", "Mirai"],
        "threat_actors": ["APT41", "Lazarus Group"]
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# THREAT ACTOR & MALWARE KEYWORD CATALOGS
# ──────────────────────────────────────────────────────────────────────────────
ACTOR_CATALOG = {
    "lockbit": "LockBit Group / Gold Southfield",
    "nobelium": "APT29 / Nobelium / Cozy Bear",
    "apt29": "APT29 / Nobelium / Cozy Bear",
    "cozy bear": "APT29 / Nobelium / Cozy Bear",
    "barium": "APT41 / BARIUM / Wicked Panda",
    "apt41": "APT41 / BARIUM / Wicked Panda",
    "kinsing": "Kinsing Actor Group",
    "shodan": "Shodan Crawler",
    "lazarus": "Lazarus Group / HIDDEN COBRA",
    "apt28": "APT28 / Fancy Bear / Forest Blizzard",
    "fancy bear": "APT28 / Fancy Bear / Forest Blizzard",
    "hafnium": "Hafnium / Silk Typhoon",
    "clop": "Clop Ransomware Gang / FIN11",
    "fin11": "Clop Ransomware Gang / FIN11",
    "volt typhoon": "Volt Typhoon",
    "black basta": "Black Basta Ransomware Group",
    "storm-0978": "Storm-0978 / RomCom Group",
}

MALWARE_CATALOG = {
    "lockbit": "LockBit 3.0",
    "shadowpad": "ShadowPad RAT",
    "plugx": "PlugX Remote Access Tool",
    "kinsing": "Kinsing Cryptominer",
    "graphicalproton": "GraphicalProton Downloader",
    "cobalt strike": "Cobalt Strike Beacon",
    "mimikatz": "Mimikatz Credential Dumper",
    "metasploit": "Metasploit Framework Payload",
    "ransomware": "Generic Ransomware Family",
    "asyncrat": "AsyncRAT Remote Access Trojan",
    "romcom": "RomCom RAT",
    "mirai": "Mirai Botnet",
}

# ──────────────────────────────────────────────────────────────────────────────
# KNOWN IOC ENRICHMENT TABLE
# ──────────────────────────────────────────────────────────────────────────────
KNOWN_IOC_ENRICHMENT = {
    "185.220.101.5": {"reputation": "Malicious", "context": "Tor Exit Node linked to LockBit C2 traffic"},
    "update.cloudservices-api.com": {"reputation": "Malicious", "context": "ShadowPad C2 Callback domain"},
    "security-update-microsoft.com": {"reputation": "Malicious", "context": "APT29 Phishing Landing Domain"},
    "172.245.16.125": {"reputation": "Malicious", "context": "ActiveMQ RCE exploit payload server"},
    "198.51.100.42": {"reputation": "Benign/Scanner", "context": "Shodan scanner crawler node"},
    "login-microsoftonline.com": {"reputation": "Malicious", "context": "Credential harvesting phishing domain"},
    "cdn-cloudflare-security.com": {"reputation": "Malicious", "context": "Malware distribution CDN impersonation"},
    "45.33.32.156": {"reputation": "Malicious", "context": "Command and control server for cryptominer operations"},
    "103.224.182.250": {"reputation": "Malicious", "context": "APT41 infrastructure — PlugX C2 relay node"},
    "194.26.29.113": {"reputation": "Malicious", "context": "Ransomware payment portal hosting server"},
}


# ──────────────────────────────────────────────────────────────────────────────
# NVD API INTEGRATION (live CVE lookup with local fallback)
# ──────────────────────────────────────────────────────────────────────────────
async def fetch_nvd_cve(cve_id: str) -> dict | None:
    """
    Fetches CVE details from the NVD REST API (v2.0).
    Returns enrichment dict on success, None on failure (triggers local fallback).
    Timeout: 5 seconds. Rate limit: 5 requests/30s without API key.
    """
    try:
        url = f"{settings.NVD_API_URL}?cveId={cve_id}"
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        async with httpx.AsyncClient(timeout=settings.NVD_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)

        if response.status_code != 200:
            logger.warning(f"NVD API returned {response.status_code} for {cve_id}")
            return None

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})

        # Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
        cvss = 0.0
        severity = "Unknown"
        metrics = cve_data.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "Unknown")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "Unknown")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss = cvss_data.get("baseScore", 0.0)
            severity = "High" if cvss >= 7.0 else ("Medium" if cvss >= 4.0 else "Low")

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        logger.info(f"NVD API: {cve_id} → CVSS {cvss} ({severity})")

        return {
            "cve_id": cve_id,
            "cvss": cvss,
            "severity": severity.capitalize(),
            "description": description[:500] if description else f"CVE {cve_id} vulnerability details from NVD.",
            "exploit_available": False,  # NVD API doesn't directly indicate this
            "malware_families": [],
            "threat_actors": []
        }

    except httpx.TimeoutException:
        logger.warning(f"NVD API timeout for {cve_id}")
        return None
    except Exception as e:
        logger.error(f"NVD API error for {cve_id}: {str(e)}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# MAIN ENRICHMENT FUNCTION
# ──────────────────────────────────────────────────────────────────────────────
async def enrich_analysis(iocs: List[Dict[str, Any]], raw_text: str) -> Dict[str, Any]:
    """
    Enriches threat analysis with CVE details, actor attribution, and malware associations.

    Enrichment flow for each CVE:
    1. Check local CVE_CATALOG → use if found
    2. If not in catalog → call NVD API (live)
    3. If NVD fails → return generic low-severity entry

    For multiple CVEs, returns the HIGHEST-severity one as primary enrichment.
    """
    text_lower = raw_text.lower()

    # ── Collect all CVE IDs from IOCs ──
    cve_ids = [ioc["value"] for ioc in iocs if ioc["type"] == "CVE ID"]

    # ── Enrich all CVEs, track highest severity ──
    best_enrichment = None
    best_cvss = -1

    for cve_id in cve_ids:
        enrichment = None

        # Step 1: Local catalog
        if cve_id in CVE_CATALOG:
            enrichment = CVE_CATALOG[cve_id].copy()
            logger.info(f"CVE {cve_id} found in local catalog (CVSS {enrichment['cvss']})")
        else:
            # Step 2: NVD API
            enrichment = await fetch_nvd_cve(cve_id)
            if enrichment:
                logger.info(f"CVE {cve_id} fetched from NVD API (CVSS {enrichment['cvss']})")

        # Step 3: Generic fallback
        if not enrichment:
            enrichment = {
                "cve_id": cve_id,
                "cvss": 5.0,
                "severity": "Medium",
                "description": f"Vulnerability {cve_id} — details not available in local catalog or NVD.",
                "exploit_available": False,
                "malware_families": [],
                "threat_actors": []
            }

        # Track highest CVSS
        if enrichment["cvss"] > best_cvss:
            best_cvss = enrichment["cvss"]
            best_enrichment = enrichment

        # Mark the CVE IOC as enriched
        for ioc in iocs:
            if ioc["type"] == "CVE ID" and ioc["value"] == cve_id:
                ioc["enriched"] = True

    # ── If no CVE found, build enrichment from text keywords ──
    if not best_enrichment:
        cvss = 2.0
        severity = "Low"
        exploit_available = False
        malware_families = []
        threat_actors = []

        # Keyword-based actor matching
        for key, val in ACTOR_CATALOG.items():
            if key in text_lower:
                threat_actors.append(val)

        # Keyword-based malware matching
        for key, val in MALWARE_CATALOG.items():
            if key in text_lower:
                malware_families.append(val)

        # Remove duplicates
        threat_actors = list(set(threat_actors))
        malware_families = list(set(malware_families))

        # Determine exploit availability & CVSS from keywords
        if any(k in text_lower for k in ["exploit", "poc", "metasploit", "proof of concept"]) or malware_families:
            exploit_available = True
            cvss = 7.5
            severity = "High"
        if any(k in text_lower for k in ["critical", "ransomware", "sideloading", "remote code execution", "rce"]):
            cvss = 9.0
            severity = "Critical"

        best_enrichment = {
            "cve_id": "N/A",
            "cvss": cvss,
            "severity": severity,
            "description": "General infrastructure compromise profile based on indicator analysis.",
            "exploit_available": exploit_available,
            "malware_families": malware_families,
            "threat_actors": threat_actors
        }
    else:
        # Supplement CVE enrichment with keyword-based actor/malware detection
        for key, val in ACTOR_CATALOG.items():
            if key in text_lower and val not in best_enrichment["threat_actors"]:
                best_enrichment["threat_actors"].append(val)
        for key, val in MALWARE_CATALOG.items():
            if key in text_lower and val not in best_enrichment["malware_families"]:
                best_enrichment["malware_families"].append(val)

    # ── Enrich individual IOCs from known intelligence ──
    for ioc in iocs:
        val_lower = ioc["value"].lower()
        if val_lower in KNOWN_IOC_ENRICHMENT:
            intel = KNOWN_IOC_ENRICHMENT[val_lower]
            ioc["reputation"] = intel["reputation"]
            ioc["context"] = intel["context"]
            ioc["enriched"] = True

    return best_enrichment
