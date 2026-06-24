from typing import Dict, Any, List


def calculate_risk(
    enrichment_data: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    enabled: bool = True
) -> Dict[str, Any]:
    """
    Computes a risk score from 0-100 based on threat factors per PRD Section 9.
    Supports conditional execution via the `enabled` flag (options.risk_scoring).

    Risk Tiers:
        Low:      0–30
        Medium:  31–60
        High:    61–80
        Critical: 81–100

    Returns: { "risk_score": int, "risk_level": str, "risk_factors": [{name, points}] }
    """
    if not enabled:
        return {
            "risk_score": 0,
            "risk_level": "N/A",
            "risk_factors": []
        }

    factors = []
    score = 0

    cvss = enrichment_data.get("cvss", 0.0)

    # ── Factor 1: CVSS Severity (+10 / +20 / +30) ──
    if cvss > 9.0:
        factors.append({
            "name": f"CVSS Score {cvss} — Critical Severity (+30 points)",
            "points": 30
        })
        score += 30
    elif cvss >= 7.0:
        factors.append({
            "name": f"CVSS Score {cvss} — High Severity (+20 points)",
            "points": 20
        })
        score += 20
    elif cvss >= 4.0:
        factors.append({
            "name": f"CVSS Score {cvss} — Medium Severity (+10 points)",
            "points": 10
        })
        score += 10

    # ── Factor 2: Exploit Availability (+25) ──
    if enrichment_data.get("exploit_available", False):
        factors.append({
            "name": "Public exploit available (+25 points)",
            "points": 25
        })
        score += 25

    # ── Factor 3: Malware Association (+15) ──
    malware_families = enrichment_data.get("malware_families", [])
    if len(malware_families) > 0:
        families_str = ", ".join(malware_families[:3])  # Truncate to top 3 for display
        factors.append({
            "name": f"Malware associated: {families_str} (+15 points)",
            "points": 15
        })
        score += 15

    # ── Factor 4: Known Threat Actor (+10) ──
    threat_actors = enrichment_data.get("threat_actors", [])
    if len(threat_actors) > 0:
        actors_str = ", ".join(threat_actors[:3])  # Truncate to top 3 for display
        factors.append({
            "name": f"Known threat actor: {actors_str} (+10 points)",
            "points": 10
        })
        score += 10

    # ── Factor 5: High IOC Reputation (+20) ──
    has_malicious_iocs = any(
        ioc.get("reputation") == "Malicious" for ioc in iocs
    )
    if has_malicious_iocs or len(iocs) > 3:
        factors.append({
            "name": "High IOC reputation — Active threat indicators found (+20 points)",
            "points": 20
        })
        score += 20

    # Cap score at 100
    capped_score = min(100, score)

    # Determine risk level per PRD tiers
    if capped_score >= 81:
        risk_level = "Critical"
    elif capped_score >= 61:
        risk_level = "High"
    elif capped_score >= 31:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": capped_score,
        "risk_level": risk_level,
        "risk_factors": factors
    }
