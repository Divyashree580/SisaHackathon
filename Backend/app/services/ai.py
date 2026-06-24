import json
import logging
from groq import Groq
from app.config import settings

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# FALLBACK HEURISTIC REPORT GENERATOR
# ──────────────────────────────────────────────────────────────────────────────
def generate_fallback_ai_report(text: str, iocs: list, mitre_enabled: bool = True) -> dict:
    """
    Template-based fallback report generator for when Groq API is unavailable.
    Analyzes text keywords to produce category-appropriate reports.
    Includes actual IOC values from input for specificity.
    """
    text_lower = text.lower()

    # Collect IOC summaries for specificity
    ioc_ips = [i["value"] for i in iocs if i["type"] == "IPv4"][:3]
    ioc_domains = [i["value"] for i in iocs if i["type"] == "Domain"][:3]
    ioc_hashes = [i["value"] for i in iocs if i["type"] in ("MD5", "SHA1", "SHA256")][:2]
    ioc_cves = [i["value"] for i in iocs if i["type"] == "CVE ID"][:3]

    # Identify threat profile
    is_ransomware = any(k in text_lower for k in ["ransomware", "encrypt", "lockbit", "vssadmin", "ransom"])
    is_phishing = any(k in text_lower for k in ["phish", "spearphishing", "email", "attachment", "credential"])
    is_exploit = any(k in text_lower for k in ["exploit", "rce", "cve-", "vulnerability", "buffer overflow"])
    is_apt = any(k in text_lower for k in ["apt", "advanced persistent", "nation-state", "espionage", "sideloading"])
    is_ddos = any(k in text_lower for k in ["ddos", "denial of service", "flood", "botnet"])
    is_cryptominer = any(k in text_lower for k in ["cryptominer", "kinsing", "mining", "xmrig", "monero"])

    # Default profile
    category = "Infrastructure Vulnerability Scan"
    summary = f"General vulnerability scan or informational scan detected. The threat context contains {len(iocs)} indicators requiring evaluation."
    attack_scenario = "1. Scanning nodes execute automated queries → 2. Network logs record connections → 3. Benign port mapping activity detected."
    business_impact = "Minimal. Represents internet background scanning activity. No internal compromise indicators found."
    immediate_actions = ["Review firewall logs for blocked entries.", "Verify management ports are properly isolated.", "Check for any unauthorized access attempts."]
    long_term_remediation = ["Configure strict segmentation rules on public-facing gateways.", "Implement network monitoring for anomalous scan patterns."]
    monitoring = ["Alert on port scan bursts from single source hosts.", "Monitor for repeated connection attempts to sensitive services."]

    mitre_mapping = [
        {"tactic": "Reconnaissance", "technique": "Active Scanning", "technique_id": "T1595", "confidence": "High"}
    ]

    if is_ransomware:
        category = "Ransomware Outbreak"
        ip_detail = f" from C2 servers ({', '.join(ioc_ips)})" if ioc_ips else ""
        cve_detail = f" exploiting {', '.join(ioc_cves)}" if ioc_cves else ""
        summary = f"Active ransomware payload execution detected{cve_detail}. Host logs indicate encryption activity and shadow copy deletion{ip_detail}. {len(iocs)} threat indicators identified."
        attack_scenario = f"1. Intruder compromises public-facing gateway{cve_detail} → 2. Lateral movement via PsExec/WMI → 3. Volume shadow copies deleted (vssadmin) → 4. File system encrypted with ransomware extensions."
        business_impact = "CRITICAL: Risk of complete business outage, data loss, extortion demands, regulatory compliance violations, and potential data exfiltration."
        immediate_actions = [
            "Isolate infected assets from all network segments immediately.",
            f"Block C2 communication to {', '.join(ioc_ips[:2]) if ioc_ips else 'identified malicious IPs'} at perimeter firewall.",
            "Reset all domain admin and service account passwords.",
            f"{'Patch ' + ', '.join(ioc_cves) + ' immediately.' if ioc_cves else 'Apply all pending security patches.'}"
        ]
        long_term_remediation = [
            "Implement immutable offline backup storage (3-2-1 backup strategy).",
            "Deploy EDR with ransomware-specific behavioral detection rules.",
            "Enforce least-privilege access across all administrative accounts."
        ]
        monitoring = [
            "Alert on vssadmin.exe and wmic.exe shadowcopy delete commands.",
            "Monitor for bulk file rename operations with unusual extensions.",
            "Audit administrative scripts spawning PowerShell with encoded commands."
        ]
        mitre_mapping = [
            {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190", "confidence": "High"},
            {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "technique_id": "T1059", "confidence": "High"},
            {"tactic": "Impact", "technique": "Data Encrypted for Impact", "technique_id": "T1486", "confidence": "Critical"},
            {"tactic": "Impact", "technique": "Inhibit System Recovery", "technique_id": "T1490", "confidence": "High"}
        ]

    elif is_phishing:
        category = "Spear Phishing Campaign"
        domain_detail = f" directing to {', '.join(ioc_domains[:2])}" if ioc_domains else ""
        summary = f"Targeted phishing campaign detected with {len(iocs)} IOCs. Malicious emails carrying weaponized attachments or credential-harvesting URLs{domain_detail}."
        attack_scenario = f"1. Spear-phishing email bypasses gateway filters → 2. Target opens attachment/clicks link{domain_detail} → 3. Macro/script triggers payload download → 4. C2 channel established for data exfiltration."
        business_impact = "HIGH: Risk of credential theft, business email compromise (BEC), unauthorized access to sensitive systems, and potential lateral movement."
        immediate_actions = [
            f"Block DNS resolution for {', '.join(ioc_domains[:2]) if ioc_domains else 'identified phishing domains'}.",
            "Quarantine all emails matching the phishing sender pattern.",
            "Force password reset for any users who clicked malicious links.",
            "Scan endpoints of affected users with EDR for IOC artifacts."
        ]
        long_term_remediation = [
            "Implement hardware MFA tokens for all administrative accounts.",
            "Deploy email authentication (SPF, DKIM, DMARC) with enforcement.",
            "Conduct regular phishing simulation exercises for employees."
        ]
        monitoring = [
            "Alert on Office applications spawning cmd.exe or PowerShell processes.",
            "Monitor mail flow rules for unauthorized forwarding modifications.",
            "Track login anomalies from geographically distant locations."
        ]
        mitre_mapping = [
            {"tactic": "Initial Access", "technique": "Phishing: Spearphishing Attachment", "technique_id": "T1566.001", "confidence": "High"},
            {"tactic": "Execution", "technique": "User Execution: Malicious File", "technique_id": "T1204.002", "confidence": "High"},
            {"tactic": "Command and Control", "technique": "Web Service", "technique_id": "T1102", "confidence": "Medium"}
        ]

    elif is_apt:
        category = "Advanced Persistent Threat Campaign"
        hash_detail = f" (file signatures: {', '.join(ioc_hashes[:1])})" if ioc_hashes else ""
        summary = f"APT-level threat activity detected{hash_detail}. Indicators suggest state-sponsored or advanced threat actor involvement with {len(iocs)} IOCs extracted."
        attack_scenario = "1. Initial compromise via supply chain or spear-phishing → 2. Custom malware deployed via DLL side-loading → 3. Persistent backdoor established → 4. Slow data exfiltration over encrypted C2 channels."
        business_impact = "CRITICAL: Risk of long-term espionage, intellectual property theft, strategic intelligence compromise, and supply chain poisoning."
        immediate_actions = [
            "Engage incident response team and begin forensic investigation.",
            f"{'Block hashes: ' + ', '.join(ioc_hashes[:2]) + ' across all endpoints.' if ioc_hashes else 'Scan all endpoints for known APT tooling artifacts.'}",
            "Isolate potentially compromised systems while preserving forensic evidence."
        ]
        long_term_remediation = [
            "Implement network segmentation with zero-trust architecture.",
            "Deploy application allowlisting on critical servers.",
            "Conduct comprehensive threat hunt across the environment."
        ]
        monitoring = [
            "Monitor for DLL side-loading in legitimate application directories.",
            "Alert on unusual encrypted outbound connections to rare destinations.",
            "Audit process creation chains for living-off-the-land binaries (LOLBins)."
        ]
        mitre_mapping = [
            {"tactic": "Initial Access", "technique": "Phishing: Spearphishing Attachment", "technique_id": "T1566.001", "confidence": "High"},
            {"tactic": "Defense Evasion", "technique": "Hijack Execution Flow: DLL Side-Loading", "technique_id": "T1574.002", "confidence": "High"},
            {"tactic": "Command and Control", "technique": "Encrypted Channel", "technique_id": "T1573", "confidence": "High"},
            {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "technique_id": "T1041", "confidence": "Medium"}
        ]

    elif is_cryptominer:
        category = "Cryptomining / Resource Hijacking"
        summary = f"Cryptomining activity detected. Indicators suggest unauthorized resource utilization for cryptocurrency mining with {len(iocs)} IOCs identified."
        attack_scenario = "1. Vulnerable service exploited for initial access → 2. Cryptominer payload downloaded and executed → 3. System resources consumed for mining operations → 4. Persistence mechanisms installed."
        business_impact = "MEDIUM-HIGH: Increased infrastructure costs, degraded system performance, and indicator of deeper compromise that could escalate."
        immediate_actions = [
            "Terminate suspicious mining processes immediately.",
            f"{'Block C2 connections to ' + ', '.join(ioc_ips[:2]) if ioc_ips else 'Block all identified mining pool connections'}.",
            "Patch the vulnerability used for initial access."
        ]
        long_term_remediation = [
            "Implement resource monitoring and anomaly detection.",
            "Restrict outbound connections to known mining pool endpoints.",
            "Harden container/VM configurations against escape attacks."
        ]
        monitoring = [
            "Alert on high CPU utilization sustained over 30+ minutes.",
            "Monitor for connections to known mining pool domains/IPs.",
            "Track new cron jobs or scheduled tasks on server infrastructure."
        ]
        mitre_mapping = [
            {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190", "confidence": "High"},
            {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "technique_id": "T1059", "confidence": "High"}
        ]

    elif is_exploit:
        category = "System Vulnerability Exploitation"
        cve_detail = f" ({', '.join(ioc_cves)})" if ioc_cves else ""
        summary = f"Active exploitation attempts targeting known vulnerabilities{cve_detail}. Attack payloads leverage service vulnerabilities to achieve remote code execution. {len(iocs)} threat indicators extracted."
        attack_scenario = f"1. Attacker sends crafted request exploiting{cve_detail or ' service vulnerability'} → 2. Service processes malicious input, spawning shell → 3. Second-stage payload downloaded from C2 → 4. Persistence and lateral movement initiated."
        business_impact = "HIGH: Risk of remote shell access, credential exposure, lateral movement, and potential full domain compromise."
        immediate_actions = [
            f"{'Apply security patches for ' + ', '.join(ioc_cves) + ' immediately.' if ioc_cves else 'Apply all pending security patches for the affected service.'}",
            "Restrict outbound connections from application-tier hosts.",
            f"{'Block malicious IPs: ' + ', '.join(ioc_ips[:3]) if ioc_ips else 'Review and block suspicious source IPs in WAF/firewall.'}"
        ]
        long_term_remediation = [
            "Enforce least-privilege service account configurations.",
            "Deploy web application firewall (WAF) with exploit signature rules.",
            "Implement virtual patching for zero-day vulnerabilities."
        ]
        monitoring = [
            "Alert on web service accounts executing shell commands.",
            "Monitor for unexpected binary downloads on application servers.",
            "Audit outbound connections from DMZ hosts to external IPs."
        ]
        mitre_mapping = [
            {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190", "confidence": "High"},
            {"tactic": "Execution", "technique": "Exploitation for Client Execution", "technique_id": "T1203", "confidence": "High"}
        ]

    result = {
        "ai_report": {
            "summary": summary,
            "attack_scenario": attack_scenario,
            "business_impact": business_impact,
            "immediate_actions": immediate_actions,
            "long_term_remediation": long_term_remediation,
            "monitoring": monitoring
        }
    }

    if mitre_enabled:
        result["mitre_mapping"] = mitre_mapping
    else:
        result["mitre_mapping"] = []

    return result


# ──────────────────────────────────────────────────────────────────────────────
# GROQ API AI ANALYSIS
# ──────────────────────────────────────────────────────────────────────────────
def run_ai_analysis(
    text: str,
    iocs: list,
    mitre_enabled: bool = True,
    mitre_technique_ids: list = None
) -> dict:
    """
    Invokes Groq API to generate a structured threat intelligence report.
    Falls back gracefully to the heuristic template generator if the API is
    offline, the key is missing, or the response cannot be parsed.

    Args:
        text: Raw threat context text
        iocs: List of extracted IOC dicts
        mitre_enabled: Whether to include MITRE ATT&CK mapping
        mitre_technique_ids: List of valid technique IDs from local catalog (constrains AI output)
    """
    if not settings.GROQ_API_KEY:
        logger.info("Groq API key missing. Running fallback heuristics report generator.")
        return generate_fallback_ai_report(text, iocs, mitre_enabled)

    try:
        client = Groq(api_key=settings.GROQ_API_KEY)

        # Build MITRE constraint instruction
        mitre_instruction = ""
        if mitre_enabled and mitre_technique_ids:
            ids_str = ", ".join(mitre_technique_ids)
            mitre_instruction = f"""
MITRE ATT&CK CONSTRAINT: You MUST only use technique IDs from this approved catalog:
{ids_str}
Do NOT invent or use technique IDs not in this list.
"""
        elif not mitre_enabled:
            mitre_instruction = "MITRE ATT&CK mapping is DISABLED. Return an empty list for mitre_mapping."

        prompt = f"""You are an elite cyber threat analyst Copilot analyzing data for a SOC analyst who needs actionable, specific recommendations.

{mitre_instruction}

---
THREAT CONTEXT:
{text[:4000]}

INDICATORS OF COMPROMISE:
{json.dumps(iocs[:20], indent=2)}
---

Perform:
1. MITRE ATT&CK Mapping: Correlate the threat context against tactics and techniques. Be specific — reference actual IOCs from the input.
2. AI Intelligence Brief: Write a comprehensive brief with these sections:
   - Threat Summary (reference specific IOCs, CVEs, and IPs from the input)
   - Attack Scenario (consecutive numbered steps showing the attack chain)
   - Business Impact (specific to the threat type — not generic)
   - Immediate Response Actions (3-5 specific, actionable items referencing actual IOCs)
   - Long-Term Hardening (3-5 specific remediation steps)
   - Monitoring Recommendations (3-5 detection strategies)

IMPORTANT: Do NOT give generic advice. Reference specific IOCs, CVEs, domains, and IPs from the input data.

You MUST respond ONLY with a raw, valid JSON object fitting this schema:
{{
  "mitre_mapping": [
    {{
      "tactic": "Initial Access",
      "technique": "Exploit Public-Facing Application",
      "technique_id": "T1190",
      "confidence": "High"
    }}
  ],
  "ai_report": {{
    "summary": "Specific threat overview...",
    "attack_scenario": "1. Step one → 2. Step two → ...",
    "business_impact": "Specific impact assessment...",
    "immediate_actions": ["Action 1", "Action 2", "Action 3"],
    "long_term_remediation": ["Remediation 1", "Remediation 2", "Remediation 3"],
    "monitoring": ["Recommendation 1", "Recommendation 2", "Recommendation 3"]
  }}
}}"""

        response = client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=3000,
            temperature=0.1,
        )

        content = response.choices[0].message.content.strip()

        # Clean markdown wrappers if any
        if content.startswith("```json"):
            content = content.replace("```json", "", 1)
        if content.startswith("```"):
            content = content.replace("```", "", 1)
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]

        data = json.loads(content.strip())

        # Validate structure
        if "ai_report" not in data:
            logger.warning("Groq response missing ai_report field, using fallback.")
            return generate_fallback_ai_report(text, iocs, mitre_enabled)

        if not mitre_enabled:
            data["mitre_mapping"] = []

        return data

    except json.JSONDecodeError as e:
        logger.error(f"Groq response JSON parse failed: {str(e)}. Triggering fallback.", exc_info=True)
        return generate_fallback_ai_report(text, iocs, mitre_enabled)
    except Exception as e:
        logger.error(f"Groq API analysis failed: {str(e)}. Triggering fallback.", exc_info=True)
        return generate_fallback_ai_report(text, iocs, mitre_enabled)
