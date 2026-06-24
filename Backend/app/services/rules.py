import uuid
from datetime import datetime
from typing import Dict, Any, List


def generate_detection_rules(
    iocs: List[Dict[str, Any]],
    enrichment_data: Dict[str, Any],
    risk_level: str,
    enabled: bool = True
) -> Dict[str, str]:
    """
    Generates Sigma, YARA, Splunk SPL, and Sentinel KQL detection rules
    based on extracted IOCs and enrichment data.

    Supports conditional execution via the `enabled` flag (options.generate_rules).
    Handles empty IOC lists gracefully with explanatory comments.
    """
    if not enabled:
        return {"sigma": "", "yara": "", "splunk": "", "kql": ""}

    # Group IOCs by type
    ips = [ioc["value"] for ioc in iocs if ioc["type"] == "IPv4"]
    domains = [ioc["value"] for ioc in iocs if ioc["type"] == "Domain"]
    urls = [ioc["value"] for ioc in iocs if ioc["type"] == "URL"]
    hashes = [ioc["value"] for ioc in iocs if ioc["type"] in ("MD5", "SHA1", "SHA256")]
    cves = [ioc["value"] for ioc in iocs if ioc["type"] == "CVE ID"]

    malware = enrichment_data.get("malware_families", [])
    malware_name = malware[0] if malware else "Generic Threat"
    # Sanitize malware name for use in rule identifiers
    malware_safe = malware_name.replace(" ", "_").replace(".", "_").replace("/", "_")
    cve_ref = cves[0] if cves else "N/A"
    today = datetime.now().strftime("%Y/%m/%d")
    today_dash = datetime.now().strftime("%Y-%m-%d")

    # Handle empty IOC case
    if not any([ips, domains, urls, hashes]):
        no_ioc_comment = (
            "# No network or file IOCs were extracted from the input.\n"
            "# Detection rules require at least one IP, domain, URL, or hash indicator.\n"
            f"# Threat context: {malware_name} | CVE: {cve_ref} | Risk: {risk_level}\n"
        )
        return {
            "sigma": no_ioc_comment + "# Provide specific IOCs to generate targeted Sigma rules.",
            "yara": no_ioc_comment + "# Provide specific file hashes or strings to generate YARA rules.",
            "splunk": no_ioc_comment + "# Provide specific IOCs to generate Splunk SPL queries.",
            "kql": no_ioc_comment + "# Provide specific IOCs to generate Sentinel KQL queries.",
        }

    # ─── 1. SIGMA RULE GENERATION ─────────────────────────────────────────────
    sigma_id = str(uuid.uuid4())
    sigma_rules = []

    # Generate separate rules per IOC type for valid logsource categories
    if hashes:
        hash_detection = "    selection_hashes:\n"
        hash_detection += "        Hashes|contains:\n"
        for h in hashes:
            hash_detection += f"            - '{_escape_sigma(h)}'\n"
        hash_detection += "    condition: selection_hashes"

        sigma_rules.append(f"""title: File Hash Detection — {malware_name}
id: {sigma_id}
status: experimental
description: Detects file artifacts associated with {malware_name} campaign ({cve_ref}).
author: SISA Sentinel Auto-Generator
date: {today}
logsource:
    category: process_creation
    product: windows
detection:
{hash_detection}
falsepositives:
    - Legitimate software with matching hash signatures
level: {risk_level.lower()}""")

    if domains or ips:
        net_detection = "    selection_network:\n"
        if domains:
            net_detection += "        QueryName|contains:\n"
            for d in domains:
                net_detection += f"            - '{_escape_sigma(d)}'\n"
        if ips:
            net_detection += "        DestinationIp:\n"
            for ip in ips:
                net_detection += f"            - '{_escape_sigma(ip)}'\n"
        net_detection += "    condition: selection_network"

        net_sigma_id = str(uuid.uuid4())
        sigma_rules.append(f"""title: Network IOC Detection — {malware_name}
id: {net_sigma_id}
status: experimental
description: Detects network communication to indicators associated with {malware_name} ({cve_ref}).
author: SISA Sentinel Auto-Generator
date: {today}
logsource:
    category: dns_query
    product: windows
detection:
{net_detection}
falsepositives:
    - Administrative vulnerability scanner runs
level: {risk_level.lower()}""")

    sigma_rule = "\n---\n".join(sigma_rules) if sigma_rules else f"# No applicable Sigma detection for {malware_name}"

    # ─── 2. YARA RULE GENERATION ──────────────────────────────────────────────
    strings_block = ""
    idx = 1
    for h in hashes:
        strings_block += f'        $hash_{idx} = "{_escape_yara(h)}" wide ascii\n'
        idx += 1
    for d in domains:
        strings_block += f'        $domain_{idx} = "{_escape_yara(d)}" wide ascii\n'
        idx += 1
    for ip in ips:
        strings_block += f'        $ip_{idx} = "{_escape_yara(ip)}" wide ascii\n'
        idx += 1

    if not strings_block:
        strings_block = f'        $meta = "{_escape_yara(malware_name)}" wide ascii\n'

    yara_rule = f"""rule Sentinel_Auto_{malware_safe} {{
    meta:
        description = "Detects files containing threat indicators: {_escape_yara(malware_name)}"
        cve = "{_escape_yara(cve_ref)}"
        generated = "{today_dash}"
        risk_level = "{risk_level}"

    strings:
{strings_block}
    condition:
        uint16(0) == 0x5A4D and (any of ($*))
}}"""

    # ─── 3. SPLUNK SPL GENERATION ─────────────────────────────────────────────
    splunk_elements = []
    for ip in ips:
        splunk_elements.append(f'dest_ip="{ip}"')
    for d in domains:
        splunk_elements.append(f'query="*{d}*"')
    for h in hashes:
        splunk_elements.append(f'file_hash="{h}"')

    if splunk_elements:
        splunk_query = (
            f"index=security ({' OR '.join(splunk_elements)})\n"
            f"| table _time, host, src_ip, dest_ip, query, process_name, file_hash\n"
            f"| sort -_time"
        )
    else:
        splunk_query = f'index=security "{malware_name}"\n| table _time, host, src_ip, dest_ip, query'

    # ─── 4. SENTINEL KQL GENERATION ──────────────────────────────────────────
    kql_elements = []
    if ips:
        ip_list = ", ".join(f'"{ip}"' for ip in ips)
        kql_elements.append(f"RemoteIP in ({ip_list})")
    if domains:
        domain_list = ", ".join(f'"{d}"' for d in domains)
        kql_elements.append(f"DomainName has_any ({domain_list})")
    if hashes:
        hash_list = ", ".join(f'"{h}"' for h in hashes)
        kql_elements.append(f"SHA256 in ({hash_list})")

    if kql_elements:
        kql_query = (
            f"DeviceNetworkEvents\n"
            f"| where {' or '.join(kql_elements)}\n"
            f"| project TimeGenerated, DeviceName, ActionType, LocalIP, RemoteIP, RemoteUrl\n"
            f"| sort by TimeGenerated desc"
        )
    else:
        kql_query = (
            f'DeviceProcessEvents\n'
            f'| where ProcessCommandLine has "{malware_name}"\n'
            f'| project TimeGenerated, DeviceName, FileName, ProcessCommandLine'
        )

    return {
        "sigma": sigma_rule,
        "yara": yara_rule,
        "splunk": splunk_query,
        "kql": kql_query
    }


def _escape_sigma(value: str) -> str:
    """Escape special characters for Sigma rule YAML strings."""
    return value.replace("'", "''").replace("\\", "\\\\")


def _escape_yara(value: str) -> str:
    """Escape special characters for YARA rule strings."""
    return value.replace("\\", "\\\\").replace('"', '\\"')
