import re
from typing import List, Dict, Any

# Regex Patterns
REGEX_IPV4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
REGEX_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b')
REGEX_URL = re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s"\'<>]*)?')
REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
REGEX_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
REGEX_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
REGEX_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
REGEX_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# Domains to exclude from extraction (benign well-known sites)
EXCLUDE_DOMAINS = {
    'microsoft.com', 'google.com', 'apple.com', 'github.com',
    'shodan.io', 'w3.org', 'schema.org', 'wikipedia.org',
    'nist.gov', 'mitre.org',
}

# File-extension-like TLDs that produce false positive domain matches
EXCLUDE_EXTENSIONS = {
    'xml', 'pdf', 'exe', 'txt', 'csv', 'dll', 'tmp', 'log',
    'doc', 'docx', 'zip', 'rar', 'png', 'jpg', 'jpeg', 'gif',
    'js', 'css', 'html', 'htm', 'bat', 'ps1', 'sh', 'py',
    'msi', 'iso', 'bin', 'dat', 'cfg', 'ini', 'sys', 'inf',
    'onion',
}

# Known malicious IOCs for reputation tagging
KNOWN_MALICIOUS_IPS = {
    '185.220.101.5', '172.245.16.125', '45.33.32.156',
    '103.224.182.250', '194.26.29.113',
}
KNOWN_MALICIOUS_DOMAINS = {
    'update.cloudservices-api.com', 'security-update-microsoft.com',
    'login-microsoftonline.com', 'cdn-cloudflare-security.com',
}
KNOWN_BENIGN_IPS = {'198.51.100.42'}


def _clean_and_dedupe(matches: list) -> list:
    """Remove duplicates and normalize to lowercase."""
    return list(set(m.strip().lower() for m in matches if m and m.strip()))


def _filter_domains(domains: list, email_domains: set, url_domains: set) -> list:
    """
    Filter domain matches to remove:
    1. Known benign domains
    2. File-extension-like false positives (e.g., 'file.exe')
    3. Domains already captured via email addresses
    4. Domains already captured via URLs
    5. Very short domains (< 4 chars total) that are almost always false positives
    """
    filtered = []
    for d in domains:
        # Skip exclusions
        if d in EXCLUDE_DOMAINS:
            continue
        # Skip if TLD looks like a file extension
        tld = d.rsplit('.', 1)[-1] if '.' in d else ''
        if tld in EXCLUDE_EXTENSIONS:
            continue
        # Skip very short domains
        if len(d) < 4:
            continue
        # Skip if already captured as part of an email or URL
        if d in email_domains or d in url_domains:
            continue
        filtered.append(d)
    return filtered


def _assign_reputation(ioc_type: str, value: str) -> tuple:
    """
    Assigns reputation and context based on known threat intelligence.
    Returns (reputation, context, enriched).
    """
    val_lower = value.lower()

    if ioc_type == "IPv4":
        if val_lower in KNOWN_MALICIOUS_IPS:
            return "Malicious", "Known malicious IP from threat intelligence feeds", True
        if val_lower in KNOWN_BENIGN_IPS:
            return "Benign/Scanner", "Shodan scanner crawler node", True
        # RFC1918 internal ranges
        if val_lower.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                  '172.20.', '172.21.', '172.22.', '172.23.',
                                  '172.24.', '172.25.', '172.26.', '172.27.',
                                  '172.28.', '172.29.', '172.30.', '172.31.',
                                  '192.168.')):
            return "Internal/RFC1918", "Private network IP address", True
        return "Suspicious", "Extracted IPv4 address", False

    if ioc_type == "Domain":
        if val_lower in KNOWN_MALICIOUS_DOMAINS:
            return "Malicious", "Known malicious domain from threat feeds", True
        return "Suspicious", "Extracted domain record", False

    if ioc_type == "URL":
        return "Suspicious", "Extracted resource URL", False

    if ioc_type == "Email":
        return "Suspicious", "Extracted email identifier", False

    if ioc_type in ("MD5", "SHA1", "SHA256"):
        return "Malicious", f"Extracted {ioc_type} hash signature", False

    if ioc_type == "CVE ID":
        return "Vulnerability Reference", "Extracted vulnerability registry index", False

    return "Unknown", "Extracted indicator", False


def extract_iocs(text: str) -> List[Dict[str, Any]]:
    """
    Extracts IPv4s, domains, URLs, emails, MD5s, SHA1s, SHA256s, and CVEs from raw text.
    Implements longest-match-wins deduplication for hash collisions.
    Excludes file extensions from domain matches and email domains from standalone domain list.
    """
    if not text:
        return []

    # --- Extract hashes with longest-match-wins dedup ---
    # SHA256 (64 hex chars) first — these are the longest
    sha256_set = set(m.lower() for m in REGEX_SHA256.findall(text))

    # SHA1 (40 hex chars) — exclude any substring of a SHA256 match
    sha1_candidates = set(m.lower() for m in REGEX_SHA1.findall(text))
    sha1_set = set()
    for candidate in sha1_candidates:
        if not any(candidate in sha256 for sha256 in sha256_set):
            sha1_set.add(candidate)

    # MD5 (32 hex chars) — exclude substrings of SHA256 or SHA1 matches
    md5_candidates = set(m.lower() for m in REGEX_MD5.findall(text))
    all_longer_hashes = sha256_set | sha1_set
    md5_set = set()
    for candidate in md5_candidates:
        if not any(candidate in longer for longer in all_longer_hashes):
            md5_set.add(candidate)

    # --- Extract other IOC types ---
    ips = _clean_and_dedupe(REGEX_IPV4.findall(text))
    urls = _clean_and_dedupe(REGEX_URL.findall(text))
    emails = _clean_and_dedupe(REGEX_EMAIL.findall(text))
    cves = [c.upper() for c in set(REGEX_CVE.findall(text))]
    raw_domains = _clean_and_dedupe(REGEX_DOMAIN.findall(text))

    # Collect email domains and URL domains to exclude from standalone domain list
    email_domains = {e.split('@')[1].lower() for e in emails if '@' in e}

    url_domains = set()
    for url in urls:
        # Extract domain from URL: strip protocol, take host part
        host = url.split('://')[1].split('/')[0].split(':')[0].lower() if '://' in url else ''
        if host:
            url_domains.add(host)

    # Filter domains
    domains = _filter_domains(raw_domains, email_domains, url_domains)

    # --- Build IOC list ---
    iocs = []

    for val in ips:
        rep, ctx, enriched = _assign_reputation("IPv4", val)
        iocs.append({"type": "IPv4", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in domains:
        rep, ctx, enriched = _assign_reputation("Domain", val)
        iocs.append({"type": "Domain", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in urls:
        rep, ctx, enriched = _assign_reputation("URL", val)
        iocs.append({"type": "URL", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in emails:
        rep, ctx, enriched = _assign_reputation("Email", val)
        iocs.append({"type": "Email", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in md5_set:
        rep, ctx, enriched = _assign_reputation("MD5", val)
        iocs.append({"type": "MD5", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in sha1_set:
        rep, ctx, enriched = _assign_reputation("SHA1", val)
        iocs.append({"type": "SHA1", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in sha256_set:
        rep, ctx, enriched = _assign_reputation("SHA256", val)
        iocs.append({"type": "SHA256", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    for val in cves:
        rep, ctx, enriched = _assign_reputation("CVE ID", val)
        iocs.append({"type": "CVE ID", "value": val, "reputation": rep, "enriched": enriched, "context": ctx})

    return iocs
