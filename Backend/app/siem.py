from fastapi import APIRouter
from typing import Optional

router = APIRouter()

@router.get("/siem/queries", summary="Generate SIEM queries for common platforms")
async def get_siem_queries(domain: Optional[str] = None, ip: Optional[str] = None):
    """Return dynamic SIEM queries for the given or default IOC set.
    """
    if not domain:
        domain = "secure-login-update.com"
    if not ip:
        ip = "185.199.108.153"
    
    # Splunk query
    splunk = f'''index=proxy (url="*{domain}*" OR dest_ip="{ip}")
| stats count by src_ip, url, dest_ip
| sort -count'''
    # Sentinel KQL query
    kql = f'''CommonSecurityLog
| where DestinationHostName contains "{domain}" or DestinationIP == "{ip}"
| summarize Count=count() by SourceIP, DestinationHostName'''
    # Elastic DSL (JSON string)
    elastic = f'''{{
  "query": {{
    "bool": {{
      "should": [
        {{ "match": {{ "url.domain": "{domain}" }} }},
        {{ "match": {{ "destination.ip": "{ip}" }} }}
      ]
    }}
  }}
}}'''
    return {
        "splunk": splunk,
        "kql": kql,
        "elastic": elastic,
    }
