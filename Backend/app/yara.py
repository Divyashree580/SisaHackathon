from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

class YaraRuleResponse(BaseModel):
    rule_name: str
    meta: dict
    strings: dict
    condition: str

# Static YARA rule template (can be extended later)
YARA_RULE_TEMPLATE = {
    "rule_name": "Phishing_Campaign_June2026",
    "meta": {
        "description": "Detects artifacts from finance phishing campaign",
        "threat_level": "critical"
    },
    "strings": {
        "$domain": "secure-login-update.com",
        "$ip": "185.199.108.153",
        "$hash": "{ 5d 41 40 2a bc 4b 2a 76 }"
    },
    "condition": "any of them"
}

@router.post("/api/yara", response_model=YaraRuleResponse)
async def generate_yara_rule():
    """Return a static YARA rule for the phishing campaign.
    Future work could accept parameters to customise the rule.
    """
    try:
        return YARA_RULE_TEMPLATE
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
