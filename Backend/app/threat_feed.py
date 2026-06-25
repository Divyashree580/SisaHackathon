import logging
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional

logger = logging.getLogger(__name__)

router = APIRouter()


class ThreatFeedEntry(BaseModel):
    indicator: str
    indicator_type: str
    pulse_count: int
    reputation: str
    tags: List[str]
    references: List[str]


class ThreatFeedResponse(BaseModel):
    entries: List[ThreatFeedEntry]
    source: str
    status: str


# Placeholder: stub endpoint so the import in main.py doesn't break.
# Full implementation will be done in the Real-Time Threat Feed bonus.
STATIC_FEED = ThreatFeedResponse(
    source="static-mock",
    status="ok",
    entries=[
        ThreatFeedEntry(
            indicator="secure-login-update.com",
            indicator_type="domain",
            pulse_count=12,
            reputation="Malicious",
            tags=["phishing", "credential-harvesting", "finance"],
            references=["https://otx.alienvault.com/indicator/domain/secure-login-update.com"]
        ),
        ThreatFeedEntry(
            indicator="185.199.108.153",
            indicator_type="IPv4",
            pulse_count=8,
            reputation="Suspicious",
            tags=["c2", "proxy", "hosting"],
            references=["https://otx.alienvault.com/indicator/ip/185.199.108.153"]
        ),
    ]
)


@router.get("/threat-feed", response_model=ThreatFeedResponse, summary="Real-Time Threat Feed (stub)")
async def get_threat_feed():
    """Stub endpoint for the real-time threat feed bonus feature.
    Returns static mock data. Full OTX/AbuseIPDB integration TBD.
    """
    return STATIC_FEED
