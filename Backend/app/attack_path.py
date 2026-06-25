import httpx
import json
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


class AttackPathRequest(BaseModel):
    threat_text: Optional[str] = None


class AttackPathStep(BaseModel):
    step: int
    phase: str
    description: str
    technique_id: Optional[str] = None


class AttackPathResponse(BaseModel):
    title: str
    steps: List[AttackPathStep]
    summary: str


# Static fallback kill-chain when Groq is unavailable
FALLBACK_ATTACK_PATH = AttackPathResponse(
    title="Phishing Campaign Attack Path",
    summary="AI-generated kill chain showing the full attack progression for a finance-targeted phishing campaign.",
    steps=[
        AttackPathStep(step=1, phase="Reconnaissance", description="Attacker identifies target organisation's finance department email addresses through OSINT and LinkedIn scraping.", technique_id="T1589"),
        AttackPathStep(step=2, phase="Weaponization", description="Malicious document crafted with embedded macro payload and lookalike domain 'secure-login-update.com' registered.", technique_id="T1587.001"),
        AttackPathStep(step=3, phase="Delivery", description="Spear-phishing email sent to finance team with urgency lure, containing link to credential harvesting page.", technique_id="T1566.002"),
        AttackPathStep(step=4, phase="Credential Harvest", description="Victim enters corporate credentials on the phishing page. Attacker captures username, password, and MFA token.", technique_id="T1056.004"),
        AttackPathStep(step=5, phase="VPN Access", description="Attacker uses stolen credentials to authenticate to the corporate VPN from IP 185.199.108.153.", technique_id="T1133"),
        AttackPathStep(step=6, phase="Lateral Movement", description="Using compromised VPN session, attacker moves laterally through internal network, targeting file servers and domain controllers.", technique_id="T1021.001"),
        AttackPathStep(step=7, phase="Privilege Escalation", description="Attacker exploits CVE-2023-3519 to escalate privileges on the Citrix ADC, gaining domain admin access.", technique_id="T1068"),
        AttackPathStep(step=8, phase="Ransomware Deploy", description="LockBit ransomware payload deployed across endpoints via PsExec. Volume shadow copies deleted. Ransom note dropped.", technique_id="T1486"),
    ]
)


GROQ_PROMPT = """You are a cyber threat intelligence analyst. Given the following threat description, generate an attack path (kill chain) showing the full attack progression.

Return ONLY a valid JSON object with this exact structure:
{{
  "title": "Brief attack path title",
  "summary": "One-sentence summary of the attack progression",
  "steps": [
    {{
      "step": 1,
      "phase": "Phase name (e.g. Reconnaissance, Delivery, Exploitation)",
      "description": "Detailed description of this phase",
      "technique_id": "MITRE ATT&CK technique ID if applicable, or null"
    }}
  ]
}}

Include 5-8 steps covering the full kill chain. Be specific to the threat described.

THREAT DESCRIPTION:
{threat_text}
"""


@router.post("/attack-path", response_model=AttackPathResponse, summary="AI Attack Path Prediction")
async def generate_attack_path(request: AttackPathRequest = None):
    """Generate an AI-powered kill chain / attack path prediction.
    Uses Groq LLM if the API key is available, otherwise returns a static example.
    """
    threat_text = (request.threat_text if request and request.threat_text else
                   "Phishing campaign targeting finance department using domain secure-login-update.com and IP 185.199.108.153, linked to LockBit ransomware and FIN7 threat actor, exploiting CVE-2023-3519.")

    # If no Groq key, return fallback
    if not settings.GROQ_API_KEY:
        logger.info("No GROQ_API_KEY set — returning static attack path.")
        return FALLBACK_ATTACK_PATH

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": settings.GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a cyber threat intelligence expert. Always respond with valid JSON only."},
                        {"role": "user", "content": GROQ_PROMPT.format(threat_text=threat_text)}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2048
                }
            )
            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]
            # Strip markdown code fences if present
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()

            parsed = json.loads(content)
            return AttackPathResponse(**parsed)

    except Exception as e:
        logger.error(f"Groq attack-path generation failed: {e}", exc_info=True)
        # Fall back to static response
        return FALLBACK_ATTACK_PATH


@router.get("/attack-path", response_model=AttackPathResponse, summary="Get default Attack Path")
async def get_default_attack_path():
    """Return the default static attack path for the example phishing campaign."""
    return FALLBACK_ATTACK_PATH
