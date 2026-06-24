import asyncio
import logging
from app.database import init_db, close_db, get_db
from app.main import run_threat_pipeline
from app.schemas import OptionsSchema

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_data")

SCENARIOS = [
    {
        "title": "Phishing campaign targeting finance dept",
        "input_type": "text",
        "content": (
            "URGENT: A spear-phishing campaign has been detected targeting our finance department. "
            "Several employees received emails claiming to be from 'finance-update@payment-security-portal.com' "
            "with the subject line 'Action Required: Update Bank Billing Info'. "
            "The email instructs victims to click on a link: http://login-microsoftonline.com/update to verify credentials. "
            "The attack leverages an active threat actor known as Fancy Bear running campaigns utilizing the AsyncRAT payload to capture keystrokes."
        ),
        "filename": ""
    },
    {
        "title": "Ransomware IOC report (LockBit)",
        "input_type": "text",
        "content": (
            "ALERT: LockBit ransomware payload execution detected in corporate environment. "
            "The threat actor Gold Southfield has exploited Citrix Bleed (CVE-2023-4966) vulnerability in our public-facing gateway. "
            "Upon compromise, volume shadow copies were deleted using vssadmin.exe, and file encryption was initiated. "
            "The ransomware was communicating with C2 server at IP address 185.220.101.5 for payload delivery and key exchange."
        ),
        "filename": ""
    },
    {
        "title": "CVE advisory (medium severity)",
        "input_type": "text",
        "content": (
            "SECURITY ADVISORY: A vulnerability bypass in WinRAR archiver has been published under CVE-2023-38831. "
            "This vulnerability allows remote attackers to execute arbitrary code when a victim opens a crafted ZIP or RAR archive. "
            "No active malware or threat actors have been associated in our environment yet, but virtual patching is recommended."
        ),
        "filename": ""
    },
    {
        "title": "PDF threat report upload simulation",
        "input_type": "file",
        "content": (
            "THREAT ANALYSIS REPORT: APT29 (Nobelium) Campaign targeting European diplomatic entities. "
            "The threat group utilizes a malicious landing domain: security-update-microsoft.com to host payloads. "
            "Initial access exploits Microsoft Office/Windows HTML remote code execution vulnerability (CVE-2023-36884) to execute RomCom RAT. "
            "The following executable file hashes were identified across compromised endpoints: "
            "SHA256: 8f4e2c8a1b0d7c6e5f4d3c2b1a0e9f8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f "
            "SHA1: 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e "
            "MD5: c4ca4238a0b923820dcc509a6f75849b"
        ),
        "filename": "apt29_threat_report.pdf"
    },
    {
        "title": "Low-risk domain check",
        "input_type": "text",
        "content": (
            "INFO: Routine firewall logs inspection detected background internet scanning activity. "
            "A scanner from Shodan crawler at IP address 198.51.100.42 was observed performing routine TCP port scans. "
            "No unauthorized login attempts or malicious payload delivery were associated with this source."
        ),
        "filename": ""
    }
]

async def main():
    logger.info("Starting seed data population...")
    
    # Init database connection
    await init_db()
    db = get_db()
    
    # Clean existing collections to prevent duplicates and start fresh
    logger.info("Cleaning existing database collections...")
    await db.analyses.delete_many({})
    await db.ai_cache.delete_many({})
    
    options = OptionsSchema()
    
    for idx, scenario in enumerate(SCENARIOS, 1):
        logger.info(f"Processing Scenario {idx}: {scenario['title']}")
        try:
            result = await run_threat_pipeline(
                content=scenario["content"],
                input_type=scenario["input_type"],
                options=options,
                filename=scenario["filename"]
            )
            logger.info(f"Successfully seeded Scenario {idx}. ID: {result['analysis_id']} (Risk: {result['risk_level']}, Score: {result['risk_score']})")
        except Exception as e:
            logger.error(f"Failed to seed Scenario {idx}: {str(e)}", exc_info=True)
            
    await close_db()
    logger.info("Seed data population finished.")

if __name__ == "__main__":
    asyncio.run(main())
