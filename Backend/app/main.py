import json
import logging
import uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db, save_analysis, get_analyses_history, get_analysis_by_id
from app.schemas import ThreatAnalysisRequest, ThreatAnalysisResponse, HistoryListResponse
from app.services.ingestion import extract_text_from_file
from app.services.extractor import extract_iocs
from app.services.enrichment import enrich_analysis
from app.services.risk import calculate_risk
from app.services.ai import run_ai_analysis
from app.services.rules import generate_detection_rules

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="SISA Sentinel - AI Threat Intelligence & MITRE ATT&CK Mapping REST API"
)

# Enable CORS for Frontend React/Vite Dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load MITRE Catalog at startup
MITRE_CATALOG = []
try:
    with open("app/data/mitre_catalog.json", "r") as f:
        MITRE_CATALOG = json.load(f)
    logger.info("MITRE ATT&CK Catalog loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load local MITRE catalog: {str(e)}")

# Initialize DB on Startup
@app.on_event("startup")
def startup_db():
    init_db()
    logger.info("Database initialized.")

@app.get("/health")
def health_check():
    """Health check endpoint for system monitoring."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

def cross_reference_mitre(mappings: list) -> list:
    """
    Cleans up technique names in AI mappings to match standard MITRE JSON entries.
    """
    if not MITRE_CATALOG:
        return mappings

    updated_mappings = []
    for mapping in mappings:
        tech_id = mapping.get("technique_id", "").strip().upper()
        found = False
        
        # Scan catalog tactics
        for tactic_group in MITRE_CATALOG:
            for tech in tactic_group["techniques"]:
                if tech["id"] == tech_id:
                    updated_mappings.append({
                        "tactic": tactic_group["tactic"],
                        "technique": tech["name"],
                        "technique_id": tech_id,
                        "confidence": mapping.get("confidence", "Medium")
                    })
                    found = True
                    break
            if found:
                break
                
        # If not found in catalog, retain original but log warning
        if not found:
            updated_mappings.append(mapping)
            
    return updated_mappings

def run_threat_pipeline(content: str, input_type: str, filename: str = "") -> dict:
    """
    Modular execution of threat analysis pipeline.
    """
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # 1. Extract IOCs (F2)
    iocs = extract_iocs(content)
    
    # 2. Enrich Threats (F3)
    enrichment = enrich_analysis(iocs, content)
    
    # 3. Calculate Risk Score (F5)
    risk_results = calculate_risk(enrichment, iocs)
    
    # 4. Generate AI report and map MITRE tactics (F6, F4)
    ai_results = run_ai_analysis(content, iocs)
    
    # Cross-reference against local catalog to avoid arbitrary AI technique descriptions (F4)
    mitre_mappings = cross_reference_mitre(ai_results.get("mitre_mapping", []))
    
    # 5. Generate Detection Rules (F7)
    detection_rules = generate_detection_rules(iocs, enrichment, risk_results["risk_level"])
    
    # Assemble analysis payload
    analysis_data = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "input_type": input_type,
        "risk_score": risk_results["risk_score"],
        "risk_level": risk_results["risk_level"],
        "risk_factors": risk_results["risk_factors"],
        "iocs": iocs,
        "enrichment": enrichment,
        "mitre_mapping": mitre_mappings,
        "ai_report": ai_results.get("ai_report", {}),
        "detection_rules": detection_rules
    }
    
    # Persist to SQLite
    save_analysis(analysis_data)
    
    return analysis_data

@app.post("/api/analyze-threat", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Submits raw threat text for analysis and extraction.
    """
    try:
        result = run_threat_pipeline(request.content, request.input_type)
        return result
    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")

@app.post("/api/analyze-threat/upload", response_model=ThreatAnalysisResponse)
async def upload_threat_file(
    file: UploadFile = File(...),
    options: Optional[str] = Form(None)
):
    """
    Extracts text from files (PDF, DOCX, CSV, TXT, JSON) and runs the pipeline.
    """
    try:
        # Read file bytes
        file_bytes = await file.read()
        
        # Ingestion Text Extraction (F1)
        extracted_text = extract_text_from_file(file_bytes, file.filename)
        
        if not extracted_text.strip():
            raise HTTPException(status_code=400, detail="Document contains no readable text contents")
            
        # Run threat pipeline
        result = run_threat_pipeline(extracted_text, "file", file.filename)
        return result
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"File upload pipeline error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

@app.get("/api/analyses", response_model=HistoryListResponse)
def get_analyses(
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100)
):
    """
    Retrieves paginated analyses logs from database.
    """
    items, total = get_analyses_history(page, pageSize)
    return {
        "items": items,
        "total": total,
        "page": page,
        "pageSize": pageSize
    }

@app.get("/api/analyses/{analysis_id}", response_model=ThreatAnalysisResponse)
def get_analysis_detail(analysis_id: str):
    """
    Retrieves detail of single analysis run by ID.
    """
    item = get_analysis_by_id(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return item
