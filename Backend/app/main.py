import json
import hashlib
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from .siem import router as siem_router
from .ioc_graph import router as ioc_graph_router
from .attack_path import router as attack_path_router
from .threat_feed import router as threat_feed_router
from .yara import router as yara_router
from app.database import init_db, close_db, get_db, save_analysis, get_analyses_history, get_analysis_by_id, check_db_health
from app.cache import compute_cache_key, get_from_cache, store_in_cache
from app.schemas import (
    ThreatAnalysisRequest, ThreatAnalysisResponse,
    HistoryListResponse, OptionsSchema
)
from app.services.ingestion import extract_text_from_file
from app.services.extractor import extract_iocs
from app.services.enrichment import enrich_analysis
from app.services.risk import calculate_risk
from app.services.ai import run_ai_analysis
from app.services.rules import generate_detection_rules

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY COUNTERS
# ──────────────────────────────────────────────────────────────────────────────
APP_START_TIME = datetime.now()
REQUEST_COUNTER = 0
ANALYSIS_COUNTER = 0
ERROR_COUNTER = 0
CACHE_HIT_COUNTER = 0
CACHE_MISS_COUNTER = 0
TOTAL_RESPONSE_TIME = 0.0

# ──────────────────────────────────────────────────────────────────────────────
# MITRE CATALOG (loaded at startup)
# ──────────────────────────────────────────────────────────────────────────────
MITRE_CATALOG = []
MITRE_TECHNIQUE_IDS = []

try:
    with open("app/data/mitre_catalog.json", "r") as f:
        MITRE_CATALOG = json.load(f)
    # Flatten all technique IDs for AI constraint
    for tactic_group in MITRE_CATALOG:
        for tech in tactic_group.get("techniques", []):
            MITRE_TECHNIQUE_IDS.append(tech["id"])
    logger.info(f"MITRE ATT&CK Catalog loaded: {len(MITRE_TECHNIQUE_IDS)} techniques.")
except Exception as e:
    logger.error(f"Failed to load local MITRE catalog: {str(e)}")


# ──────────────────────────────────────────────────────────────────────────────
# APP LIFECYCLE (MongoDB connect/disconnect)
# ──────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    logger.info("Database initialized.")
    yield
    # Shutdown
    await close_db()
    logger.info("Database connection closed.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="SISA Sentinel — AI Threat Intelligence & MITRE ATT&CK Mapping REST API",
    lifespan=lifespan
)

# Enable CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# REGISTER BONUS-FEATURE ROUTERS
# ──────────────────────────────────────────────────────────────────────────────
app.include_router(yara_router, tags=["YARA"])
app.include_router(siem_router, prefix="/api", tags=["SIEM"])
app.include_router(ioc_graph_router, prefix="/api", tags=["IOC Graph"])
app.include_router(attack_path_router, prefix="/api", tags=["Attack Path"])
app.include_router(threat_feed_router, prefix="/api", tags=["Threat Feed"])


# ──────────────────────────────────────────────────────────────────────────────
# REQUEST TIMING MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    global REQUEST_COUNTER, TOTAL_RESPONSE_TIME, ERROR_COUNTER

    start = time.perf_counter()
    REQUEST_COUNTER += 1

    try:
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        TOTAL_RESPONSE_TIME += elapsed_ms

        response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
        logger.info(
            f"{request.method} {request.url.path} → {response.status_code} in {elapsed_ms:.2f}ms"
        )

        if response.status_code >= 500:
            ERROR_COUNTER += 1

        return response
    except Exception:
        ERROR_COUNTER += 1
        raise


# ──────────────────────────────────────────────────────────────────────────────
# MITRE CROSS-REFERENCE
# ──────────────────────────────────────────────────────────────────────────────
def cross_reference_mitre(mappings: list) -> list:
    """
    Cross-references AI-generated technique IDs against the local MITRE catalog
    to ensure correct technique names and valid tactic assignments.
    """
    if not MITRE_CATALOG:
        return mappings

    updated_mappings = []
    for mapping in mappings:
        tech_id = mapping.get("technique_id", "").strip().upper()
        found = False

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
            logger.warning(f"MITRE technique {tech_id} not found in local catalog.")

    return updated_mappings


# ──────────────────────────────────────────────────────────────────────────────
# THREAT ANALYSIS PIPELINE
# ──────────────────────────────────────────────────────────────────────────────
async def run_threat_pipeline(
    content: str,
    input_type: str,
    options: OptionsSchema,
    filename: str = ""
) -> dict:
    """
    Modular execution of threat analysis pipeline with:
    - Per-stage error handling (degraded response on partial failure)
    - Pipeline timing for each stage
    - Conditional execution based on options flags
    """
    global ANALYSIS_COUNTER
    ANALYSIS_COUNTER += 1

    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    errors = []
    timing = {}
    pipeline_start = time.perf_counter()

    # ── Stage 1: IOC Extraction (F2) ──
    t0 = time.perf_counter()
    try:
        iocs = extract_iocs(content)
    except Exception as e:
        iocs = []
        errors.append({"stage": "ioc_extraction", "error": str(e)})
        logger.error(f"IOC extraction failed: {str(e)}", exc_info=True)
    timing["extraction_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # ── Stage 2: Enrichment (F3) ──
    t0 = time.perf_counter()
    try:
        enrichment = await enrich_analysis(iocs, content)
    except Exception as e:
        enrichment = {
            "cve_id": "N/A", "cvss": 0.0, "severity": "Unknown",
            "description": "", "exploit_available": False,
            "malware_families": [], "threat_actors": []
        }
        errors.append({"stage": "enrichment", "error": str(e)})
        logger.error(f"Enrichment failed: {str(e)}", exc_info=True)
    timing["enrichment_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # ── Stage 3: Risk Scoring (F5) — conditional ──
    t0 = time.perf_counter()
    try:
        risk_results = calculate_risk(enrichment, iocs, enabled=options.risk_scoring)
    except Exception as e:
        risk_results = {"risk_score": 0, "risk_level": "N/A", "risk_factors": []}
        errors.append({"stage": "risk_scoring", "error": str(e)})
        logger.error(f"Risk scoring failed: {str(e)}", exc_info=True)
    timing["risk_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # ── Stage 4: AI Analysis + MITRE Mapping (F4, F6) — conditional MITRE ──
    t0 = time.perf_counter()
    try:
        ai_results = run_ai_analysis(
            content, iocs,
            mitre_enabled=options.mitre_mapping,
            mitre_technique_ids=MITRE_TECHNIQUE_IDS
        )
        if options.mitre_mapping:
            mitre_mappings = cross_reference_mitre(ai_results.get("mitre_mapping", []))
        else:
            mitre_mappings = []
    except Exception as e:
        ai_results = {
            "ai_report": {
                "summary": "", "attack_scenario": "", "business_impact": "",
                "immediate_actions": [], "long_term_remediation": [], "monitoring": []
            },
            "mitre_mapping": []
        }
        mitre_mappings = []
        errors.append({"stage": "ai_analysis", "error": str(e)})
        logger.error(f"AI analysis failed: {str(e)}", exc_info=True)
    timing["ai_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # ── Stage 5: Detection Rules (F7) — conditional ──
    t0 = time.perf_counter()
    try:
        detection_rules = generate_detection_rules(
            iocs, enrichment, risk_results["risk_level"],
            enabled=options.generate_rules
        )
    except Exception as e:
        detection_rules = {"sigma": "", "yara": "", "splunk": "", "kql": ""}
        errors.append({"stage": "rule_generation", "error": str(e)})
        logger.error(f"Rule generation failed: {str(e)}", exc_info=True)
    timing["rules_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # Total pipeline time
    timing["total_ms"] = round((time.perf_counter() - pipeline_start) * 1000, 2)

    # ── Assemble response ──
    analysis_data = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "input_type": input_type,
        "raw_input": content[:5000],  # Store first 5000 chars
        "cached": False,
        "risk_score": risk_results["risk_score"],
        "risk_level": risk_results["risk_level"],
        "risk_factors": risk_results["risk_factors"],
        "iocs": iocs,
        "enrichment": enrichment,
        "mitre_mapping": mitre_mappings,
        "ai_report": ai_results.get("ai_report", {}),
        "detection_rules": detection_rules,
        "errors": errors,
        "pipeline_timing": timing,
        "options": options.model_dump()
    }

    # Persist to MongoDB
    db = get_db()
    await save_analysis(analysis_data)

    return analysis_data


# ──────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """
    Health check endpoint with embedded runtime metrics and dependency status.
    """
    db_healthy = False
    try:
        db_healthy = await check_db_health()
    except Exception:
        db_healthy = False

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": round((datetime.now() - APP_START_TIME).total_seconds(), 1),
        "version": settings.PROJECT_VERSION,
        "metrics": {
            "total_requests": REQUEST_COUNTER,
            "total_analyses": ANALYSIS_COUNTER,
            "avg_response_time_ms": round(
                TOTAL_RESPONSE_TIME / max(REQUEST_COUNTER, 1), 2
            ),
            "error_count": ERROR_COUNTER,
            "cache_hit_count": CACHE_HIT_COUNTER,
            "cache_miss_count": CACHE_MISS_COUNTER
        },
        "dependencies": {
            "database": db_healthy,
            "groq_api": bool(settings.GROQ_API_KEY),
            "nvd_api": True  # Always available (has local fallback)
        }
    }


@app.post("/api/analyze-threat", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Submits raw threat text for analysis and extraction.
    Supports caching: identical input content returns cached response.
    Supports conditional pipeline execution via options flags.
    """
    global CACHE_HIT_COUNTER, CACHE_MISS_COUNTER

    try:
        options = request.options or OptionsSchema()
        db = get_db()

        # Cache check
        cache_key = compute_cache_key(request.content)
        cached = await get_from_cache(cache_key, db)
        if cached:
            CACHE_HIT_COUNTER += 1
            cached["cached"] = True
            return cached

        CACHE_MISS_COUNTER += 1

        # Run pipeline
        result = await run_threat_pipeline(
            request.content, request.input_type, options
        )

        # Store in cache
        await store_in_cache(cache_key, result, db)

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline processing failed: {str(e)}"
        )


@app.post("/api/analyze-threat/upload", response_model=ThreatAnalysisResponse)
async def upload_threat_file(
    file: UploadFile = File(...),
    options: Optional[str] = Form(None)
):
    """
    Extracts text from files (PDF, DOCX, DOC, CSV, TXT, JSON) and runs
    the threat analysis pipeline.
    """
    global CACHE_HIT_COUNTER, CACHE_MISS_COUNTER

    try:
        # Validate filename
        if not file.filename:
            raise HTTPException(status_code=400, detail="Uploaded file has no filename")

        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        supported = {"pdf", "docx", "doc", "txt", "csv", "json"}
        if ext not in supported:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: .{ext}. Supported: {', '.join(sorted(supported))}"
            )

        # Read file bytes
        file_bytes = await file.read()

        # File size check (10MB max)
        if len(file_bytes) > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail="File exceeds 10MB size limit"
            )

        # Parse options from form data
        parsed_options = OptionsSchema()
        if options:
            try:
                parsed_options = OptionsSchema(**json.loads(options))
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Failed to parse options form field: {str(e)}")

        db = get_db()

        # Cache check (hash the file bytes)
        cache_key = hashlib.sha256(file_bytes).hexdigest()
        cached = await get_from_cache(cache_key, db)
        if cached:
            CACHE_HIT_COUNTER += 1
            cached["cached"] = True
            return cached

        CACHE_MISS_COUNTER += 1

        # Ingestion: extract text from file (F1)
        extracted_text = extract_text_from_file(file_bytes, file.filename)

        if not extracted_text.strip():
            raise HTTPException(
                status_code=400,
                detail="Document contains no readable text content"
            )

        # Run pipeline
        result = await run_threat_pipeline(
            extracted_text, "file", parsed_options, file.filename
        )

        # Store in cache
        await store_in_cache(cache_key, result, db)

        return result

    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"File upload pipeline error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"File processing failed: {str(e)}"
        )


@app.get("/api/analyses", response_model=HistoryListResponse)
async def get_analyses(
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = Query(None, description="Filter: Critical, High, Medium, Low"),
    input_type: Optional[str] = Query(None, description="Filter: text, file"),
    sort: str = Query("desc", description="Sort order: asc or desc")
):
    """
    Retrieves paginated analysis history from database with optional filters.
    """
    items, total = await get_analyses_history(
        page=page,
        page_size=pageSize,
        risk_level=risk_level,
        input_type=input_type,
        sort_order=sort
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "pageSize": pageSize
    }


@app.get("/api/analyses/{analysis_id}", response_model=ThreatAnalysisResponse)
async def get_analysis_detail(analysis_id: str):
    """
    Retrieves full detail of a single analysis run by ID.
    Returns the complete raw_input (un-truncated) in the detail view.
    """
    # Basic UUID format validation
    try:
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid analysis_id format. Expected UUID."
        )

    item = await get_analysis_by_id(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return item
