# Implementation Plan - Threat Intelligence & Attack Mapping Backend

This plan outlines the technical design, routing structure, modules, and verification steps for the python backend of the **AI-Powered Threat Intelligence & Attack Mapping Platform** built for the **SISA AI-Prism Hackathon 2026**.

We will build a high-performance **FastAPI** application in python, implementing the complete REST API contract and modules outlined in the PRD.

---

## User Review Required

> [!IMPORTANT]
> - **Technology Choice**: Python 3.11+, **FastAPI** for routing, **SQLite** for database storage, and **Uvicorn** as the ASGI server.
> - **AI Integration**: We will integrate the **Anthropic Claude API** (using the standard `anthropic` SDK) to perform intelligent report generation and MITRE ATT&CK mapping. 
> - **Reliability Fallback**: If the `ANTHROPIC_API_KEY` is missing or the external API call fails, the backend will automatically fallback to a template-based heuristic generator. This guarantees the API never fails during evaluations or live demonstrations.

---

## Proposed Changes

We will build the backend inside the [Backend](file:///c:/Users/divya/SisaHackathon/Backend) directory.

### 1. Dependency Scaffolding (`requirements.txt`)
We will install the required dependencies:
- `fastapi`, `uvicorn` (Core web framework)
- `anthropic` (Claude API client)
- `PyPDF2`, `python-docx` (File extraction)
- `python-dotenv` (Environment variable configurations)
- `pydantic` (Data schema validations)

### 2. Configuration (`app/config.py`)
- Setup configuration loading using standard environment variables loaded from `.env`.
- CORS configurations to allow frontend origins (`http://localhost:5173`).

### 3. Database Layer (`app/database.py`)
- Use a single, local SQLite database file `threat_intel.db` initialized at startup.
- Create database tables:
  - `analyses` (record ID, timestamp, input source, risk parameters, AI report sections)
  - `iocs` (extracted values, type, reputation rating, context logs)
  - `mitre_mappings` (mapped tactics, technique name, technique ID, confidence rating)
  - `detection_rules` (rule types, YAML/text contents)
- Simple connection helpers using python's built-in `sqlite3` driver.

### 4. Data Schemas (`app/schemas.py`)
- Define Pydantic request models (`ThreatAnalysisRequest`, `OptionsSchema`) and response models matching the PRD contracts.

### 5. Services Pipeline (`app/services/`)

- **`ingestion.py`**:
  - Handles parsing raw text or extraction from multipart files (supporting PDF, DOCX, CSV, TXT, JSON) into standard text.
- **`extractor.py`**:
  - Regex-based high-speed extraction engine targeting IPv4, domain names, URLs, emails, MD5/SHA1/SHA256 hashes, and CVE-IDs.
- **`enrichment.py`**:
  - Local lookups for common CVEs (CVSS score, description) and exploit availability.
  - Matches IOC values against local blacklists to determine reputation (Malicious, Suspicious, Benign).
- **`risk.py`**:
  - Implements the exact point-scoring formula outlined in Section 9 of the PRD, capping the final score at 100.
- **`ai.py`**:
  - Formats user input and parsed context into a prompt.
  - Calls Anthropic Claude model (`claude-3-5-sonnet`) requesting a structured JSON containing: Summary, Attack Scenario, Business Impact, Immediate/Long-term/Monitoring lists.
  - Automatically falls back to a deterministic text template generator if the API is offline.
- **`rules.py`**:
  - Generates Sigma (YAML) rules, YARA rules, Splunk SPL queries, and Microsoft Sentinel KQL queries based on extracted IOC elements.

### 6. Main Routing Hub (`app/main.py`)
- Implements:
  - `POST /api/analyze-threat` (Submit raw text/CVEs/URLs)
  - `POST /api/analyze-threat/upload` (Multipart file upload)
  - `GET /api/analyses` (Paginated list of previous runs)
  - `GET /api/analyses/{id}` (Get details of a single run by ID)
  - `GET /health` (System monitoring health check)

---

## Verification Plan

### Automated Tests
- Check package compilation: run `python -m compileall app` to verify syntax.
- Verify API server startup: run `uvicorn app.main:app --port 8000` locally.

### Manual Verification
- Execute `curl` commands or run the integrated frontend and verify that REST calls succeed and persist correctly to `threat_intel.db`.
