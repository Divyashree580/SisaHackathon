from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class OptionsSchema(BaseModel):
    mitre_mapping: bool = True
    generate_rules: bool = True
    risk_scoring: bool = True


class ThreatAnalysisRequest(BaseModel):
    input_type: str = Field(..., description="Source type: 'text' or 'file'")
    content: str = Field(..., description="Raw text threat context, CVE ID, or URL")
    options: Optional[OptionsSchema] = Field(default_factory=OptionsSchema)


class RiskFactor(BaseModel):
    name: str
    points: int


class IOCItem(BaseModel):
    type: str
    value: str
    reputation: str
    enriched: bool
    context: Optional[str] = None


class EnrichmentSchema(BaseModel):
    cve_id: str = "N/A"
    cvss: float = 0.0
    severity: str = "Unknown"
    description: str = ""
    exploit_available: bool = False
    malware_families: List[str] = []
    threat_actors: List[str] = []


class MitreMappingSchema(BaseModel):
    tactic: str
    technique: str
    technique_id: str
    confidence: str


class AIReportSchema(BaseModel):
    summary: str = ""
    attack_scenario: str = ""
    business_impact: str = ""
    immediate_actions: List[str] = []
    long_term_remediation: List[str] = []
    monitoring: List[str] = []


class DetectionRulesSchema(BaseModel):
    sigma: str = ""
    yara: str = ""
    splunk: str = ""
    kql: str = ""


class PipelineError(BaseModel):
    stage: str
    error: str


class PipelineTiming(BaseModel):
    extraction_ms: float = 0
    enrichment_ms: float = 0
    risk_ms: float = 0
    ai_ms: float = 0
    rules_ms: float = 0
    total_ms: float = 0


class ThreatAnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    input_type: str
    raw_input: Optional[str] = None
    cached: bool = False
    risk_score: int
    risk_level: str
    risk_factors: List[RiskFactor] = []
    iocs: List[IOCItem] = []
    enrichment: Optional[EnrichmentSchema] = None
    mitre_mapping: List[MitreMappingSchema] = []
    ai_report: Optional[AIReportSchema] = None
    detection_rules: Optional[DetectionRulesSchema] = None
    errors: List[PipelineError] = []
    pipeline_timing: Optional[PipelineTiming] = None
    options: Optional[OptionsSchema] = None


class HistoryListResponse(BaseModel):
    items: List[ThreatAnalysisResponse]
    total: int
    page: int
    pageSize: int
