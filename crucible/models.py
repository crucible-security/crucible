from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator

try:
    _crucible_version = version("crucible-security")
except PackageNotFoundError:
    _crucible_version = "0.0.0-dev"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    INSECURE_OUTPUT = "insecure_output"
    TRAINING_DATA_POISONING = "training_data_poisoning"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"
    INSECURE_PLUGIN = "insecure_plugin"
    EXCESSIVE_AGENCY = "excessive_agency"
    OVERRELIANCE = "overreliance"
    MODEL_THEFT = "model_theft"
    GOAL_HIJACKING = "goal_hijacking"
    JAILBREAK = "jailbreak"


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    INCOMPLETE = "INCOMPLETE"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProviderPreset:
    body_template: str
    response_path: str
    default_timeout: float
    extra_headers: dict[str, str] = field(default_factory=dict)
    description: str = ""
    requires_model: bool = False
    url_suffix: str = (
        ""  # Appended to --target URL when preset is used (e.g. /api/chat)
    )


PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "openai": ProviderPreset(
        '{"messages":[{"role":"user","content":"{payload}"}]}',
        "choices[0].message.content",
        30.0,
    ),
    "langchain": ProviderPreset(
        '{"input":"{payload}"}',
        "result",
        30.0,
    ),
    "glean": ProviderPreset(
        '{"query":"{payload}","peopleSearch":false}',
        "",
        30.0,
    ),
    "raw": ProviderPreset(
        "{payload}",
        "",
        30.0,
    ),
    "generic": ProviderPreset(
        '{"message":"{payload}"}',
        "",
        30.0,
    ),
    "ollama": ProviderPreset(
        '{"model":"{model}","messages":[{"role":"user","content":"{payload}"}],"stream":false}',
        "message.content",
        120.0,
        requires_model=True,
        description="Ollama local inference server (POST /api/chat)",
        url_suffix="/api/chat",
    ),
    "lmstudio": ProviderPreset(
        '{"messages":[{"role":"user","content":"{payload}"}],"temperature":0}',
        "choices[0].message.content",
        120.0,
        description="LM Studio OpenAI-compatible API (POST /v1/chat/completions)",
    ),
    "huggingface-tgi": ProviderPreset(
        '{"inputs":"{payload}","parameters":{}}',
        "generated_text",
        120.0,
        description="HuggingFace Text Generation Inference (POST /generate)",
    ),
}

# Body format presets for common agent frameworks (backwards compatible shim)
BODY_FORMAT_PRESETS: dict[str, str] = {
    name: preset.body_template for name, preset in PROVIDER_PRESETS.items()
}


# Common response paths for auto-detection (tried in order)
DEFAULT_RESPONSE_PATHS: list[str] = [
    "choices[0].message.content",
    "message.content",
    "result",
    "response",
    "answer",
    "output",
    "text",
    "content",
    "data.response",
    "data.text",
    "data.content",
    "results[0].answer",
    "response.text",
    "message",
]


class AgentTarget(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable name for the target agent.",
    )
    url: HttpUrl = Field(
        ...,
        description="The HTTP(S) endpoint to send attack payloads to.",
    )
    provider: str = Field(
        default="custom",
        description="Agent provider: openai, anthropic, groq, or custom.",
    )
    method: str = Field(
        default="POST",
        pattern=r"^(GET|POST|PUT|PATCH|DELETE)$",
        description="HTTP method used for requests.",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional headers to include in requests.",
    )
    body_template: str = Field(
        default='{"message": "{payload}"}',
        description="JSON body template with {payload} placeholder.",
    )
    timeout: float = Field(
        default=30.0,
        gt=0,
        le=300,
        description="Request timeout in seconds.",
    )
    response_path: str = Field(
        default="",
        description="JMESPath expression to extract agent response from JSON.",
    )
    retry_count: int = Field(
        default=2,
        ge=0,
        le=10,
        description="Number of retries on failure.",
    )
    delay_ms: int = Field(
        default=500,
        ge=0,
        le=60000,
        description="Delay between requests in milliseconds.",
    )
    proxy: str = Field(
        default="",
        description="HTTP proxy URL for traffic inspection (e.g. Burp Suite).",
    )
    description: str = Field(
        default="",
        max_length=500,
        description="Optional description of the target agent.",
    )

    @field_validator("method", mode="before")
    @classmethod
    def _uppercase_method(cls, v: str) -> str:
        return v.upper()

    def build_payload_body(self, payload: str) -> str:
        import ast
        import json

        template = self.body_template
        data = None

        try:
            # 1. Try standard JSON first
            data = json.loads(template)
        except json.JSONDecodeError:
            try:
                # 2. Try loose parsing (handles missing quotes from shell stripping)
                # We need to handle the {payload} placeholder by temporarily replacing it
                # with a safe string that literal_eval won't choke on.
                placeholder = "___CRUCIBLE_PAYLOAD_PLACEHOLDER___"
                loose_template = template.replace("{payload}", placeholder)
                data = ast.literal_eval(loose_template)

                # If literal_eval succeeded, we have a dict.
                # Now we need a recursive replacement to put the placeholder back.
                def restore_placeholder(obj: Any) -> Any:
                    if isinstance(obj, str):
                        return obj.replace(placeholder, "{payload}")
                    if isinstance(obj, list):
                        return [restore_placeholder(item) for item in obj]
                    if isinstance(obj, dict):
                        return {k: restore_placeholder(v) for k, v in obj.items()}
                    return obj

                data = restore_placeholder(data)
            except (ValueError, SyntaxError):
                # 3. Final fallback to raw string replacement
                return self.body_template.replace("{payload}", payload)

        # Recursive function to find and replace {payload} in the JSON structure
        def inject(obj: Any) -> Any:
            if isinstance(obj, str):
                return obj.replace("{payload}", payload)
            if isinstance(obj, list):
                return [inject(item) for item in obj]
            if isinstance(obj, dict):
                return {k: inject(v) for k, v in obj.items()}
            return obj

        injected_data = inject(data)
        return json.dumps(injected_data)


class Finding(BaseModel):
    id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this finding.",
    )
    attack_name: str = Field(
        ...,
        description="Name of the attack that produced this finding.",
    )
    category: AttackCategory = Field(
        ...,
        description="OWASP attack category.",
    )
    severity: Severity = Field(
        ...,
        description="Severity level of the finding.",
    )
    title: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Short title summarizing the finding.",
    )
    description: str = Field(
        default="",
        description="Detailed description of the vulnerability.",
    )
    payload: str = Field(
        ...,
        description="The attack payload that triggered this finding.",
    )
    response_snippet: str = Field(
        default="",
        max_length=2000,
        description="Relevant portion of the agent's response.",
    )
    passed: bool | None = Field(
        default=None,
        description="Whether the agent defended against this attack.",
    )
    execution_error: bool = Field(
        default=False,
        description="Whether an execution error (timeout/network error) occurred during the attack.",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this finding (0.0-1.0).",
    )
    remediation: str = Field(
        default="",
        description="Suggested remediation steps.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Links to relevant documentation or standards.",
    )
    owasp_ref: str = Field(
        default="",
        description=(
            "Maps to OWASP Agentic AI Top 10 risk category. "
            "Note: this references the IMPACT category "
            "(e.g., OWASP-AGENT-003: Goal Hijacking), not the attack vector "
            "(which is typically prompt injection). "
            "See docs/owasp_mapping.md for full mapping."
        ),
    )
    atlas_technique: str = Field(
        default="",
        description="MITRE ATLAS technique ID (e.g. AML.T0051).",
    )
    atlas_tactic: str = Field(
        default="",
        description="MITRE ATLAS tactic ID (e.g. AML.TA0002).",
    )
    nist_function: str = Field(
        default="",
        description="NIST AI RMF function (GOVERN/MAP/MEASURE/MANAGE).",
    )
    nist_category: str = Field(
        default="",
        description="NIST AI RMF category (e.g. MEASURE 2.5).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this finding was generated.",
    )


class ModuleResult(BaseModel):
    module_name: str = Field(
        ...,
        description="Name of the module.",
    )
    module_description: str = Field(
        default="",
        description="Description of what this module tests.",
    )
    category: AttackCategory = Field(
        ...,
        description="Primary attack category.",
    )
    total_attacks: int = Field(
        default=0,
        ge=0,
        description="Total number of attacks executed.",
    )
    passed: int = Field(
        default=0,
        ge=0,
        description="Number of attacks the agent defended against.",
    )
    failed: int = Field(
        default=0,
        ge=0,
        description="Number of attacks that succeeded.",
    )
    errors: int = Field(
        default=0,
        ge=0,
        description="Number of attacks that encountered errors.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Individual findings from each attack.",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Deduction-based score (0-100).",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="How long this module took to execute.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional module-specific metadata.",
    )

    @property
    def pass_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return (self.passed / self.total_attacks) * 100.0


class ScanResult(BaseModel):
    id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for this scan.",
    )
    target: AgentTarget = Field(
        ...,
        description="The agent target that was scanned.",
    )
    status: ScanStatus = Field(
        default=ScanStatus.PENDING,
        description="Current status of the scan.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the scan started.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When the scan completed.",
    )
    modules: list[ModuleResult] = Field(
        default_factory=list,
        description="Results from each security module.",
    )
    total_findings: int = Field(
        default=0,
        ge=0,
        description="Total failed findings across all modules.",
    )
    critical_count: int = Field(
        default=0,
        ge=0,
        description="Number of critical findings.",
    )
    high_count: int = Field(
        default=0,
        ge=0,
        description="Number of high-severity findings.",
    )
    medium_count: int = Field(
        default=0,
        ge=0,
        description="Number of medium-severity findings.",
    )
    low_count: int = Field(
        default=0,
        ge=0,
        description="Number of low-severity findings.",
    )
    info_count: int = Field(
        default=0,
        ge=0,
        description="Number of informational findings.",
    )
    overall_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Aggregate score (0-100, deduction-based).",
    )
    failed_execution_count: int = Field(
        default=0,
        ge=0,
        description="Number of attacks that failed to execute due to timeout or network errors.",
    )
    grade: Grade = Field(
        default=Grade.F,
        description="Letter grade (A/B/C/D/F).",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Total scan duration.",
    )
    crucible_version: str = Field(
        default=_crucible_version,
        description="Version of Crucible used for this scan.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan-level metadata.",
    )

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target.name,
            "status": self.status.value,
            "grade": self.grade.value,
            "score": self.overall_score,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "duration": f"{self.duration_seconds:.1f}s",
        }

    def get_failed_findings(self) -> list[Finding]:
        failed = []
        for module in self.modules:
            for finding in module.findings:
                if finding.passed is False and not getattr(
                    finding, "execution_error", False
                ):
                    failed.append(finding)
        return failed


# --- Multi-turn & Behavioral Models ---


class ConversationTurn(BaseModel):
    role: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConversationHistory(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    turns: list[ConversationTurn] = Field(default_factory=list)


class DriftScore(BaseModel):
    turn_index: int
    semantic_drift: float = Field(ge=0.0, le=1.0)
    formality_score: float = Field(ge=0.0, le=1.0)
    topic_adherence: float = Field(ge=0.0, le=1.0)
    refusal_signal: float = Field(ge=0.0, le=1.0)
    composite_drift: float = Field(ge=0.0, le=1.0)


class BehavioralProfile(BaseModel):
    target_name: str
    baseline_length_avg: float = 0.0
    baseline_formality_avg: float = 0.0
    baseline_refusal_avg: float = 0.0
    drift_history: list[DriftScore] = Field(default_factory=list)
    trust_degraded: bool = False
    integrity_score: Grade = Grade.A


# --- Profiler Models ---


class AgentCapability(str, Enum):
    SEARCH = "search"
    CODE_EXECUTION = "code_execution"
    DATABASE_ACCESS = "database_access"
    EMAIL = "email"
    EXTERNAL_API = "external_api"
    FILE_SYSTEM = "file_system"
    UNKNOWN = "unknown"


class AgentProfile(BaseModel):
    target_name: str
    agent_type: str = "generic"
    inferred_capabilities: list[AgentCapability] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    system_prompt_hints: str = ""
    recommended_modules: list[str] = Field(default_factory=list)


# --- Compliance Models ---


class RiskClassification(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNCLEAR = "unclear"


class ComplianceRequirement(BaseModel):
    article: str
    description: str
    risk_classification: RiskClassification
    status: ComplianceStatus
    related_findings: list[str] = Field(default_factory=list)
    remediation: str = ""


class ComplianceReport(BaseModel):
    scan_id: str
    target_name: str
    standard: str = "EU AI Act 2024"
    requirements: list[ComplianceRequirement] = Field(default_factory=list)
    overall_status: ComplianceStatus = ComplianceStatus.UNCLEAR
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingStatus(str, Enum):
    FIXED = "fixed"  # was failing in scan_a, passing in scan_b
    REGRESSED = "regressed"  # was passing in scan_a, failing in scan_b
    NEW = "new"  # not present in scan_a, failing in scan_b
    RESOLVED = "resolved"  # not present in scan_a, passing in scan_b
    UNCHANGED_FAIL = "unchanged_fail"  # failing in both
    UNCHANGED_PASS = "unchanged_pass"  # passing in both
    EXECUTION_ERROR = "execution_error"  # errored in one or both


class FindingDiff(BaseModel):
    attack_id: str
    attack_name: str
    status: FindingStatus
    severity: Severity
    scan_a_passed: bool | None = None  # None if not present
    scan_b_passed: bool | None = None  # None if not present
    atlas_technique: str = ""
    nist_category: str = ""
    module: str = ""


class ModuleDiff(BaseModel):
    module_name: str
    score_a: float
    score_b: float
    score_delta: float
    fixed_count: int
    regressed_count: int
    new_count: int
    findings: list[FindingDiff]


class DiffResult(BaseModel):
    scan_a_path: str
    scan_b_path: str
    scan_a_version: str
    scan_b_version: str
    scan_a_timestamp: str | None = None
    scan_b_timestamp: str | None = None
    score_a: float
    score_b: float
    score_delta: float
    grade_a: Grade
    grade_b: Grade
    total_fixed: int
    total_regressed: int
    total_new: int
    total_unchanged_fail: int
    modules: list[ModuleDiff]
    generated_at: str
    warning: str | None = None


class PreflightResult(BaseModel):
    reachable: bool
    method_accepted: bool
    looks_like_llm_endpoint: bool
    status_code: int
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 4 — crucible watch models
# ---------------------------------------------------------------------------


class WatchInterval(str, Enum):
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    ONE_HOUR = "1h"
    SIX_HOURS = "6h"
    TWELVE_HOURS = "12h"
    DAILY = "24h"

    def to_seconds(self) -> int:
        """Convert the interval string to seconds."""
        mapping = {
            "5m": 300,
            "15m": 900,
            "1h": 3600,
            "6h": 21600,
            "12h": 43200,
            "24h": 86400,
        }
        return mapping[self.value]


class WatchConfig(BaseModel):
    """Configuration for a crucible watch session."""

    target: AgentTarget
    interval: WatchInterval = WatchInterval.ONE_HOUR
    drift_threshold: float = 0.15  # 15% behavioral change triggers alert
    score_threshold: float = 10.0  # 10-point score drop triggers alert
    alert_slack_webhook: str | None = None
    alert_email: str | None = None  # future use
    modules: list[str] | None = None  # restrict to specific modules
    fail_on_alert: bool = False  # exit code 1 when alert fires (for CI)
    skip_preflight: bool = False


class WatchBaseline(BaseModel):
    """A stored baseline scan result used as the reference for drift detection."""

    created_at: str
    target_url: str
    scan_result: ScanResult
    behavioral_profile: BehavioralProfile | None = None
    version: str  # Crucible version that created this baseline


class WatchAlert(BaseModel):
    """An alert fired when behavioral drift or score regression is detected."""

    fired_at: str
    alert_type: str  # "score_drop" | "drift_detected" | "regression"
    score_before: float
    score_after: float
    score_delta: float
    drift_score: float | None = None
    diff_result: DiffResult
    severity: str  # "WARNING" | "CRITICAL"
    target_url: str


class WatchCheckResult(BaseModel):
    """Result of a single watch check cycle."""

    checked_at: str
    target_url: str
    cycle_number: int
    baseline_score: float
    current_score: float
    score_delta: float
    alert_fired: bool
    alert: WatchAlert | None = None
    regressed_count: int = 0
    fixed_count: int = 0
    new_count: int = 0


class WatchStatus(BaseModel):
    """Summary of a watch session, read from watch_log.jsonl."""

    running: bool
    started_at: str | None
    last_check_at: str | None
    next_check_at: str | None
    alert_count: int
    check_count: int
    baseline_path: str
    current_score: float | None
    baseline_score: float | None
