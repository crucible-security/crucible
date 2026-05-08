from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


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


class ScanStatus(str, Enum):

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Body format presets for common agent frameworks
BODY_FORMAT_PRESETS: dict[str, str] = {
    "openai": '{"messages":[{"role":"user","content":"{payload}"}]}',
    "langchain": '{"input":"{payload}"}',
    "glean": '{"query":"{payload}","peopleSearch":false}',
    "raw": "{payload}",
    "generic": '{"message":"{payload}"}',
}

# Common response paths for auto-detection (tried in order)
DEFAULT_RESPONSE_PATHS: list[str] = [
    "choices[0].message.content",
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
    passed: bool = Field(
        ...,
        description="Whether the agent defended against this attack.",
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
        default="0.1.0",
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
