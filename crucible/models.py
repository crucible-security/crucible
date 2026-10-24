from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

if TYPE_CHECKING:
    from crucible.trace.models import PolicyAction

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


class FindingVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "N/A"
    INCONCLUSIVE = "INCONCLUSIVE"


class AgentCapability(str, Enum):
    MCP = "mcp"
    NETWORK = "network"
    SHELL = "shell"
    FILE_SYSTEM = "file_system"
    DATABASE_ACCESS = "database_access"
    CODE_EXECUTION = "code_execution"
    BROWSER = "browser"
    RAG = "rag"
    MULTI_AGENT = "multi_agent"
    MEMORY = "memory"
    SEARCH = "search"
    EMAIL = "email"
    EXTERNAL_API = "external_api"
    UNKNOWN = "unknown"


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
        '{"model":"{model}","messages":[{"role":"user","content":"{payload}"}]}',
        "choices[0].message.content",
        30.0,
        requires_model=True,
        description="OpenAI Chat Completions API (POST /v1/chat/completions)",
        url_suffix="/v1/chat/completions",
    ),
    "openrouter": ProviderPreset(
        '{"model":"{model}","messages":[{"role":"user","content":"{payload}"}]}',
        "choices[0].message.content",
        60.0,
        requires_model=True,
        description="OpenRouter unified API (POST /api/v1/chat/completions)",
        url_suffix="/api/v1/chat/completions",
    ),
    "anthropic": ProviderPreset(
        '{"model":"{model}","max_tokens":1024,"messages":[{"role":"user","content":"{payload}"}]}',
        "content[0].text",
        60.0,
        extra_headers={"anthropic-version": "2023-06-01"},
        requires_model=True,
        description="Anthropic Messages API (POST /v1/messages)",
        url_suffix="/v1/messages",
    ),
    "groq": ProviderPreset(
        '{"model":"{model}","messages":[{"role":"user","content":"{payload}"}]}',
        "choices[0].message.content",
        30.0,
        requires_model=True,
        description="Groq Cloud OpenAI-compatible API (POST /openai/v1/chat/completions)",
        url_suffix="/openai/v1/chat/completions",
    ),
    "mistral": ProviderPreset(
        '{"model":"{model}","messages":[{"role":"user","content":"{payload}"}]}',
        "choices[0].message.content",
        30.0,
        requires_model=True,
        description="Mistral AI API (POST /v1/chat/completions)",
        url_suffix="/v1/chat/completions",
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
    "content[0].text",
    "candidates[0].content.parts[0].text",
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
    capabilities: list[str] = Field(
        default_factory=list,
        description="Declared target execution capabilities: mcp, network, file_system, shell, browser, rag, database_access, code_execution, multi_agent, memory.",
    )

    def has_capability(self, capability: str | AgentCapability) -> bool:
        """Check if target declares the requested capability."""
        cap_val = capability.value if isinstance(capability, AgentCapability) else str(capability).lower()
        if not self.capabilities:
            return False
        caps_lower = [c.lower() for c in self.capabilities]
        if "all" in caps_lower:
            return True
        return cap_val in caps_lower

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
    verdict: FindingVerdict = Field(
        default=FindingVerdict.INCONCLUSIVE,
        description="Four-state evaluation verdict: PASS, FAIL, N/A, or INCONCLUSIVE.",
    )
    passed: bool | None = Field(
        default=None,
        description="Backward-compatible boolean: True for PASS, False for FAIL, None for N/A or INCONCLUSIVE.",
    )

    @model_validator(mode="before")
    @classmethod
    def _sync_verdict_and_passed(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "verdict" in data and data["verdict"] is not None:
                v = data["verdict"]
                if isinstance(v, str):
                    v_upper = v.upper()
                    if v_upper in ("PASS", "PASSED"):
                        data["verdict"] = FindingVerdict.PASS
                        if data.get("passed") is None:
                            data["passed"] = True
                    elif v_upper in ("FAIL", "FAILED"):
                        data["verdict"] = FindingVerdict.FAIL
                        if data.get("passed") is None:
                            data["passed"] = False
                    elif v_upper in ("N/A", "NA"):
                        data["verdict"] = FindingVerdict.NA
                        data["passed"] = None
                    elif v_upper == "INCONCLUSIVE":
                        data["verdict"] = FindingVerdict.INCONCLUSIVE
                        data["passed"] = None
                elif v == FindingVerdict.PASS and data.get("passed") is None:
                    data["passed"] = True
                elif v == FindingVerdict.FAIL and data.get("passed") is None:
                    data["passed"] = False
                elif v in (FindingVerdict.NA, FindingVerdict.INCONCLUSIVE):
                    data["passed"] = None
            elif "passed" in data and data["passed"] is not None:
                if data["passed"] is True:
                    data["verdict"] = FindingVerdict.PASS
                elif data["passed"] is False:
                    data["verdict"] = FindingVerdict.FAIL
            if data.get("execution_error") is True:
                data["passed"] = None
                if "verdict" not in data or data["verdict"] == FindingVerdict.INCONCLUSIVE:
                    data["verdict"] = FindingVerdict.INCONCLUSIVE
        return data
    execution_error: bool = Field(
        default=False,
        description="Whether an execution error (timeout/network error) occurred during the attack.",
    )
    error_details: str = Field(
        default="",
        description="Detailed exception or HTTP error message if an execution error occurred.",
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
    payload_source: str = Field(
        default="static",
        description="Source of the payload: static or dynamic.",
    )
    payload_index: int = Field(
        default=0,
        description="Index of the payload within its source.",
    )


class ConfidenceInterval(BaseModel):
    """95 % bootstrap confidence interval for a binomial proportion."""

    lower: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Lower bound of the confidence interval.",
    )
    upper: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Upper bound of the confidence interval.",
    )
    confidence_level: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
        description="Confidence level (e.g. 0.95 for 95%).",
    )


class StatisticalFinding(BaseModel):
    """Extended finding with statistical data (only in --confidence mode)."""

    attack_id: str = Field(..., description="Unique attack identifier (e.g. PI-001).")
    attack_name: str = Field(..., description="Human-readable attack name.")
    sample_count: int = Field(
        ..., ge=1, description="How many times the attack was executed."
    )
    pass_count: int = Field(
        ..., ge=0, description="How many times the model defended (passed)."
    )
    fail_count: int = Field(
        ..., ge=0, description="How many times the attack bypassed the model."
    )
    pass_rate: float = Field(
        ..., ge=0.0, le=1.0, description="pass_count / sample_count."
    )
    bypass_rate: float = Field(
        ..., ge=0.0, le=1.0, description="fail_count / sample_count."
    )
    confidence_interval: ConfidenceInterval = Field(
        ..., description="Bootstrap 95% CI for the bypass rate."
    )
    is_significant: bool = Field(
        ...,
        description=(
            "True if the CI does not straddle 0.5 — i.e. the result is "
            "clearly pass or clearly fail."
        ),
    )
    severity: Severity = Field(..., description="Severity of this attack class.")
    atlas_technique: str = Field(default="", description="MITRE ATLAS technique ID.")
    nist_category: str = Field(default="", description="NIST AI RMF category.")


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
    na_count: int = Field(
        default=0,
        ge=0,
        description="Number of attacks marked N/A (not applicable to target architecture).",
    )
    inconclusive_count: int = Field(
        default=0,
        ge=0,
        description="Number of attacks marked INCONCLUSIVE (ambiguous response).",
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
    statistical_findings: list[StatisticalFinding] = Field(
        default_factory=list,
        description="Per-attack statistical findings (populated in --confidence mode only).",
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
    statistical_findings: list[StatisticalFinding] = Field(
        default_factory=list,
        description="Aggregated statistical findings (populated in --confidence mode only).",
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

    @property
    def total_attacks(self) -> int:
        """Total individual test attacks executed across all modules."""
        return sum(m.total_attacks for m in self.modules)

    @property
    def passed_count(self) -> int:
        """Number of test attacks successfully defended/refused (excluding execution errors)."""
        return sum(m.passed for m in self.modules)

    @property
    def na_count(self) -> int:
        """Total N/A (inapplicable) tests."""
        count = 0
        for m in self.modules:
            if m.findings:
                count += sum(1 for f in m.findings if getattr(f, "verdict", None) == FindingVerdict.NA)
            else:
                count += getattr(m, "na_count", 0)
        return count

    @property
    def inconclusive_count(self) -> int:
        """Total inconclusive tests."""
        count = 0
        for m in self.modules:
            if m.findings:
                count += sum(1 for f in m.findings if getattr(f, "verdict", None) == FindingVerdict.INCONCLUSIVE)
            else:
                count += getattr(m, "inconclusive_count", 0)
        return count

    @property
    def valid_attacks_count(self) -> int:
        """Total evaluated attacks with decisive PASS or FAIL (excluding N/A, INCONCLUSIVE, and execution errors)."""
        decisive = 0
        has_findings = False
        for m in self.modules:
            if m.findings:
                has_findings = True
                decisive += sum(
                    1
                    for f in m.findings
                    if getattr(f, "verdict", None) in (FindingVerdict.PASS, FindingVerdict.FAIL)
                    and not f.execution_error
                )
            else:
                decisive += m.passed + m.failed
        if not has_findings:
            return max(0, sum(m.passed + m.failed for m in self.modules))
        return decisive

    @property
    def pass_rate(self) -> float | None:
        """Percentage of applicable cleanly evaluated test attacks successfully defended.

        Returns None if no applicable tests exist (valid_attacks_count == 0).
        """
        valid = self.valid_attacks_count
        if valid == 0:
            return None
        return (self.passed_count / valid) * 100.0

    @property
    def is_incomplete(self) -> bool:
        """True if the scan had > 20% execution errors among attempted tests or was marked INCOMPLETE."""
        attempted = self.total_attacks - self.na_count
        return self.grade == Grade.INCOMPLETE or (
            attempted > 0
            and (self.failed_execution_count / attempted) > 0.20
        )

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target.name,
            "capabilities": self.target.capabilities,
            "status": "INCOMPLETE" if self.is_incomplete else self.status.value,
            "passed_tests": self.passed_count,
            "valid_tests": self.valid_attacks_count,
            "total_tests": self.total_attacks,
            "na_tests": self.na_count,
            "inconclusive_tests": self.inconclusive_count,
            "execution_errors": self.failed_execution_count,
            "pass_rate": f"{self.pass_rate:.1f}%" if self.pass_rate is not None else None,
            "failed_findings": self.total_findings,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "score": self.overall_score,
            "grade": self.grade.value,
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


# =============================================================================
# Phase 7 — crucible poison-test (v0.8.0)
# =============================================================================


class MemoryType(str, Enum):
    RAG = "rag"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    UNKNOWN = "unknown"


class PoisonStatus(str, Enum):
    PLANTED = "planted"
    VERIFIED_ACTIVE = "verified_active"
    VERIFIED_INACTIVE = "verified_inactive"
    VERIFICATION_ERROR = "verification_error"
    EXPIRED = "expired"


class PoisonPlantRecord(BaseModel):
    session_id: str = Field(description="Unique session ID (UUID4 or user-provided).")
    memory_type: MemoryType = Field(description="The memory subsystem target type.")
    topic: str = Field(description="The target topic/subject of the poisoning.")
    technique: int = Field(description="The generation technique used (1 to 4).")
    trigger: str = Field(
        description="The prompt trigger phrase used to activate the poison."
    )
    activation_signal: str = Field(
        description="The unique 8-character confirmation code."
    )
    document_text: str = Field(
        description="The full generated document content with embedded code."
    )
    planted_at: str = Field(
        description="ISO timestamp of when the session was created."
    )
    status: PoisonStatus = Field(
        default=PoisonStatus.PLANTED, description="Current evaluation status."
    )
    verified_at: str | None = Field(
        default=None, description="ISO timestamp of the last verification attempt."
    )
    activation_response: str | None = Field(
        default=None, description="The raw agent output that verified activation."
    )
    target_url: str = Field(description="Target URL of the agent/RAG system.")


class PoisonTestResult(BaseModel):
    session_id: str = Field(description="The session ID associated with this check.")
    status: PoisonStatus = Field(description="The verified status of the poison test.")
    verified_at: str = Field(description="ISO timestamp of the validation run.")
    activation_signal: str = Field(description="The targeted confirmation token.")
    trigger: str = Field(description="The trigger query sent to the agent.")
    response_snippet: str = Field(description="Snippet of the agent response.")
    is_active: bool = Field(
        description="True if the activation signal was found in the response."
    )
    error_message: str | None = Field(
        default=None, description="Detailed error description if verification failed."
    )


# ---------------------------------------------------------------------------
# Phase 9 — Identity & Privilege Layer (ASI03)
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """Named, scoped AI agent identity for policy enforcement.

    Define agents in the policy YAML v2 ``agents:`` section.  At runtime the
    proxy reads the ``X-Crucible-Agent-Id`` header (or ``agent_id`` JSON body
    field) and matches it to a definition here.
    """

    agent_id: str = Field(description="Unique identifier for this agent.")
    description: str = Field(default="", description="Human-readable description.")
    allowed_tools: list[str] = Field(
        default_factory=list,
        description="Explicit tool allowlist.  Empty list = all tools permitted.",
    )
    denied_tools: list[str] = Field(
        default_factory=list,
        description="Explicit tool denylist.  Overrides allowed_tools.",
    )
    max_calls_per_session: int | None = Field(
        default=None,
        description="Maximum number of tool calls per session marker.",
    )
    max_calls_per_hour: int | None = Field(
        default=None,
        description="Maximum number of tool calls in any rolling 60-minute window.",
    )
    max_unique_tools_per_session: int | None = Field(
        default=None,
        description="Maximum distinct tool names allowed in a single session.",
    )
    allowed_hours_utc: str | None = Field(
        default=None,
        description='UTC hour window, e.g. "09:00-18:00".  None = unrestricted.',
    )


class IdentityCallRecord(BaseModel):
    """Single tool call made by a named agent — stored in the behavioral log.

    One record is appended to ``~/.crucible/identity-logs/{agent_id}.jsonl``
    for every intercepted tool call, regardless of the policy decision.
    """

    timestamp: str = Field(description="ISO-8601 UTC timestamp of the call.")
    agent_id: str = Field(description="Agent that made this call.")
    tool_name: str = Field(description="Tool name from the tools/call request.")
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Tool arguments dict, or None if not a tool call.",
    )
    policy_action: PolicyAction = Field(description="Policy decision applied.")
    request_id: str = Field(description="UUID4 matching the proxy audit log entry.")
    session_marker: str | None = Field(
        default=None,
        description="Opaque session identifier supplied by the client.",
    )


class IdentityViolation(BaseModel):
    """A single detected identity/privilege violation."""

    violation_type: str = Field(
        description=(
            "One of: tool_outside_allowlist | denied_tool | rate_limit_session |"
            " rate_limit_hour | unique_tool_limit | hour_violation"
        )
    )
    severity: Severity = Field(description="Severity of this violation.")
    agent_id: str = Field(description="Agent that triggered the violation.")
    tool_name: str | None = Field(
        default=None,
        description="Tool involved in the violation, if applicable.",
    )
    description: str = Field(description="Human-readable violation description.")
    detected_at: str = Field(description="ISO-8601 UTC timestamp of detection.")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting data (counts, limits, timestamps, etc.).",
    )


class IdentityBehaviorSummary(BaseModel):
    """Aggregate behavior summary produced by ``crucible identity audit``."""

    agent_id: str = Field(description="Agent whose behavior is summarised.")
    window_start: str = Field(description="ISO-8601 UTC start of the analysis window.")
    window_end: str = Field(description="ISO-8601 UTC end of the analysis window.")
    total_calls: int = Field(description="Total tool calls recorded in the window.")
    unique_tools_used: list[str] = Field(description="Distinct tool names observed.")
    tools_outside_allowlist: list[str] = Field(
        description="Tools called that are not in the agent's allowed_tools.",
    )
    calls_per_tool: dict[str, int] = Field(
        description="Call count broken down by tool name.",
    )
    calls_denied: int = Field(description="Calls that resulted in a DENY action.")
    calls_alerted: int = Field(description="Calls that triggered an ALERT action.")
    risk_score: float = Field(
        description="Aggregate risk score 0.0 (clean) → 1.0 (high anomaly).",
    )
    violations: list[IdentityViolation] = Field(
        default_factory=list,
        description="All violations detected in this window.",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="Human-readable summary strings for each finding.",
    )


# Import guard — PolicyAction is defined in crucible.trace.models, not here.
# We reference it in IdentityCallRecord via a forward-ref string so that
# crucible.models stays importable without importing the trace sub-package.
# The actual enum is resolved at runtime via model_rebuild().


class FuzzArmResult(BaseModel):
    """Result of fuzzing a single strategy/arm."""

    strategy_name: str = Field(description="Name of the attack strategy.")
    visit_count: int = Field(description="Number of times this arm was pulled.")
    q_value: float = Field(description="Current estimated reward (Q-value).")
    reward_history: list[float] = Field(description="Rewards obtained in each visit.")
    bypasses_found: int = Field(description="Number of bypasses found by this arm.")


class FuzzSessionResult(BaseModel):
    """Result of a complete fuzzer execution session."""

    target: str = Field(description="Target endpoint URL.")
    total_iterations: int = Field(description="Total rounds/pulls executed.")
    early_stopped: bool = Field(
        description="Whether fuzzing stopped before max_iterations."
    )
    stop_reason: str = Field(
        description="The reason for stopping (e.g. threshold met, convergence)."
    )
    best_strategy: str = Field(
        description="The strategy with the highest estimated reward."
    )
    fitness_threshold: float = Field(
        description="The early stopping fitness threshold."
    )
    logprob_mode: bool = Field(description="Whether logprob entropy mode was active.")
    arm_results: list[FuzzArmResult] = Field(description="Details for each fuzzer arm.")
    elapsed_seconds: float = Field(
        description="Time elapsed during the fuzzing session."
    )
    round_log: list[dict[str, Any]] = Field(
        description="Chronological log of all rounds."
    )


class STIXIndicator(BaseModel):
    """Pydantic model representing a STIX 2.1 Indicator."""

    type: str = Field(default="indicator")
    spec_version: str = Field(default="2.1")
    id: str = Field(description="Unique STIX indicator ID.")
    created: str = Field(description="Creation timestamp.")
    modified: str = Field(description="Modification timestamp.")
    name: str = Field(description="Name of the indicator.")
    description: str = Field(description="Description of the indicator.")
    indicator_types: list[str] = Field(
        default_factory=lambda: ["compromise", "malicious-activity"]
    )
    pattern: str = Field(description="STIX pattern mapping the file hash.")
    pattern_type: str = Field(default="stix")
    pattern_version: str = Field(default="2.1")
    valid_from: str = Field(description="Validity start timestamp.")
    confidence: int | None = Field(
        default=None, description="Confidence of the indicator."
    )
    external_references: list[dict[str, Any]] = Field(default_factory=list)


class STIXBundle(BaseModel):
    """Pydantic model representing a STIX 2.1 Bundle."""

    type: str = Field(default="bundle")
    id: str = Field(description="Unique STIX bundle ID.")
    objects: list[STIXIndicator] = Field(description="List of STIX objects.")
