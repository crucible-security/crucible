
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional, Union

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
        return self.body_template.replace("{payload}", payload)

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
    completed_at: Optional[datetime] = Field(
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

