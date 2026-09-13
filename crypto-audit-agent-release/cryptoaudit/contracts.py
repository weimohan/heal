"""Stable data contracts shared by the baseline, Agent, UI, and reports."""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_REVIEW = "completed_with_review"
    AWAITING_USER = "awaiting_user"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    DEGRADED = "degraded"
    FAILED = "failed"


class EvidenceState(BaseModel):
    """Facts the deterministic completion gate expects to see."""

    source_fingerprint: bool = False
    inventory_complete: bool = False
    local_scan_complete: bool = False
    claim_links_complete: bool = False
    verification_complete: bool = False
    patch_integrity_complete: bool = False
    human_review_complete: bool = True


class AlgorithmUse(BaseModel):
    name: str = Field(min_length=1)
    category: str = Field(min_length=1)
    status: Literal["recommended", "review", "deprecated"]
    line: int = Field(ge=1)
    evidence: str = Field(min_length=1)
    security_note: str = Field(min_length=1)
    evidence_type: Literal["source", "ast"] = "source"


class LocalFinding(BaseModel):
    """A finding supported by deterministic source evidence."""

    finding_id: str = Field(pattern=r"^[A-Z0-9-]+:[0-9]+$")
    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    evidence: str = Field(min_length=1)
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    remediation: str = Field(min_length=1)
    status: Literal["confirmed"] = "confirmed"
    origin: Literal["policy", "ast", "verifier"]
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_type: Literal["source", "ast"] = "source"

    @model_validator(mode="after")
    def validate_span(self) -> "LocalFinding":
        if self.end_line < self.line:
            raise ValueError("end_line must not precede line")
        return self


class ModelHypothesis(BaseModel):
    """A model-originated claim kept separate until independently supported."""

    hypothesis_id: str = Field(pattern=r"^H-[0-9]+$")
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    related_lines: list[int] = Field(default_factory=list)
    requested_evidence: list[str] = Field(default_factory=list)
    status: Literal["likely", "unknown"]
    evidence_ids: list[str] = Field(default_factory=list)


class KnowledgeCitation(BaseModel):
    knowledge_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    excerpt: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    version: str = Field(min_length=1)
    score: float = Field(ge=0.0)


class PatchProposal(BaseModel):
    status: Literal["proposed", "not_applicable", "requires_review"]
    diff: str = ""
    patched_code: str = ""
    rationale: str = Field(min_length=1)
    requires_human_review: bool = False
    target_finding_ids: list[str] = Field(default_factory=list)
    source_sha256: str = ""


class VerificationResult(BaseModel):
    patch_applied: bool
    resolved_finding_ids: list[str] = Field(default_factory=list)
    remaining_findings: list[LocalFinding] = Field(default_factory=list)
    conclusion: str = Field(min_length=1)
    source_sha256_before: str = ""
    source_sha256_after: str = ""
    rescan_completed: bool = False
    evidence_ids: list[str] = Field(default_factory=list)


class TraceEvent(BaseModel):
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    duration_ms: float = Field(ge=0.0)


class Observation(BaseModel):
    observation_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    success: bool
    payload: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    duration_ms: float = Field(ge=0.0)
    error: str = ""


class AgentAction(BaseModel):
    """The only three decisions the provider may return."""

    action: Literal["call_tool", "ask_user", "finish"]
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    question: str = ""
    question_kind: Literal["clarification", "approval"] = "clarification"
    hypotheses: list[ModelHypothesis] = Field(default_factory=list)
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_action_payload(self) -> "AgentAction":
        if self.action == "call_tool" and not self.tool_name:
            raise ValueError("call_tool requires tool_name")
        if self.action == "ask_user" and not self.question:
            raise ValueError("ask_user requires question")
        return self


class AuditSession(BaseModel):
    """In-memory task state; `source` is deliberately excluded from dumps."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    goal: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: str = Field(default="", exclude=True)
    source_for_model: str = Field(default="", exclude=True)
    last_user_answer: str = Field(default="", exclude=True)
    mode: Literal["baseline", "agent", "compare"] = "agent"
    decision_source: str = "unknown"
    algorithms: list[AlgorithmUse] = Field(default_factory=list)
    local_findings: list[LocalFinding] = Field(default_factory=list)
    model_hypotheses: list[ModelHypothesis] = Field(default_factory=list)
    citations: list[KnowledgeCitation] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    evidence: EvidenceState = Field(default_factory=EvidenceState)
    patch: PatchProposal | None = None
    verification: VerificationResult | None = None
    pending_question: str = ""
    pending_question_kind: Literal["clarification", "approval", ""] = ""
    human_decision: Literal["", "approved", "rejected"] = ""
    phase: str = "created"
    status: SessionStatus = SessionStatus.RUNNING
    completion_reason: str = ""
    step_count: int = 0

    @classmethod
    def from_source(
        cls,
        source: str,
        source_name: str = "inline.py",
        goal: str = "审计密码代码并生成可验证整改建议",
        mode: Literal["baseline", "agent", "compare"] = "agent",
        task_id: str | None = None,
    ) -> "AuditSession":
        digest = source_sha256(source)
        return cls(
            task_id=task_id or f"audit-{digest[:12]}",
            goal=goal,
            source_name=source_name,
            source_sha256=digest,
            source=source,
            source_for_model=source,
            mode=mode,
        )

    def checkpoint_dict(self) -> dict[str, Any]:
        """Return only fields safe to persist."""
        return self.model_dump(
            exclude={"source", "source_for_model"},
            mode="json",
        )


def source_sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class AgentError(RuntimeError):
    """Base error for bounded Agent execution."""


class ProviderError(AgentError):
    """The model provider failed or returned an unusable decision."""


class SourceIntegrityError(AgentError):
    """The source changed after a proposal or checkpoint was created."""
