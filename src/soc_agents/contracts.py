"""Typed contracts between agents.

Rules: ``extra="forbid"``; control fields are enums, bounded numbers or regex-checked ids; free text coming from
logs only lives in ``*_text`` fields with a hard length cap and is never used to decide control flow.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ALERT_ID_RE = r"^\d{9,11}\.\d{1,15}$"
AGENT_ID_RE = r"^\d{3,6}$"
NAME_RE = r"^[A-Za-z0-9._-]{1,64}$"
ISO_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:?\d{2})$"
UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
CVE_RE = r"^CVE-\d{4}-\d{4,7}$"
TECH_RE = r"^T\d{4}(\.\d{3})?$"

AlertId = Annotated[str, StringConstraints(pattern=ALERT_ID_RE)]
AgentId = Annotated[str, StringConstraints(pattern=AGENT_ID_RE)]
Name = Annotated[str, StringConstraints(pattern=NAME_RE)]
Iso = Annotated[str, StringConstraints(pattern=ISO_RE)]
CorrelationId = Annotated[str, StringConstraints(pattern=UUID_RE)]
Technique = Annotated[str, StringConstraints(pattern=TECH_RE)]
Cve = Annotated[str, StringConstraints(pattern=CVE_RE)]
Text = Annotated[str, StringConstraints(max_length=500)]
ShortText = Annotated[str, StringConstraints(max_length=200)]
Severity = Literal["low", "medium", "high", "critical"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ContractViolation(Exception):
    """An agent produced output that does not match its schema."""


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(re.sub(r"Z$", "+00:00", value))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---- triage --------------------------------------------------------------------------------------------------


class TriageRequest(Contract):
    correlation_id: CorrelationId
    alert_id: AlertId | None = None
    time_from: Iso | None = None

    @model_validator(mode="after")
    def _one_of(self) -> TriageRequest:
        if bool(self.alert_id) == bool(self.time_from):
            raise ValueError("exactly one of alert_id or time_from is required")
        return self


class TriageResult(Contract):
    alert_id: AlertId
    alert_time: Iso
    agent_id: AgentId
    agent_name: Name
    rule_id: Annotated[int, Field(ge=1, le=999_999)]
    rule_level: Annotated[int, Field(ge=0, le=15)]
    severity: Severity
    hypothesis_text: Text
    mitre_techniques: Annotated[list[Technique], Field(max_length=10)] = []
    confidence: Annotated[float, Field(ge=0, le=1)]
    injection_suspected: bool = False
    injection_reasons: Annotated[
        list[Annotated[str, StringConstraints(pattern=r"^[a-z0-9_:]{1,64}$")]], Field(max_length=10)
    ] = []


# ---- enrichment ----------------------------------------------------------------------------------------------


class EnrichmentRequest(Contract):
    correlation_id: CorrelationId
    agent_id: AgentId
    rule_id: Annotated[int, Field(ge=1, le=999_999)]


class Vulnerability(Contract):
    cve: Cve
    severity: Literal["Critical", "High", "Medium", "Low"]
    package_text: ShortText = ""


class EnrichmentResult(Contract):
    agent_id: AgentId
    agent_name: Name | None = None  # None when the agent is no longer registered (alerts outlive agents)
    agent_status: Literal["active", "disconnected", "never_connected", "pending", "unknown"]
    os_platform: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{0,32}$")] = ""
    rule_description_text: ShortText = ""
    rule_groups: Annotated[list[Name], Field(max_length=20)] = []
    vulnerabilities: Annotated[list[Vulnerability], Field(max_length=20)] = []
    injection_suspected: bool = False


# ---- investigator --------------------------------------------------------------------------------------------


class InvestigationRequest(Contract):
    correlation_id: CorrelationId
    agent_id: AgentId
    alert_id: AlertId
    time_from: Iso
    time_to: Iso
    mitre_techniques: Annotated[list[Technique], Field(max_length=10)] = []


class TimelineEntry(Contract):
    alert_id: AlertId
    timestamp: Iso
    rule_id: Annotated[int, Field(ge=1, le=999_999)]
    rule_level: Annotated[int, Field(ge=0, le=15)]
    summary_text: ShortText = ""


class InvestigationResult(Contract):
    related_alert_count: Annotated[int, Field(ge=0, le=100_000)]
    timeline: Annotated[list[TimelineEntry], Field(max_length=30)] = []
    top_techniques: Annotated[list[Technique], Field(max_length=10)] = []
    assessment_text: Text = ""
    injection_suspected: bool = False


# ---- reporter / incident -------------------------------------------------------------------------------------


class ReportRequest(Contract):
    correlation_id: CorrelationId
    triage: TriageResult
    enrichment: EnrichmentResult
    investigation: InvestigationResult
    injection_suspected: bool


ActionKind = Literal[
    "review_host_isolation", "review_credential_reset", "review_vulnerability_patch", "manual_investigation"
]


class SuggestedAction(Contract):
    id: Annotated[str, StringConstraints(pattern=r"^A\d{1,2}$")]
    kind: ActionKind
    target: Name
    rationale_text: ShortText
    status: Literal["requires_human_approval"] = "requires_human_approval"


class Incident(Contract):
    incident_id: CorrelationId
    created_at: Iso
    status: Literal["completed", "failed"]
    injection_suspected: bool
    injection_stages: list[Literal["triage", "enrichment", "investigator"]] = []
    steps: int
    triage: TriageResult | None = None
    enrichment: EnrichmentResult | None = None
    investigation: InvestigationResult | None = None
    suggested_actions: list[SuggestedAction] = []
    report_markdown: str = ""
    error: str = ""
