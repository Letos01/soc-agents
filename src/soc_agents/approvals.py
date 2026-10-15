"""Simulated human approval. It only RECORDS a decision; nothing is executed anywhere."""

from __future__ import annotations

import re
from pathlib import Path

from soc_agents.audit import Audit
from soc_agents.contracts import Incident

_UUID = re.compile(r"^[0-9a-f-]{36}$")


def record_decision(
    incidents_dir: str, audit: Audit, incident_id: str, action_id: str, decision: str, by: str
) -> dict[str, str]:
    if not _UUID.match(incident_id):
        raise ValueError("invalid incident id")
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    path = Path(incidents_dir) / f"{incident_id}.json"
    incident = Incident.model_validate_json(path.read_text(encoding="utf-8"))
    action = next((a for a in incident.suggested_actions if a.id == action_id), None)
    if action is None:
        raise ValueError(f"unknown action {action_id}")
    audit.write(
        kind="approval",
        incident_id=incident_id,
        action_id=action_id,
        kind_of_action=action.kind,
        target=action.target,
        decision=decision,
        decided_by=by[:64],
        executed=False,
        correlation_id=incident_id,
    )
    return {"incident_id": incident_id, "action_id": action_id, "decision": decision, "executed": "false"}
