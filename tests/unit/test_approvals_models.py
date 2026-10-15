import json
from pathlib import Path

import pytest

from soc_agents.approvals import record_decision
from soc_agents.audit import Audit
from soc_agents.config import Settings
from soc_agents.contracts import Incident, SuggestedAction, new_correlation_id
from soc_agents.models import resolve_model


def _incident(tmp: Path) -> str:
    cid = new_correlation_id()
    inc = Incident(
        incident_id=cid,
        created_at="2026-10-15T00:00:00Z",
        status="completed",
        injection_suspected=True,
        steps=4,
        suggested_actions=[SuggestedAction(id="A1", kind="manual_investigation", target="db-01", rationale_text="x")],
    )
    (tmp / f"{cid}.json").write_text(inc.model_dump_json())
    return cid


def test_approval_only_records(tmp_path: Path) -> None:
    cid = _incident(tmp_path)
    audit_file = tmp_path / "a.jsonl"
    out = record_decision(str(tmp_path), Audit(str(audit_file)), cid, "A1", "approve", "leo")
    assert out["executed"] == "false"
    row = json.loads(audit_file.read_text())
    assert row["kind"] == "approval" and row["executed"] is False and row["decision"] == "approve"


@pytest.mark.parametrize(
    ("iid", "aid", "dec"), [("../etc/passwd", "A1", "approve"), (None, "A9", "approve"), (None, "A1", "execute")]
)
def test_approval_rejects_bad_input(tmp_path: Path, iid: str | None, aid: str, dec: str) -> None:
    cid = _incident(tmp_path)
    with pytest.raises(ValueError):
        record_decision(str(tmp_path), Audit(None), iid or cid, aid, dec, "leo")


def test_model_resolution() -> None:
    assert resolve_model("gemini-2.5-flash") == "gemini-2.5-flash"
    pytest.importorskip("litellm")
    assert resolve_model("litellm/anthropic/claude-sonnet-4-5").model == "anthropic/claude-sonnet-4-5"


def test_settings_from_env() -> None:
    s = Settings.from_env({"MODEL": "m", "MAX_STEPS": "3", "TRIAGE_PORT": "9999", "WAZUH_API_PASSWORD": "p", "X": "y"})
    assert s.model == "m" and s.limits.max_steps == 3 and s.ports["triage"] == 9999
    assert dict(s.wazuh_env) == {"WAZUH_API_PASSWORD": "p"}
    assert s.agent_url("triage") == "http://127.0.0.1:9999"
    assert s.limits.per_agent_tokens == 15000
    s2 = Settings.from_env({"REPORTER_URL": "http://reporter:9104"})
    assert s2.agent_url("reporter") == "http://reporter:9104"
