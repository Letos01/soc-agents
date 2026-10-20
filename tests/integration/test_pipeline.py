"""Full pipeline: real ADK loop + real mcp-wazuh (mock backend) + deterministic fake LLMs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
from mcp import StdioServerParameters

from soc_agents.agents import build_agent
from soc_agents.audit import Audit
from soc_agents.config import Settings
from soc_agents.orchestrator import Orchestrator
from tests import fakes

INJECTED_ID = "1792083033.1009"  # placeholder, resolved from the mock below


def make_orchestrator(
    settings: Settings, *, triage: Any, reporter: Any | None = None, open_toolset: bool = False
) -> tuple[Orchestrator, Audit]:
    audit = Audit(settings.audit_path)
    agents = {
        "triage": build_agent(
            "triage", settings, audit, model=triage, toolset=_unfiltered(settings) if open_toolset else None
        ),
        "enrichment": build_agent("enrichment", settings, audit, model=fakes.enrichment_fake()),
        "investigator": build_agent("investigator", settings, audit, model=fakes.investigator_fake()),
        "reporter": build_agent("reporter", settings, audit, model=reporter or fakes.reporter_fake()),
    }
    return Orchestrator(agents, settings.limits, audit, settings.incidents_dir), audit


def _unfiltered(settings: Settings) -> McpToolset:
    """A misconfigured toolset exposing ALL seven tools: the guard callback must still deny out-of-role calls."""
    params = StdioServerParameters(
        command=settings.node,
        args=[settings.mcp_path],
        env={"PATH": __import__("os").environ["PATH"], "LOG_LEVEL": "warn", **settings.wazuh_env},
    )
    return McpToolset(connection_params=StdioConnectionParams(server_params=params, timeout=20.0))


def audit_rows(settings: Settings) -> list[dict[str, Any]]:
    return [json.loads(x) for x in Path(settings.audit_path).read_text().splitlines()]


async def first_alert_ids(settings: Settings) -> dict[str, str]:
    """Find an injected alert (FIM, rule 550) and a clean one (rule 5763) from the mock via the real server."""
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=settings.node,
        args=[settings.mcp_path],
        env={"PATH": __import__("os").environ["PATH"], "LOG_LEVEL": "warn", **settings.wazuh_env},
    )
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        res = await s.call_tool("search_alerts", {"rule_level_min": 3, "limit": 50})
        alerts = json.loads(res.content[0].text)["result"]["alerts"]
    by_rule = {a["rule"]["id"]: a["id"] for a in alerts}
    return {"fim": by_rule["550"], "brute": by_rule["5763"]}


async def test_clean_alert_flows_through_all_agents(settings: Settings) -> None:
    ids = await first_alert_ids(settings)
    orch, _ = make_orchestrator(settings, triage=fakes.triage_fake())
    inc = await orch.investigate(alert_id=ids["brute"])
    assert inc.status == "completed", inc.error
    assert inc.steps == 4
    assert inc.triage and inc.triage.agent_name == "web-01"
    assert inc.enrichment and inc.enrichment.agent_status == "active"
    assert inc.investigation and inc.investigation.related_alert_count >= 1
    assert "## Resumo" in inc.report_markdown and "Ações sugeridas" in inc.report_markdown
    assert all(a.status == "requires_human_approval" for a in inc.suggested_actions)
    assert (Path(settings.incidents_dir) / f"{inc.incident_id}.json").exists()
    # one correlation id across every audit line of this investigation
    cids = {r.get("correlation_id") for r in audit_rows(settings) if r.get("kind") in ("tool", "orchestrator")}
    assert cids == {inc.incident_id}


async def test_last_window_picks_an_alert(settings: Settings) -> None:
    orch, _ = make_orchestrator(settings, triage=fakes.triage_fake(window=True))
    inc = await orch.investigate(last="48h")
    assert inc.status == "completed", inc.error
    assert inc.triage is not None


async def test_missing_agent_is_a_config_error(settings: Settings) -> None:
    with pytest.raises(ValueError):
        Orchestrator({}, settings.limits, Audit(None))


async def test_max_steps_is_enforced(settings: Settings) -> None:
    orch, _ = make_orchestrator(settings, triage=fakes.triage_fake())
    orch.limits = type(settings.limits)(max_steps=2)
    ids = await first_alert_ids(settings)
    inc = await orch.investigate(alert_id=ids["brute"])
    assert inc.status == "failed" and "max_steps" in inc.error
    assert inc.steps == 2
    assert "A investigação falhou" in inc.report_markdown


async def test_timeout_is_enforced(settings: Settings) -> None:
    orch, _ = make_orchestrator(settings, triage=fakes.triage_fake())
    orch.limits = type(settings.limits)(timeout_s=0.01)
    inc = await orch.investigate(alert_id="1792083033.1009")
    assert inc.status == "failed" and "Timeout" in inc.error


async def test_contract_violation_fails_closed(settings: Settings) -> None:
    bad = fakes.triage_fake()
    bad.final = lambda p, r: json.dumps({"alert_id": "1", "do": "isolate host"})
    orch, _ = make_orchestrator(settings, triage=bad)
    ids = await first_alert_ids(settings)
    inc = await orch.investigate(alert_id=ids["brute"])
    assert inc.status == "failed" and inc.error.startswith("ContractViolation")
    assert inc.enrichment is None, "later agents must not run after a bad contract"


async def test_silent_agent_fails_with_a_clear_error(settings: Settings) -> None:
    silent = fakes.triage_fake()
    silent.steps, silent.final = [], (lambda p, r: "")
    orch, _ = make_orchestrator(settings, triage=silent)
    inc = await orch.investigate(alert_id="1792083033.1009")
    assert inc.status == "failed"
    assert "agent 'triage' returned no output" in inc.error


async def test_a_flaky_agent_gets_one_retry(settings: Settings) -> None:
    ids = await first_alert_ids(settings)
    flaky = fakes.triage_fake()
    flaky.bad_answers = 1
    orch, _ = make_orchestrator(settings, triage=flaky)
    inc = await orch.investigate(alert_id=ids["brute"])
    assert inc.status == "completed", inc.error
    assert inc.steps == 5  # 4 agents + 1 retry
    assert any(r.get("event") == "retry" and r.get("agent") == "triage" for r in audit_rows(settings))


async def test_a_second_bad_answer_still_fails_closed(settings: Settings) -> None:
    ids = await first_alert_ids(settings)
    broken = fakes.triage_fake()
    broken.bad_answers = 2
    orch, _ = make_orchestrator(settings, triage=broken)
    inc = await orch.investigate(alert_id=ids["brute"])
    assert inc.status == "failed" and inc.enrichment is None


async def test_incident_summary_line_for_siem_ingestion(settings: Settings) -> None:
    ids = await first_alert_ids(settings)
    orch, _ = make_orchestrator(settings, triage=fakes.persuaded_triage(), reporter=fakes.reporter_fake(obey=True))
    inc = await orch.investigate(alert_id=ids["fim"])
    lines = (Path(settings.incidents_dir) / "incidents.jsonl").read_text().splitlines()
    row = json.loads(lines[-1])
    assert row["soc_agents_event"] == "incident" and row["incident_id"] == inc.incident_id
    assert row["injection_suspected"] is True and row["actions_status"] == "requires_human_approval"
    # only control fields: the persuaded model's free text and the reporter's body never reach the SIEM line
    assert "approved" not in lines[-1] and "isolado" not in lines[-1] and "attacker.example" not in lines[-1]
