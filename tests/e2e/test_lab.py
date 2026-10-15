"""Against the live Wazuh lab from mcp-wazuh (./scripts/lab-up.sh).

SOC_LAB=1  real Wazuh + real mcp-wazuh + deterministic fake LLMs (no API key): proves the contracts hold on real data.
SOC_E2E=1  same, with the real model from MODEL (needs GOOGLE_API_KEY or the LiteLLM provider key).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from soc_agents.agents import build_agent
from soc_agents.audit import Audit
from soc_agents.config import Limits, Settings
from soc_agents.orchestrator import Orchestrator
from tests import fakes
from tests.conftest import MCP_DIST

LAB = os.environ.get("SOC_LAB") == "1" or os.environ.get("SOC_E2E") == "1"
pytestmark = [pytest.mark.e2e, pytest.mark.skipif(not LAB, reason="set SOC_LAB=1 or SOC_E2E=1 with the lab running")]


@pytest.fixture()
def lab(tmp_path: Path) -> Settings:
    pw = os.environ.get("LAB_READER_PASSWORD")
    if not pw:
        pytest.skip("set LAB_READER_PASSWORD (the mcp-reader password given to lab-create-readonly-users.sh)")
    env = {
        "WAZUH_API_URL": os.environ.get("WAZUH_API_URL", "https://localhost:55000"),
        "WAZUH_API_USER": "mcp-reader",
        "WAZUH_API_PASSWORD": pw,
        "WAZUH_INDEXER_URL": os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200"),
        "WAZUH_INDEXER_USER": "mcp-reader",
        "WAZUH_INDEXER_PASSWORD": pw,
        "TLS_INSECURE": "true",
    }
    return Settings(
        model=os.environ.get("MODEL", "gemini-2.5-flash"),
        mcp_path=str(MCP_DIST),
        wazuh_env=env,
        limits=Limits(timeout_s=300),
        audit_path=str(tmp_path / "audit.jsonl"),
        incidents_dir=str(tmp_path / "incidents"),
    )


async def lab_alerts(s: Settings) -> list[dict[str, Any]]:
    params = StdioServerParameters(
        command=s.node, args=[s.mcp_path], env={"PATH": os.environ["PATH"], "LOG_LEVEL": "warn", **s.wazuh_env}
    )
    async with stdio_client(params) as (r, w), ClientSession(r, w) as c:
        await c.initialize()
        res = await c.call_tool(
            "search_alerts",
            {
                "rule_level_min": 3,
                "limit": 50,
                "time_from": (datetime.now(UTC) - timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        return json.loads(res.content[0].text)["result"]["alerts"]  # type: ignore[no-any-return]


def _agents(s: Settings, audit: Audit, real: bool) -> dict[str, Any]:
    if real:
        return {r: build_agent(r, s, audit) for r in ("triage", "enrichment", "investigator", "reporter")}
    return {
        "triage": build_agent("triage", s, audit, model=fakes.triage_fake()),
        "enrichment": build_agent("enrichment", s, audit, model=fakes.enrichment_fake()),
        "investigator": build_agent("investigator", s, audit, model=fakes.investigator_fake()),
        "reporter": build_agent("reporter", s, audit, model=fakes.reporter_fake()),
    }


@pytest.mark.parametrize("rule_id", ["550", "31106", "92057", "5763"])
async def test_lab_pipeline(lab: Settings, rule_id: str) -> None:
    alerts = {a["rule"]["id"]: a["id"] for a in await lab_alerts(lab)}
    if rule_id not in alerts:
        pytest.skip(f"rule {rule_id} not seeded in the lab (npm run seed:lab in mcp-wazuh)")
    audit = Audit(lab.audit_path)
    real = os.environ.get("SOC_E2E") == "1"
    inc = await Orchestrator(_agents(lab, audit, real), lab.limits, audit, lab.incidents_dir).investigate(
        alert_id=alerts[rule_id]
    )
    out = Path(os.environ.get("SOC_E2E_OUT", lab.incidents_dir))
    out.mkdir(parents=True, exist_ok=True)
    (out / f"lab-{rule_id}{'-real' if real else ''}.md").write_text(inc.report_markdown)
    assert inc.status == "completed", inc.error
    assert inc.triage is not None
    assert inc.triage.injection_suspected is (rule_id != "5763")
    if rule_id == "5763":
        # the clean brute-force alert is correlated with the injected User-Agent alert on the same host
        assert inc.injection_stages == ["investigator"]
    assert all(a.status == "requires_human_approval" for a in inc.suggested_actions)
