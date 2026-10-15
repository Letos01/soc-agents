"""The same pipeline over real A2A: four agent servers on their own ports, orchestrated via RemoteA2aAgent."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import httpx
import uvicorn
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

from soc_agents.agents import build_agent
from soc_agents.audit import Audit
from soc_agents.orchestrator import Orchestrator
from tests import fakes
from tests.adversarial.test_injection_pipeline import _alert_ids


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_pipeline_over_a2a(settings: Any) -> None:
    audit = Audit(settings.audit_path)
    models = {
        "triage": fakes.triage_fake(),
        "enrichment": fakes.enrichment_fake(),
        "investigator": fakes.investigator_fake(),
        "reporter": fakes.reporter_fake(),
    }
    servers, remotes, cards = [], {}, {}
    for role, model in models.items():
        port = _port()
        app = to_a2a(build_agent(role, settings, audit, model=model), host="127.0.0.1", port=port)
        srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
        servers.append((srv, asyncio.create_task(srv.serve())))
        cards[role] = f"http://127.0.0.1:{port}/.well-known/agent-card.json"
        remotes[role] = RemoteA2aAgent(name=role, agent_card=cards[role])
    try:
        for srv, _ in servers:
            while not srv.started:
                await asyncio.sleep(0.05)
        async with httpx.AsyncClient() as c:
            card = (await c.get(cards["triage"])).json()
        assert card["name"] == "triage"

        alert_id = (await _alert_ids(settings))["550"]
        inc = await Orchestrator(remotes, settings.limits, audit, settings.incidents_dir).investigate(alert_id=alert_id)
        assert inc.status == "completed", inc.error
        assert inc.injection_suspected is True  # forced server-side by the triage guard, carried over A2A
        assert "REVISÃO HUMANA OBRIGATÓRIA" in inc.report_markdown
    finally:
        for srv, task in servers:
            srv.should_exit = True
            await task
