"""Serve one agent role as an A2A server (own port, own Agent Card)."""

from __future__ import annotations

import uvicorn
from google.adk.a2a.utils.agent_to_a2a import to_a2a

from soc_agents.agents import build_agent
from soc_agents.audit import Audit
from soc_agents.config import Settings


def serve(role: str, settings: Settings) -> None:
    agent = build_agent(role, settings, Audit(settings.audit_path))
    app = to_a2a(agent, host=settings.host, port=settings.ports[role])
    uvicorn.run(app, host=settings.host, port=settings.ports[role], log_level="warning")
