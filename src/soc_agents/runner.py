"""Run one agent (remote A2A or local) once, in a fresh session, and return its final text."""

from __future__ import annotations

import json
from typing import Any

from google.adk.agents import BaseAgent
from google.adk.agents.run_config import RunConfig
from google.adk.runners import InMemoryRunner
from google.genai import types

from soc_agents.contracts import ContractViolation

APP = "soc-agents"


async def run_once(agent: BaseAgent, payload: dict[str, Any], *, max_llm_calls: int = 8) -> str:
    runner = InMemoryRunner(agent=agent, app_name=APP)
    session = await runner.session_service.create_session(app_name=APP, user_id="orchestrator")
    message = types.Content(role="user", parts=[types.Part(text=json.dumps(payload))])
    final = ""
    try:
        async for event in runner.run_async(
            user_id="orchestrator",
            session_id=session.id,
            new_message=message,
            run_config=RunConfig(max_llm_calls=max_llm_calls),
        ):
            if event.is_final_response() and event.content and event.content.parts:
                final = "".join(p.text or "" for p in event.content.parts if not getattr(p, "thought", False))
    finally:
        # Also on timeout/cancel: closing the runner stops the agent's MCP child process.
        await runner.close()
    if not final.strip():
        # A remote agent that fails (unreachable, refused card, crashed) can end with no content and no error
        # event; say so instead of letting it surface as a JSON parse error.
        raise ContractViolation(f"agent '{agent.name}' returned no output")
    return final
