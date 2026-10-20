"""The pipeline against a running mcp-wazuh over Streamable HTTP (the VPS deployment shape)."""

from __future__ import annotations

import dataclasses
import json
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from typing import Any

import pytest

from soc_agents.agents import build_agent
from soc_agents.audit import Audit
from soc_agents.config import Settings
from soc_agents.orchestrator import Orchestrator
from tests import fakes
from tests.adversarial.test_injection_pipeline import _alert_ids
from tests.conftest import MCP_DIR, MCP_DIST

TOKEN = "t" * 48


@pytest.fixture(scope="module")
def mcp_http(mock_wazuh: dict[str, str]) -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {
        **os.environ,
        **mock_wazuh,
        "MCP_TRANSPORT": "http",
        "MCP_HTTP_PORT": str(port),
        "MCP_AUTH_TOKENS": TOKEN,
        "LOG_LEVEL": "warn",
        "AUDIT_LOG_PATH": os.devnull,
    }
    proc = subprocess.Popen(["node", str(MCP_DIST)], cwd=MCP_DIR, env=env)  # noqa: S603, S607
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/mcp"
    proc.terminate()


def _agents(s: Settings, audit: Audit, triage: Any) -> dict[str, Any]:
    return {
        "triage": build_agent("triage", s, audit, model=triage),
        "enrichment": build_agent("enrichment", s, audit, model=fakes.enrichment_fake()),
        "investigator": build_agent("investigator", s, audit, model=fakes.investigator_fake()),
        "reporter": build_agent("reporter", s, audit, model=fakes.reporter_fake()),
    }


async def test_pipeline_over_mcp_http(settings: Settings, mcp_http: str) -> None:
    s = dataclasses.replace(settings, mcp_url=mcp_http, mcp_token=TOKEN, mcp_path="/nonexistent")
    audit = Audit(s.audit_path)
    alert_id = (await _alert_ids(settings))["550"]
    inc = await Orchestrator(_agents(s, audit, fakes.persuaded_triage()), s.limits, audit).investigate(
        alert_id=alert_id
    )
    assert inc.status == "completed", inc.error
    assert inc.injection_suspected is True  # the security block arrives over HTTP exactly as over stdio
    with open(s.audit_path) as fh:
        rows = [json.loads(line) for line in fh]
    # allowlist still enforced over HTTP: the persuaded triage's out-of-role call is denied
    assert any(
        r.get("role") == "triage" and r.get("name") == "get_agent" and r.get("outcome") == "denied" for r in rows
    )


async def test_http_mode_requires_a_token(settings: Settings, mcp_http: str) -> None:
    s = dataclasses.replace(settings, mcp_url=mcp_http, mcp_token="")
    with pytest.raises(ValueError, match="MCP_WAZUH_TOKEN"):
        build_agent("triage", s, Audit(None), model=fakes.triage_fake())


async def test_wrong_token_fails_closed(settings: Settings, mcp_http: str) -> None:
    s = dataclasses.replace(settings, mcp_url=mcp_http, mcp_token="x" * 48)
    audit = Audit(s.audit_path)
    inc = await Orchestrator(_agents(s, audit, fakes.triage_fake()), s.limits, audit).investigate(
        alert_id="1792083033.1009"
    )
    assert inc.status == "failed"
