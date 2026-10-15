from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from soc_agents.config import Limits, Settings

HERE = Path(__file__).resolve().parent
MCP_DIR = Path(os.environ.get("MCP_WAZUH_DIR", HERE.parent.parent / "mcp-wazuh")).resolve()
MCP_DIST = MCP_DIR / "dist" / "index.js"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def mock_wazuh() -> Iterator[dict[str, str]]:
    if not MCP_DIST.exists() or not (MCP_DIR / "scripts" / "mock-wazuh.mjs").exists():
        pytest.skip(f"mcp-wazuh not built at {MCP_DIR} (set MCP_WAZUH_DIR; run npm ci && npm run build)")
    api, idx = _free_port(), _free_port()
    proc = subprocess.Popen(  # noqa: S603
        ["node", "scripts/mock-wazuh.mjs"],  # noqa: S607
        cwd=MCP_DIR,
        env={**os.environ, "MOCK_API_PORT": str(api), "MOCK_INDEXER_PORT": str(idx)},
        stdout=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", idx), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield {
        "WAZUH_API_URL": f"http://127.0.0.1:{api}",
        "WAZUH_API_USER": "mcp-reader",
        "WAZUH_API_PASSWORD": "mcp-reader-pass",
        "WAZUH_INDEXER_URL": f"http://127.0.0.1:{idx}",
        "WAZUH_INDEXER_USER": "mcp-reader",
        "WAZUH_INDEXER_PASSWORD": "mcp-reader-pass",
    }
    proc.terminate()


@pytest.fixture()
def settings(mock_wazuh: dict[str, str], tmp_path: Path) -> Settings:
    return Settings(
        mcp_path=str(MCP_DIST),
        wazuh_env=mock_wazuh,
        limits=Limits(max_steps=6, timeout_s=60, max_llm_calls=8, max_tool_calls=6, token_budget=60000),
        audit_path=str(tmp_path / "audit.jsonl"),
        incidents_dir=str(tmp_path / "incidents"),
    )


def pytest_configure() -> None:
    sys.dont_write_bytecode = True
