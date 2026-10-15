"""Environment-driven settings. Secrets are read here and never logged."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

ROLES = ("triage", "enrichment", "investigator", "reporter")
DEFAULT_PORTS = {"triage": 9101, "enrichment": 9102, "investigator": 9103, "reporter": 9104}
_WAZUH_KEYS = (
    "WAZUH_API_URL",
    "WAZUH_API_USER",
    "WAZUH_API_PASSWORD",
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "TLS_INSECURE",
    "TLS_CA_PATH",
)


@dataclass(frozen=True)
class Limits:
    max_steps: int = 6
    timeout_s: float = 120.0
    max_llm_calls: int = 8
    max_tool_calls: int = 6
    token_budget: int = 60000

    @property
    def per_agent_tokens(self) -> int:
        """The investigation budget is split across the four agents."""
        return max(1, self.token_budget // len(ROLES))


@dataclass(frozen=True)
class Settings:
    model: str = "gemini-2.5-flash"
    model_extra_body: str = ""  # JSON object sent with every LiteLLM request (e.g. OpenRouter router plugins)
    mcp_path: str = "../mcp-wazuh/dist/index.js"
    node: str = "node"
    wazuh_env: Mapping[str, str] = field(default_factory=dict)
    host: str = "127.0.0.1"
    public_host: str = "127.0.0.1"  # host written into each Agent Card (a service name under docker compose)
    urls: Mapping[str, str] = field(default_factory=dict)  # per-role override of where the orchestrator calls
    ports: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_PORTS))
    limits: Limits = field(default_factory=Limits)
    audit_path: str = "./audit/audit.jsonl"
    incidents_dir: str = "./incidents"

    def agent_url(self, role: str) -> str:
        return self.urls.get(role) or f"http://{self.host}:{self.ports[role]}"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        limits = Limits(
            max_steps=int(e.get("MAX_STEPS", 6)),
            timeout_s=float(e.get("INVESTIGATION_TIMEOUT_S", 120)),
            max_llm_calls=int(e.get("MAX_LLM_CALLS", 8)),
            max_tool_calls=int(e.get("MAX_TOOL_CALLS", 6)),
            token_budget=int(e.get("TOKEN_BUDGET", 60000)),
        )
        ports = {r: int(e.get(f"{r.upper()}_PORT", DEFAULT_PORTS[r])) for r in ROLES}
        return cls(
            model=e.get("MODEL", "gemini-2.5-flash"),
            model_extra_body=e.get("MODEL_EXTRA_BODY", ""),
            mcp_path=e.get("MCP_WAZUH_PATH", "../mcp-wazuh/dist/index.js"),
            node=e.get("NODE_BIN", "node"),
            wazuh_env={k: e[k] for k in _WAZUH_KEYS if k in e},
            host=e.get("AGENT_HOST", "127.0.0.1"),
            public_host=e.get("AGENT_PUBLIC_HOST", e.get("AGENT_HOST", "127.0.0.1")),
            urls={r: e[f"{r.upper()}_URL"] for r in ROLES if f"{r.upper()}_URL" in e},
            ports=ports,
            limits=limits,
            audit_path=e.get("AUDIT_LOG_PATH", "./audit/audit.jsonl"),
            incidents_dir=e.get("INCIDENTS_DIR", "./incidents"),
        )
