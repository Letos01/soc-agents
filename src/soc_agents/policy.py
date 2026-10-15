"""Least privilege: which MCP tools each agent may call. Enforced in code, not in prompts."""

from __future__ import annotations

ALLOWLIST: dict[str, frozenset[str]] = {
    "triage": frozenset({"search_alerts", "get_alert"}),
    "enrichment": frozenset({"get_agent", "get_rule", "list_vulnerabilities"}),
    "investigator": frozenset({"search_alerts", "alert_stats"}),
    "reporter": frozenset(),
}

# Anything that could change state anywhere. None exist in mcp-wazuh today; this makes the intent explicit and
# makes a future write tool fail closed even if somebody adds it to an allowlist by mistake.
FORBIDDEN_PREFIXES = ("create_", "delete_", "update_", "set_", "restart_", "isolate_", "block_", "run_", "execute_")


def is_allowed(role: str, tool: str) -> bool:
    if tool.startswith(FORBIDDEN_PREFIXES):
        return False
    return tool in ALLOWLIST.get(role, frozenset())


def tool_filter(role: str) -> list[str]:
    return sorted(ALLOWLIST[role])
