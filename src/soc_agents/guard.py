"""Per-agent runtime guard, wired in as ADK callbacks.

* ``before_tool``  - allowlist (defense in depth behind ``tool_filter``), per-call tool budget, audit.
* ``after_tool``   - lifts ``security.injection_suspected`` from the mcp-wazuh envelope into session state, in code.
* ``after_model``  - token budget, and output coercion: the final JSON is validated against the agent's contract and
                     ``injection_suspected`` is OR-ed with the state flag so the model cannot clear it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import BaseModel, ValidationError

from soc_agents.audit import Audit
from soc_agents.config import Limits
from soc_agents.contracts import EnrichmentResult, InvestigationResult, TriageResult
from soc_agents.policy import is_allowed

OUTPUT_CONTRACTS: dict[str, type[BaseModel]] = {
    "triage": TriageResult,
    "enrichment": EnrichmentResult,
    "investigator": InvestigationResult,
}
MAX_REPORT_CHARS = 8000
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)
ERROR_PREFIX = "CONTRACT_VIOLATION:"
# Marks a response produced by before_tool. ADK still runs after_tool callbacks on it (the tool itself does not run),
# so after_tool must not audit it as a successful call.
DENIED = "_guard_denied"


def extract_security(tool_response: Any) -> dict[str, Any]:
    """Find the mcp-wazuh ``security`` block in an ADK/MCP tool response, whatever its wrapping."""
    candidates: list[Any] = []
    if isinstance(tool_response, dict):
        candidates.append(tool_response)
        if isinstance(tool_response.get("structuredContent"), dict):
            candidates.append(tool_response["structuredContent"])
        for part in tool_response.get("content") or []:
            text = part.get("text") if isinstance(part, dict) else None
            if isinstance(text, str):
                try:
                    candidates.append(json.loads(text))
                except ValueError:
                    continue
    for c in candidates:
        sec = c.get("security") if isinstance(c, dict) else None
        if isinstance(sec, dict):
            return sec
    return {}


def _text_of(response: LlmResponse) -> tuple[str | None, bool]:
    parts = (response.content.parts if response.content else None) or []
    if any(p.function_call for p in parts):
        return None, True
    text = "".join(p.text or "" for p in parts if not getattr(p, "thought", False))
    return (text or None), False


# Free-text fields never drive control flow, so an over-long one is clipped instead of failing the investigation
# (real models are verbose). Control fields are never clipped: a bad id or enum still fails closed.
TEXT_LIMITS = {
    "hypothesis_text": 500,
    "assessment_text": 500,
    "rule_description_text": 200,
    "package_text": 200,
    "summary_text": 200,
}


def _clip_text(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (v[: TEXT_LIMITS[k] - 1] + "…" if len(v) > TEXT_LIMITS[k] else v)
            if k in TEXT_LIMITS and isinstance(v, str)
            else _clip_text(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_clip_text(v) for v in value]
    return value


def coerce_output(role: str, text: str, injection: bool, reasons: list[str]) -> str:
    """Validate ``text`` against the role's contract, forcing the injection flag. Raises ContractViolation-ish."""
    model = OUTPUT_CONTRACTS[role]
    data = json.loads(_FENCE.sub("", text.strip()))
    if not isinstance(data, dict):
        raise ValueError("output is not a JSON object")
    data = _clip_text(data)
    data["injection_suspected"] = bool(data.get("injection_suspected")) or injection
    if role == "triage":
        merged = list(dict.fromkeys([*(data.get("injection_reasons") or []), *reasons]))[:10]
        data["injection_reasons"] = merged
    return model.model_validate(data).model_dump_json()


class Guard:
    def __init__(self, role: str, audit: Audit, limits: Limits) -> None:
        self.role = role
        self.audit = audit
        self.limits = limits

    # state helpers -----------------------------------------------------------------------------------------
    @staticmethod
    def _cid(state: Any) -> str:
        return str(state.get("correlation_id", "unknown"))

    def before_agent(self, callback_context: Any) -> None:
        # The correlation id is a control field of every request; take it from the validated JSON only.
        try:
            parts = callback_context.user_content.parts or []
            data = json.loads("".join(p.text or "" for p in parts))
            cid = data.get("correlation_id")
            if isinstance(cid, str) and re.fullmatch(r"[0-9a-f-]{36}", cid):
                callback_context.state["correlation_id"] = cid
        except (ValueError, AttributeError, TypeError):
            pass
        self.audit.write(kind="agent", role=self.role, event="start", correlation_id=self._cid(callback_context.state))
        return None

    def before_tool(self, tool: Any, args: dict[str, Any], tool_context: Any) -> dict[str, Any] | None:
        state, name = tool_context.state, tool.name
        if not is_allowed(self.role, name):
            self.audit.write(
                kind="tool",
                role=self.role,
                name=name,
                outcome="denied",
                reason="not_in_allowlist",
                correlation_id=self._cid(state),
            )
            return {"error": "tool_not_allowed", "tool": name, DENIED: True}
        calls = int(state.get("tool_calls", 0)) + 1
        if calls > self.limits.max_tool_calls:
            self.audit.write(
                kind="tool",
                role=self.role,
                name=name,
                outcome="denied",
                reason="tool_budget",
                correlation_id=self._cid(state),
            )
            return {"error": "tool_budget_exceeded", DENIED: True}
        state["tool_calls"] = calls
        self.audit.write(
            kind="tool", role=self.role, name=name, params=args, outcome="call", correlation_id=self._cid(state)
        )
        return None

    def after_tool(self, tool: Any, args: dict[str, Any], tool_context: Any, tool_response: Any) -> None:
        state = tool_context.state
        if isinstance(tool_response, dict) and tool_response.get(DENIED):
            return None
        sec = extract_security(tool_response)
        suspected = bool(sec.get("injection_suspected"))
        if suspected:
            state["injection_suspected"] = True
            known = list(state.get("injection_reasons", []))
            state["injection_reasons"] = list(dict.fromkeys([*known, *map(str, sec.get("reasons", []))]))[:10]
        self.audit.write(
            kind="tool",
            role=self.role,
            name=tool.name,
            outcome="ok",
            injection_suspected=suspected,
            correlation_id=self._cid(state),
        )
        return None

    def after_model(self, callback_context: Any, llm_response: LlmResponse) -> LlmResponse | None:
        state = callback_context.state
        usage = getattr(llm_response, "usage_metadata", None)
        used = int(state.get("tokens", 0)) + int(getattr(usage, "total_token_count", 0) or 0)
        state["tokens"] = used
        if used > self.limits.per_agent_tokens:
            self.audit.write(
                kind="agent", role=self.role, event="token_budget", tokens=used, correlation_id=self._cid(state)
            )
            return _reply(f"{ERROR_PREFIX} token budget exceeded")
        text, has_call = _text_of(llm_response)
        if has_call or text is None:
            return None
        if self.role == "reporter":
            if len(text) > MAX_REPORT_CHARS:
                return _reply(f"{ERROR_PREFIX} report too long")
            return None
        try:
            clean = coerce_output(
                self.role, text, bool(state.get("injection_suspected")), list(state.get("injection_reasons", []))
            )
        except (ValueError, ValidationError) as exc:
            self.audit.write(
                kind="agent",
                role=self.role,
                event="contract_violation",
                detail=type(exc).__name__,
                # field locations and error types only: values may carry attacker text
                fields=[f"{'.'.join(map(str, e['loc']))}:{e['type']}" for e in exc.errors()][:10]
                if isinstance(exc, ValidationError)
                else [],
                correlation_id=self._cid(state),
            )
            return _reply(f"{ERROR_PREFIX} {type(exc).__name__}")
        self.audit.write(
            kind="agent",
            role=self.role,
            event="done",
            injection_suspected=bool(state.get("injection_suspected")),
            correlation_id=self._cid(state),
        )
        return _reply(clean)

    def callbacks(self) -> dict[str, Any]:
        return {
            "before_agent_callback": self.before_agent,
            "before_tool_callback": self.before_tool,
            "after_tool_callback": self.after_tool,
            "after_model_callback": self.after_model,
        }


def _reply(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))
