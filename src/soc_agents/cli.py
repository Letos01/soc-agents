from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import warnings

# ADK marks its A2A support as experimental and warns on every use; the CLI should print the report only.
warnings.filterwarnings("ignore", category=UserWarning, module=r"(google\.adk|soc_agents)(\..*)?")

# Imports below come after the filter on purpose: ADK emits one of the warnings at import time.
from google.adk.agents import BaseAgent  # noqa: E402

from soc_agents.agents import build_agent  # noqa: E402
from soc_agents.audit import Audit  # noqa: E402
from soc_agents.config import ROLES, Settings  # noqa: E402
from soc_agents.orchestrator import PIPELINE, Orchestrator  # noqa: E402


def _remote_agents(settings: Settings) -> dict[str, BaseAgent]:
    from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

    return {
        r: RemoteA2aAgent(name=r, agent_card=f"{settings.agent_url(r)}/.well-known/agent-card.json") for r in PIPELINE
    }


def _local_agents(settings: Settings, audit: Audit) -> dict[str, BaseAgent]:
    return {r: build_agent(r, settings, audit) for r in PIPELINE}


async def _investigate(args: argparse.Namespace) -> int:
    logging.getLogger("google_adk").setLevel(logging.ERROR)  # e.g. "Ignoring a session state delta ..."
    settings = Settings.from_env()
    audit = Audit(settings.audit_path)
    agents = _local_agents(settings, audit) if args.local else _remote_agents(settings)
    orch = Orchestrator(agents, settings.limits, audit, settings.incidents_dir)
    inc = await orch.investigate(alert_id=args.alert_id, last=args.last)
    print(inc.model_dump_json(indent=2) if args.json else inc.report_markdown)
    return 0 if inc.status == "completed" else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc-agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("investigate", help="triage and investigate an alert")
    g = inv.add_mutually_exclusive_group(required=True)
    g.add_argument("--alert-id")
    g.add_argument("--last", help="e.g. 30m, 1h, 2d: investigate the highest-level recent alert")
    inv.add_argument("--local", action="store_true", help="run agents in-process instead of over A2A")
    inv.add_argument("--json", action="store_true")

    srv = sub.add_parser("serve", help="serve one agent as an A2A server")
    srv.add_argument("role", choices=ROLES)

    ap = sub.add_parser("approve", help="record a human decision (nothing is executed)")
    ap.add_argument("incident_id")
    ap.add_argument("action_id")
    ap.add_argument("--decision", choices=["approve", "reject"], required=True)
    ap.add_argument("--by", required=True)

    args = p.parse_args(argv)
    if args.cmd == "investigate":
        return asyncio.run(_investigate(args))
    if args.cmd == "serve":
        from soc_agents.server import serve

        serve(args.role, Settings.from_env())
        return 0
    from soc_agents.approvals import record_decision

    s = Settings.from_env()
    try:
        out = record_decision(
            s.incidents_dir, Audit(s.audit_path), args.incident_id, args.action_id, args.decision, args.by
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0
