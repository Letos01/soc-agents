"""Extension points (no implementation on purpose)."""

from __future__ import annotations

from typing import Protocol


class ThreatIntelProvider(Protocol):
    """Future ``threat-rag`` hook: enrich indicators with external/RAG intelligence.

    Not implemented. If added, it must return only validated, length-capped fields and run as its own A2A agent
    with its own allowlist, like every other agent.
    """

    async def lookup(self, indicator: str) -> dict[str, str]: ...
