"""Append-only JSONL audit trail. Never records secrets or log content, only ids, sizes and outcomes."""

from __future__ import annotations

import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SECRET_KEY = re.compile(r"pass|secret|token|key|authorization|credential", re.I)
_MAX_VALUE = 200


def redact(value: Any) -> Any:
    """Redact secret-looking keys and truncate long strings, recursively."""
    if isinstance(value, dict):
        return {k: "[redacted]" if _SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value[:50]]
    if isinstance(value, str) and len(value) > _MAX_VALUE:
        return value[:_MAX_VALUE] + f"...[{len(value)} chars]"
    return value


class Audit:
    def __init__(self, path: str | None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **fields: Any) -> dict[str, Any]:
        record = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), **redact(fields)}
        if self._path:
            with self._lock, self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
