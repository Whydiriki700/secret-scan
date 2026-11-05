"""Secret Scan storage: append-only findings ledger.

Everything stays on the user's own machine, inside the active Hermes home:
  <HERMES_HOME>/secret-scan/findings.jsonl - one line per finding event

Only pattern names, severities, masked previews, and surface names are
stored. A full credential value is never written to disk by this plugin.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

_LOCK = threading.Lock()


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        pass
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    return Path.home() / ".hermes"


def data_dir() -> Path:
    path = hermes_home() / "secret-scan"
    path.mkdir(parents=True, exist_ok=True)
    return path


def append_finding(record: Dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _LOCK:
        with open(data_dir() / "findings.jsonl", "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def read_recent(limit: int = 100) -> List[Dict[str, Any]]:
    path = data_dir() / "findings.jsonl"
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]
