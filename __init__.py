"""Secret Scan - secrets never leave in a reply.

A Hermes plugin that scans the agent's outgoing replies and tool traffic
for credential-shaped strings, redacts them before anyone sees them, and
records every finding in a local append-only ledger.

How it works:
  1. `transform_llm_output` holds the finished reply, scans it, and in
     enforce mode replaces every credential-shaped span with a redaction
     marker plus a short note naming the pattern types found.
  2. `post_tool_call` scans tool arguments and results the same way and
     records findings (surface: tool traffic). Tool traffic is observed,
     never rewritten; the reply gate is the enforcement point.
  3. Findings store pattern name, severity, and a 4-character masked
     preview only. Full values are never stored or shown.

Modes (config: plugins.entries.secret-scan.settings.mode):
  - enforce (default): replies are redacted before delivery
  - warn: findings are recorded, replies are never changed
  - off: plugin observes nothing and changes nothing
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

try:
    from . import scanner, store
except ImportError:  # loaded as a top-level module in tests
    import scanner  # type: ignore
    import store  # type: ignore

logger = logging.getLogger(__name__)

_CTX: Any = None


def _mode() -> str:
    if _CTX is not None:
        try:
            mode = _CTX.get_config("mode", "enforce")
            if isinstance(mode, str) and mode.lower() in {"enforce", "warn", "off"}:
                return mode.lower()
        except Exception:
            pass
    return "enforce"


def _record(findings: List[Dict[str, Any]], surface: str, session_id: str) -> None:
    for finding in findings:
        try:
            store.append_finding(
                {
                    "ts": time.time(),
                    "session_id": session_id,
                    "surface": surface,
                    "pattern": finding["pattern"],
                    "severity": finding["severity"],
                    "preview": finding["preview"],
                }
            )
        except Exception:
            logger.debug("secret-scan: ledger append failed", exc_info=True)


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def on_post_tool_call(tool_name: str, args: Any = None, result: Any = None, **kwargs: Any) -> None:
    if _mode() == "off":
        return
    session_id = str(kwargs.get("session_id") or "")
    text = ""
    try:
        text = json.dumps(args, default=str) if args is not None else ""
    except Exception:
        text = str(args)
    if result is not None:
        text += "\n" + (result if isinstance(result, str) else str(result))
    try:
        findings = scanner.scan_text(text)
    except Exception:
        logger.warning("secret-scan: tool traffic scan failed", exc_info=True)
        return
    if findings:
        _record(findings, "tool:" + str(tool_name), session_id)


def on_transform_llm_output(response_text: str = "", **kwargs: Any) -> Optional[str]:
    mode = _mode()
    if mode == "off" or not response_text:
        return None
    session_id = str(kwargs.get("session_id") or "")
    try:
        findings = scanner.scan_text(response_text)
    except Exception:
        # Fail closed: a broken scanner must never silently pass a reply.
        logger.warning("secret-scan: reply scan failed", exc_info=True)
        if mode == "warn":
            return None
        return (
            response_text
            + "\n\n[secret-scan: the scan failed internally, so treat any "
            "credential-looking content in this reply as unverified.]"
        )
    if not findings:
        return None
    _record(findings, "reply", session_id)
    if mode == "warn":
        return None
    redacted = scanner.redact_text(response_text, findings)
    kinds = ", ".join(sorted({f["pattern"] for f in findings}))
    return (
        redacted
        + f"\n\n[secret-scan: {len(findings)} credential-shaped value(s) "
        f"redacted before delivery ({kinds}). Values are never stored; "
        "see the local findings ledger for masked previews.]"
    )


# ---------------------------------------------------------------------------
# Surfaces: /secretscan command, secretscan_status tool, CLI
# ---------------------------------------------------------------------------


def _format_findings(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "Secret Scan ledger is empty. No credential-shaped value has been seen yet."
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row.get("pattern", "?")] = counts.get(row.get("pattern", "?"), 0) + 1
    lines = ["Secret Scan findings (most recent last):"]
    lines.append("Counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for row in rows[-5:]:
        lines.append(
            f"- {row.get('severity')} | {row.get('pattern')} | {row.get('preview')} "
            f"| surface={row.get('surface') or '-'}"
        )
    return "\n".join(lines)


def secretscan_command(raw_args: str = "", **kwargs: Any) -> str:
    return _format_findings(store.read_recent(limit=100))


def secretscan_status_tool(params: Dict[str, Any] | None = None, **kwargs: Any) -> str:
    rows = store.read_recent(limit=100)
    return json.dumps(
        {
            "success": True,
            "findings_recent": len(rows),
            "latest": rows[-5:],
            "note": "Full history lives in <HERMES_HOME>/secret-scan/findings.jsonl",
        }
    )


def _cli_setup(subparser: Any) -> None:
    sub = subparser.add_subparsers(dest="secretscan_action")
    sub.add_parser("findings", help="Show recent Secret Scan findings")


def _cli_handler(args: Any) -> int:
    print(_format_findings(store.read_recent(limit=100)))
    return 0


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(ctx: Any) -> None:
    global _CTX
    _CTX = ctx

    ctx.register_hook("post_tool_call", on_post_tool_call)
    try:
        ctx.register_hook("transform_llm_output", on_transform_llm_output, hold_stream=True)
    except TypeError:
        ctx.register_hook("transform_llm_output", on_transform_llm_output)

    ctx.register_command(
        "secretscan",
        secretscan_command,
        description="Show recent Secret Scan findings (masked previews only)",
    )
    ctx.register_tool(
        name="secretscan_status",
        toolset="secret-scan",
        schema={
            "name": "secretscan_status",
            "description": (
                "Return Secret Scan's recent findings: credential patterns seen "
                "in replies or tool traffic, with masked previews only."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
        handler=secretscan_status_tool,
    )
    ctx.register_cli_command(
        "secretscan",
        "Inspect the Secret Scan findings ledger",
        _cli_setup,
        _cli_handler,
        description="Show Secret Scan findings recorded on this machine",
    )
