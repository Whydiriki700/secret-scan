"""Secret Scan core: deterministic credential pattern detection.

Pure Python, no Hermes imports, no network. The scanner looks for the
shapes credentials actually take in the wild, not for the word "secret":

  - provider API keys (OpenAI style sk-, Anthropic sk-ant-, GitHub ghp_ /
    github_pat_, Google GOCSPX- and AIza, AWS AKIA access key ids)
  - Telegram bot tokens (<digits>:AA...)
  - JWTs (eyJ... . ... . ...)
  - PEM private key blocks
  - explicit assignments: api_key = ..., password: ..., client_secret = ...
    with a value that is long enough and not an obvious placeholder

Every finding reports the pattern name, a severity, and a masked preview
(first 4 characters only). Full values are never stored or returned.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "private_key_block",
        "severity": "critical",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    },
    {
        "name": "openai_api_key",
        "severity": "critical",
        "regex": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    },
    {
        "name": "anthropic_api_key",
        "severity": "critical",
        "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    },
    {
        "name": "github_token",
        "severity": "critical",
        "regex": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    },
    {
        "name": "google_client_secret",
        "severity": "critical",
        "regex": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"),
    },
    {
        "name": "google_api_key",
        "severity": "high",
        "regex": re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    },
    {
        "name": "aws_access_key_id",
        "severity": "high",
        "regex": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    },
    {
        "name": "telegram_bot_token",
        "severity": "critical",
        "regex": re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    },
    {
        "name": "jwt",
        "severity": "high",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    },
    {
        "name": "bearer_token",
        "severity": "high",
        "regex": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}", re.IGNORECASE),
    },
]

_ASSIGNMENT = re.compile(
    r"(?P<key>api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)"
    r"\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9._~+/=-]{12,})[\"']?",
    re.IGNORECASE,
)

_PLACEHOLDER_WORDS = (
    "your", "example", "placeholder", "changeme", "change-me", "redacted",
    "xxxx", "todo", "dummy", "sample", "test-key", "not-a-real",
)


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "***"


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(word in low for word in _PLACEHOLDER_WORDS)


def scan_text(text: Any) -> List[Finding]:
    """Return one finding per credential-shaped match in `text`."""
    if text is None:
        return []
    if not isinstance(text, str):
        text = str(text)
    findings: List[Finding] = []
    seen_spans = set()
    for pattern in _PATTERNS:
        for match in pattern["regex"].finditer(text):
            span = match.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)
            findings.append(
                {
                    "pattern": pattern["name"],
                    "severity": pattern["severity"],
                    "preview": _mask(match.group(0)),
                    "start": span[0],
                    "end": span[1],
                }
            )
    for match in _ASSIGNMENT.finditer(text):
        value = match.group("value")
        if _is_placeholder(value):
            continue
        span = match.span("value")
        if span in seen_spans:
            continue
        seen_spans.add(span)
        findings.append(
            {
                "pattern": "assigned_secret:" + match.group("key").lower(),
                "severity": "high",
                "preview": _mask(value),
                "start": span[0],
                "end": span[1],
            }
        )
    findings.sort(key=lambda f: f["start"])
    return findings


def redact_text(text: str, findings: List[Finding]) -> str:
    """Replace each finding's span with a redaction marker, end to start."""
    out = text
    for finding in sorted(findings, key=lambda f: f["start"], reverse=True):
        out = out[: finding["start"]] + "[redacted by secret-scan]" + out[finding["end"] :]
    return out
