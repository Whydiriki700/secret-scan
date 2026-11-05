"""Scenario tests for the Secret Scan core scanner.

Run: python3 tests/test_scanner.py   (no dependencies)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402

FAKE_OPENAI = "sk-" + "a1B2c3D4" * 6
FAKE_GITHUB = "ghp_" + "X9" * 20
FAKE_TELEGRAM = "123456789:AA" + "zZ9-" * 8
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"[:16]
FAKE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn

    return wrap


@case("plain text has no findings")
def _():
    assert scanner.scan_text("The deploy finished and the report is ready.") == []


@case("openai style key is found and masked")
def _():
    findings = scanner.scan_text(f"here is the key {FAKE_OPENAI} ok")
    assert len(findings) == 1 and findings[0]["pattern"] == "openai_api_key"
    assert findings[0]["preview"].endswith("***") and FAKE_OPENAI not in findings[0]["preview"]


@case("github and telegram tokens are found")
def _():
    findings = scanner.scan_text(f"{FAKE_GITHUB} and {FAKE_TELEGRAM}")
    kinds = {f["pattern"] for f in findings}
    assert "github_token" in kinds and "telegram_bot_token" in kinds


@case("aws key id and private key block are found")
def _():
    findings = scanner.scan_text(FAKE_AWS + "\n" + FAKE_PEM)
    kinds = {f["pattern"] for f in findings}
    assert "aws_access_key_id" in kinds and "private_key_block" in kinds


@case("assigned secret is found, placeholder is ignored")
def _():
    hits = scanner.scan_text('api_key = "Zx9Qw8Er7Ty6Ui5Op4As3Df2"')
    assert any(f["pattern"].startswith("assigned_secret") for f in hits)
    assert scanner.scan_text('api_key = "your-api-key-here"') == []


@case("redaction removes the value and keeps the text")
def _():
    text = f"token: {FAKE_OPENAI} done"
    out = scanner.redact_text(text, scanner.scan_text(text))
    assert FAKE_OPENAI not in out and "[redacted by secret-scan]" in out and "done" in out


@case("short values and ordinary words are not flagged")
def _():
    assert scanner.scan_text("password is a common english word in this sentence") == []
    assert scanner.scan_text(None) == [] and scanner.scan_text(42) == []


def main() -> int:
    failed = 0
    for name, fn in CASES:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
