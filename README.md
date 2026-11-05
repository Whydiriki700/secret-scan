# Secret Scan

**Secrets never leave in a reply.**

Secret Scan is a Hermes Agent plugin that inspects the agent's outgoing replies and tool traffic for credential-shaped strings, redacts them before anyone sees them, and records every finding locally.

Agents paste things. A config value in a tool result, a token in a debug dump, a key quoted back while "helping": one paste into a chat, a commit, or a ticket and the credential is out. Secret Scan is the last gate before that happens.

## How it works

1. **Reply gate.** A `transform_llm_output` hook holds the finished reply and scans it deterministically: provider API keys (OpenAI, Anthropic, GitHub, Google, AWS), Telegram bot tokens, JWTs, bearer tokens, PEM private key blocks, and explicit `api_key = ...` / `password = ...` style assignments with non-placeholder values.
2. **Redaction, fail closed.** In `enforce` mode each match is replaced with `[redacted by secret-scan]` and the reply carries a short note naming the pattern types found. If the scanner itself errors, the reply is marked unverified instead of passed silently.
3. **Tool traffic watch.** A `post_tool_call` hook scans tool arguments and results and records findings. Traffic is observed, never rewritten; the reply is the enforcement point.
4. **Ledger.** Findings land in an append-only ledger at `$HERMES_HOME/secret-scan/findings.jsonl` with pattern name, severity, surface, and a 4-character masked preview. Full values are never stored, never shown, never sent anywhere.

## Surfaces

* `/secretscan` in chat: recent findings and counts.
* `secretscan_status` tool: the agent can check what it almost leaked.
* `hermes secretscan findings` on the CLI: read the ledger from a terminal.

## Install

```bash
hermes plugins install Whydiriki700/secret-scan --enable
```

Or copy this directory into `~/.hermes/plugins/secret-scan/` and run `hermes plugins enable secret-scan`, then restart Hermes.

Verify any time with:

```bash
hermes plugins validate ~/.hermes/plugins/secret-scan
hermes plugins doctor ~/.hermes/plugins/secret-scan
```

## Configuration

In `config.yaml`:

```yaml
plugins:
  entries:
    secret-scan:
      settings:
        mode: enforce   # enforce | warn | off
```

* `enforce` (default): replies are redacted before delivery.
* `warn`: findings are recorded, replies are never modified.
* `off`: Secret Scan observes nothing and changes nothing.

## Honest limitations

* Pattern based, not entropy based. A credential in an unusual shape (split across lines, base64 encoded, screenshotted) can pass. This is a strong net, not a proof of absence.
* Placeholders like `your-api-key-here` are ignored on purpose, so documentation examples do not trigger noise.
* Tool traffic is logged, not blocked. A tool that itself sends data out (an upload, a post) is outside this gate; the reply to the user is what Secret Scan controls.

## Development

```bash
python3 tests/test_scanner.py   # 7 scenario tests, no dependencies
```

The scanner (`scanner.py`) is pure Python with no Hermes imports, so the detection logic can be tested and audited in isolation.

## License

MIT

---

**More by the same author**

- [ProofGate](https://github.com/Whydiriki700/proofgate): no proof, no done. Agent completion claims checked against tool evidence, fail closed.
- [Commit Keeper](https://github.com/Whydiriki700/commit-keeper): automatic git checkpoints for agent workspaces, secrets excluded by name.
- [Context Keeper](https://github.com/Whydiriki700/context-keeper): session checkpoints that survive restarts, restored into the next session.
- [money-magnet](https://github.com/Whydiriki700/money-magnet): finance tracker, budget alerts, crypto portfolio PnL and arbitrage scanner for Hermes Agent.
- [Token Dashboard](https://github.com/Whydiriki700/token-dashboard): live token usage and cost dashboard for Hermes Desktop.
- Osvyn on Telegram: [t.me/osvynofficial](https://t.me/osvynofficial)
