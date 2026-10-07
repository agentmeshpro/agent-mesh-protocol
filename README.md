# AMP — Agent Mesh Protocol

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Package version](https://img.shields.io/badge/package-0.3.1-green.svg)](CHANGELOG.md)
[![Protocol version](https://img.shields.io/badge/protocol-1.0.0-blue.svg)](docs/WIRE-BINDING.md)
[![Tests](https://img.shields.io/badge/tests-1015_passing-brightgreen.svg)](tests/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](CONTRIBUTING.md)

**An open wire protocol for agent-to-agent communication.** Like HTTP for browsers — but for AI agents. `ampro` is the Python reference implementation; the protocol itself is language-agnostic.

> ⚠️ **Pre-1.0.** The wire format is stabilising toward 1.0 but may still evolve between minor versions. Receivers MUST ignore unknown fields. See [RELEASING.md](RELEASING.md) for the stability contract.

---

## Why?

Today every agent framework — MCP, A2A, OpenAI's Assistants API, LangChain, custom builds — speaks its own dialect. An agent built for one can't natively talk to agents built on another. AMP is the HTTP-layer answer: a single typed wire format that any runtime can implement, so agents interoperate across frameworks, clouds, languages, and trust boundaries.

| Feature | AMP | MCP | Google A2A | OpenAI Assistants |
|---|---|---|---|---|
| Wire format published | ✅ | ✅ | ✅ | ❌ (proprietary) |
| Cross-agent addressing (`agent://`) | ✅ | partial | ✅ | ❌ |
| Trust tiers + auth methods in spec | ✅ (4 tiers, 5 methods) | ❌ | partial | ❌ |
| Signed delegation chains | ✅ | ❌ | ❌ | ❌ |
| Compliance primitives (PII, erasure, jurisdiction) | ✅ | ❌ | ❌ | ❌ |
| Wire-level streaming (SSE) | ✅ | ✅ | ✅ | ✅ |
| Framework-agnostic reference impl | ✅ | ✅ | partial | ❌ |
| Normative test vectors | ✅ (34) | partial | ❌ | ❌ |

---

## Install

```bash
pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
```

> PyPI publication pending; install from source until 1.0.

---

## 30-Second Tour — AMPI

**AMPI** (Agent Message Processing Interface) is the declarative framework for building an AMP agent. Think ASGI, but for agents.

```python
# agent.py
from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage

agent = AgentApp(
    agent_id="agent://my-bot.example.com",
    endpoint="http://localhost:8000/agent/message",
)

@agent.on("task.create")
async def handle(msg: AgentMessage, ctx: AMPContext) -> dict:
    return {"echo": msg.body, "trust": ctx.trust_tier.value}
```

Run it:

```bash
ampro-server agent:agent --port 8000
```

Test it without a server:

```python
from ampro.server.test import TestServer

server = TestServer(agent)
response = await server.send(incoming_message)
```

That's it. See [`examples/41-45`](examples/) for tools, middleware, session hooks, `ctx.send`/`delegate`/`discover`, and more.

---

## What's in the box

| Layer | What it provides |
|---|---|
| **Protocol primitives** — `ampro.core`, `ampro.trust`, `ampro.identity` | Typed envelopes, `agent://` addressing, 4-tier trust resolution, 5 auth methods (Bearer / DID / JWKS / API key / mTLS), capability negotiation |
| **Security** — `ampro.security`, `ampro.session` | RFC 9421 message signing, Ed25519 keys, nonce + dedup + rate-limit stores, session handshake, SSRF guards |
| **Compliance** — `ampro.compliance` | PII classification, erasure propagation, jurisdiction tagging, audit attestation |
| **Delegation** — `ampro.delegation` | Signed multi-hop delegation chains with cost receipts and budget enforcement |
| **Streaming** — `ampro.streaming` | Server-sent events, multiplexing, checkpoints, backpressure |
| **Registry** — `ampro.registry` | Agent discovery, federation, trust proofs |
| **Framework** — `ampro.ampi` | `AgentApp` + decorators (`@on`, `@tool`, `@middleware`, `@on_startup`, `@on_session_start`, `@on_error`), `AMPContext` |
| **Server + Client SDK** — `ampro.server`, `ampro.client` | Reference FastAPI server, `ampro-server` CLI, outbound message/discover/stream/connect helpers |
| **Conformance** — `tests/vectors/` | 34 JSON vectors portable to any language implementation |

---

## Choose your path

### I'm building an agent

→ Start with the [30-second tour](#30-second-tour--ampi) above.
→ Then browse [`examples/`](examples/) — 45 runnable scripts, `41-45` cover AMPI specifically.
→ Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the mental model.

### I'm implementing AMP in another language (Go, Rust, TypeScript, ...)

→ [docs/WIRE-BINDING.md](docs/WIRE-BINDING.md) is the normative HTTP binding.
→ [`tests/vectors/`](tests/vectors/) has 34 cross-implementation test vectors with a [README index](tests/vectors/README.md).
→ Raise a spec question via [`.github/ISSUE_TEMPLATE/spec_proposal.md`](.github/ISSUE_TEMPLATE/spec_proposal.md).

### I'm reviewing or evaluating the protocol

→ [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — protocol architecture at a glance.
→ [docs/WIRE-BINDING.md](docs/WIRE-BINDING.md) — normative spec.
→ [docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) + [docs/SECURITY-AUDIT-V2.md](docs/SECURITY-AUDIT-V2.md) — audit retrospectives.

### I want to contribute

→ [CONTRIBUTING.md](CONTRIBUTING.md) — setup, testing, the AMPI extension surface.
→ [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.
→ [SECURITY.md](SECURITY.md) — responsible disclosure.

---

## Status

| | |
|---|---|
| Protocol version | **1.0.0** (stabilising; pre-ratification) |
| Package version | **0.3.1** — see [CHANGELOG.md](CHANGELOG.md) |
| Test suite | **1015 tests passing** across 3 Python versions |
| Security audits | 2 completed — all 66 CRITICAL+HIGH findings closed in v0.2.3 |
| PyPI | Not yet published — install from git until 1.0 |
| CI | Matrix (Python 3.11 / 3.12 / 3.13) + ruff + framework-purity grep |

---

## Protocol vs platform

AMP is deliberately narrow. It specifies the wire contract and nothing else. Everything about how an agent *is* — how you create it, configure it, operate it, observe it — is the host platform's job.

| Protocol (this package) | Platform (your business) |
|---|---|
| `agent://` addressing | Agent creation & onboarding |
| `POST /agent/message` + typed body schemas | Agent configuration & settings |
| Trust tiers & auth methods | Memory system |
| Signed delegation chains | Model selection & routing |
| Streaming & events | UI / dashboard |
| Compliance & erasure | Internal orchestration |
| RFC 9421 signing | Key storage & rotation policy |

If something requires a specific framework, database, or business concept to implement, it doesn't belong in `ampro`.

---

## Security

Report vulnerabilities to **security@amp-protocol.dev** — see [SECURITY.md](SECURITY.md) for the disclosure process.

**Read before deploying:** [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) — what the protocol guarantees, what it deliberately doesn't, and the host-platform checklist (trust anchoring, key storage, TLS, rate limits).

Built-in protections: RFC 9421 message signing with freshness windows + nonce binding, dedup (5-min window), per-sender rate limiting, concurrency caps, poison-message tracking, delegation-budget enforcement, pluggable JWKS resolver with revocation checked on every call, SSRF guards on all outbound URLs.

Version 0.2.3 closed all 66 CRITICAL+HIGH findings from the Phase 0 audit sprint. See [docs/SECURITY-AUDIT-V2.md](docs/SECURITY-AUDIT-V2.md) for the retrospective.

---

## License

[Apache License 2.0](LICENSE). Copyright 2026 AMP Contributors.

Contributions are licensed under Apache-2.0 per the DCO workflow described in [CONTRIBUTING.md](CONTRIBUTING.md).
