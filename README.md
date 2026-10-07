# AMP — Agent Mesh Protocol

[![CI](https://github.com/CatlystAI/agent-mesh-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/CatlystAI/agent-mesh-protocol/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Package version](https://img.shields.io/badge/package-0.4.0-green.svg)](CHANGELOG.md)
[![Protocol version](https://img.shields.io/badge/protocol-1.0.0-blue.svg)](docs/WIRE-BINDING.md)

**An open protocol for agent-to-agent communication — trust, delegation and compliance built in, and interoperable with A2A, PACT and MCP out of the box.** `ampro` is the Python reference implementation; the protocol itself is language-agnostic.

> ⚠️ **Pre-1.0.** The wire format is stabilising toward 1.0 but may still evolve between minor versions. Receivers MUST ignore unknown fields. See [RELEASING.md](RELEASING.md) for the stability contract.

---

## Why?

Agents increasingly talk to other agents — across frameworks, companies and trust boundaries. The industry is converging on [A2A](https://a2a-protocol.org) as the transport, [PACT](https://openpactprotocol.org) for personal agents acting for users, and [MCP](https://modelcontextprotocol.io) for tools. What none of them standardise is the hard part of a real mesh: **who may act for whom, how far a delegation reaches, what it may spend, and which data may cross which border.**

AMP adds exactly that, and speaks the other protocols natively, so you don't have to choose:

- **One agent, every protocol.** Write handlers once; serve them over AMP, A2A 1.0, PACT and MCP from the same process.
- **Trust you can verify.** RFC 9421 signed messages, DID/JWT/API-key/mTLS authentication, four trust tiers, key revocation.
- **Delegation with limits.** Signed multi-hop delegation chains with scope narrowing, depth, fan-out and budget enforcement.
- **Compliance primitives.** PII classification, jurisdiction and data residency, erasure propagation, audit attestation.

| | AMP | A2A | PACT | MCP |
|---|---|---|---|---|
| Purpose | Agent mesh: trust, delegation, compliance | Agent-to-agent transport | Personal agents acting for users on A2A | Tools and context for models |
| Signed multi-hop delegation chains | ✅ | ❌ | ❌ (single-hop OAuth grant) | ❌ |
| User consent via OAuth device flow | via PACT | ❌ | ✅ | ❌ |
| Compliance (PII, erasure, jurisdiction) | ✅ | ❌ | ❌ | ❌ |
| Served by `ampro` | ✅ native | ✅ adapter | ✅ adapter | ✅ adapter |

AMP rides **on top of** A2A rather than competing with it: AMP agents publish an A2A Agent Card, accept A2A calls, and carry AMP's delegation and compliance data through A2A's extension mechanism (`https://github.com/CatlystAI/agent-mesh-protocol/ext/amp/v1`). Plain A2A clients simply ignore it.

---

## Install

```bash
pip install "ampro[all] @ git+https://github.com/CatlystAI/agent-mesh-protocol.git"
```

Extras: `server` (uvicorn), `a2a` / `pact` (JWT verification), `mcp`, `flask`, `all`. The core package depends only on pydantic, cryptography, base58 and httpx.

---

## 30-Second Tour — AMPI

**AMPI** (Agent Message Processing Interface) is the declarative framework for building an agent. Think ASGI, but for agents.

```python
# agent.py
from ampro.ampi.app import AgentApp

agent = AgentApp(
    agent_id="agent://my-bot.example.com",
    endpoint="https://my-bot.example.com/agent/message",
)

@agent.on("task.create")
async def handle(msg, ctx):
    return {"echo": msg.body["description"], "via": ctx.protocol, "trust": ctx.trust_tier.value}

@agent.tool("add", description="Add two numbers")
def add(a: int, b: int) -> dict:
    return {"sum": a + b}
```

Serve it over every protocol at once:

```bash
ampro-server agent:agent --port 8000 --protocols amp,a2a,mcp
```

| Protocol | Endpoint |
|---|---|
| AMP | `GET /.well-known/agent.json`, `POST /agent/message` |
| A2A 1.0 | `GET /.well-known/agent-card.json`, `POST /a2a/message:send`, `/a2a/message:stream`, `/a2a/tasks/…`, JSON-RPC at `POST /a2a` |
| MCP | Streamable HTTP at `/mcp` — your `@tool`s plus an `amp_task` tool |

Test without a server:

```python
from ampro.server.test import TestServer

response = await TestServer(agent).send(incoming_message)
```

The server binds to `127.0.0.1` by default. Before exposing it, read [Production deployment](#production-deployment).

---

## Interoperability

| Guide | What it covers |
|---|---|
| [docs/INTEROP-A2A.md](docs/INTEROP-A2A.md) | Serving and calling A2A 1.0 agents (HTTP+JSON, JSON-RPC, streaming), AMP ↔ A2A mapping, the AMP extension. Verified against the official `a2a-sdk` client. |
| [docs/INTEROP-PACT.md](docs/INTEROP-PACT.md) | Hosting brands as a PACT Provider: personal-agent JWT identity, OAuth device-code delegation, scopes, step-up and signed receipts. Verified against the official PACT conformance suite. |
| [docs/INTEROP-MCP.md](docs/INTEROP-MCP.md) | Exposing tools to MCP clients (Claude, Cursor, …) and importing tools from remote MCP servers. Verified against the official `mcp` SDK. |

Calling other agents:

```python
from ampro.interop.a2a import A2AClient

async with A2AClient("https://agent.example.com/.well-known/agent-card.json") as a2a:
    reply = await a2a.send_message("Where is my order?")
```

---

## What's in the box

| Layer | What it provides |
|---|---|
| **Protocol primitives** — `ampro.core`, `ampro.trust`, `ampro.identity` | Typed envelopes, `agent://` addressing, 4-tier trust resolution, auth methods (JWT / DID / API key / mTLS), capability negotiation |
| **Security** — `ampro.security`, `ampro.session` | RFC 9421 message signing, Ed25519 keys, nonce + dedup + rate-limit stores, X25519 session key agreement, SSRF guard with DNS pinning |
| **Compliance** — `ampro.compliance` | PII classification, erasure propagation, jurisdiction tagging, audit attestation |
| **Delegation** — `ampro.delegation` | Signed multi-hop delegation chains with depth, fan-out and budget enforcement; cost receipts |
| **Streaming** — `ampro.streaming` | Server-sent events, multiplexing, checkpoints, backpressure |
| **Registry** — `ampro.registry` | Agent discovery, federation, trust proofs |
| **Framework** — `ampro.ampi` | `AgentApp` + decorators (`@on`, `@tool`, `@middleware`, `@on_startup`, `@on_session_start`, `@on_error`), `AMPContext` |
| **Server + Client SDK** — `ampro.server`, `ampro.client` | Framework-free ASGI server with a security pipeline, `ampro-server` CLI, outbound send/discover/stream/connect helpers |
| **Interop** — `ampro.interop` | A2A 1.0, PACT and MCP adapters and clients |
| **Conformance** — `tests/vectors/` | JSON vectors portable to any language implementation |

---

## Production deployment

The reference server runs the full request pipeline of [WIRE-BINDING Appendix D](docs/WIRE-BINDING.md): size limit → authentication → rate limit → validation → sender binding → recipient check → loop detection → caller-scoped dedup → concurrency limit → handler timeout. Exception details never reach clients.

```python
from ampro.server import AgentServer
from ampro.server.auth import SignatureAuthenticator
from ampro.server.security import SecurityPolicy

server = AgentServer.from_app(
    agent,
    security=SecurityPolicy.production([
        SignatureAuthenticator("https://my-bot.example.com", key_owner=lookup_agent_for_key),
    ]),
)
asgi_app = server.asgi()   # run with any ASGI server, behind TLS
```

Checklist:

- **Require authentication** (`SecurityPolicy.production`, `require_auth=True` on the A2A/MCP adapters) before binding beyond loopback.
- **Register your key infrastructure:** `register_public_key_resolver`, a `RevocationStore`, and API keys via `register_api_key`.
- **Share state across workers:** every store (dedup, rate limits, tasks, contexts, sessions, grants) is a small protocol with a bounded in-memory default. Plug in Redis or a database when you run more than one process.
- **Terminate TLS** in front of the server, and set `public_url` so signatures and Agent Cards use your external origin.
- Read [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md): what the protocol guarantees, and what it leaves to you.

---

## Choose your path

**Building an agent** → the tour above, then [`examples/`](examples/) (`41-45` AMPI, `46` A2A, `47` MCP, `48` PACT) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Implementing AMP in another language** → [docs/WIRE-BINDING.md](docs/WIRE-BINDING.md) (normative) and [`tests/vectors/`](tests/vectors/) ([index](tests/vectors/README.md)).

**Evaluating the protocol** → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/WIRE-BINDING.md](docs/WIRE-BINDING.md), [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md), and the audit retrospectives [SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) / [SECURITY-AUDIT-V2.md](docs/SECURITY-AUDIT-V2.md).

**Contributing** → [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md).

---

## Protocol vs platform

AMP specifies the wire contract and nothing else. How an agent *is* — how you create, configure, operate and observe it — is the host platform's job.

| Protocol (this package) | Platform (your business) |
|---|---|
| `agent://` addressing, A2A/PACT/MCP bindings | Agent creation & onboarding |
| `POST /agent/message` + typed body schemas | Agent configuration & settings |
| Trust tiers & auth methods | Memory system |
| Signed delegation chains | Model selection & routing |
| Streaming & events | UI / dashboard |
| Compliance & erasure | Internal orchestration |
| RFC 9421 signing | Key storage & rotation policy |

---

## Security

Report vulnerabilities to **security@amp-protocol.dev** — see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 AMP Contributors.
