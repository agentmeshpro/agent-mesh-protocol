# Agent Mesh Protocol — Architecture Guide

## Overview

The Agent Mesh Protocol (AMP) defines how autonomous agents communicate across
platforms, runtimes, and trust boundaries. It is a wire-level protocol — it specifies
message formats, headers, state machines, and security primitives. It does not specify
how agents are built, what AI models they use, or how they make decisions.

```
┌─────────────────────────────────────────────────────────┐
│                    YOUR PLATFORM                        │
│  (How agents are built — memory, AI models, UI, tools)  │
│  Examples: LangGraph, CrewAI, AutoGen, custom           │
├─────────────────────────────────────────────────────────┤
│              AGENT MESH PROTOCOL (AMP)                  │
│  (How agents talk — addressing, trust, delegation,      │
│   sessions, streaming, compliance, schemas)             │
│  Package: pip install ampro                             │
├─────────────────────────────────────────────────────────┤
│                    TRANSPORT                            │
│  (How bytes move — HTTP/HTTPS, WebSocket, MQTT)         │
│  Default: HTTPS. Protocol is transport-agnostic.        │
└─────────────────────────────────────────────────────────┘
```

AMP sits in the middle. It doesn't care what's above (your platform) or below
(your transport). It defines the conversation rules.

---

## 1. What Makes Something an Agent

Any system that does two things is an agent:

1. **Serves `/.well-known/agent.json`** — declares identity, capabilities, trust
   requirements, and endpoint
2. **Accepts `POST /agent/message`** — receives and processes protocol messages

That's it. The hardware, AI model, programming language, and runtime are irrelevant.

```
Cloud AI service         → agent://assistant@cloud.example.com
Raspberry Pi             → agent://home-pi.local
Smart refrigerator       → agent://fridge@home.example.com
Traffic controller       → agent://signal-42@traffic.example.com
Factory robot            → agent://arm-7@factory.example.com
Phone app                → agent://mobile@phone.example.com
Browser extension        → agent://browser-helper.local
```

30 lines of Python makes anything an agent. If it speaks AMP, it's in the mesh.

---

## 2. Addressing

Every agent has an `agent://` URI. Three forms:

### Direct Host
```
agent://weather-service.example.com
```
The agent IS at this host. Resolution: fetch
`https://weather-service.example.com/.well-known/agent.json`.

### Registry Slug
```
agent://data-processor@registry.example.com
```
A registry knows where this agent lives. Resolution: call
`GET https://registry.example.com/agent/resolve/data-processor`.

### Decentralized Identifier (DID)
```
agent://did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```
The identity IS the cryptographic key. Self-verifying — no registry needed.

### Multiple Addresses
Agents can have multiple addresses (all listed in the `identifiers` array of
agent.json). They all resolve to the same endpoint and the same public key.

### Shorthand
Within a platform, bare slugs like `@data-processor` are allowed. They are
normalized to `agent://data-processor@registry.example.com` before any
cross-platform communication. Bare slugs MUST NOT appear in messages that leave
the platform.

---

## 3. Message Envelope

Every message uses the same envelope:

```json
{
  "sender": "agent://alice.example.com",
  "recipient": "agent://service.example.com",
  "id": "msg-uuid-123",
  "body_type": "task.create",
  "headers": {
    "Session-Id": "sess-uuid-456",
    "Protocol-Version": "1.0.0",
    "Priority": "normal",
    "Trust-Tier": "verified"
  },
  "body": {
    "description": "Process this data set",
    "context": {"dataset_id": "ds-789", "format": "csv"},
    "priority": "high"
  }
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `sender` | Yes | `agent://` URI of the sending agent |
| `recipient` | Yes | `agent://` URI of the receiving agent |
| `id` | Auto | UUID, generated if not provided. Used for dedup and correlation |
| `body_type` | Yes | What kind of message this is (see Body Types below) |
| `headers` | No | Extensible key-value pairs. Receivers MUST ignore unknown headers |
| `body` | No | The message payload, validated against `body_type` schema |

### Standard Headers

The protocol defines 51+ standard headers. Receivers understand these but MUST
ignore any header they don't recognize (forward-compatibility). Key headers:

| Header | Purpose |
|--------|---------|
| `Session-Id` | Session this message belongs to |
| `Protocol-Version` | Protocol version (e.g. `1.0.0`) |
| `Trust-Tier` | Sender's trust level (`internal`, `owner`, `verified`, `external`) |
| `Trust-Score` | Numeric trust score (e.g. `450/1000`) |
| `Delegation-Depth` | How many delegation hops remain |
| `Visited-Agents` | Comma-separated list of agents in the delegation chain |
| `Chain-Budget` | Remaining budget in the delegation chain |
| `Session-Binding` | HMAC-SHA256 proof for session-bound messages |
| `Context-Schema` | URN declaring what schema `body.context` follows |
| `Transaction-Id` | Groups multiple tasks into one transaction |
| `Correlation-Group` | Groups related tasks (fan-out, multi-party) |
| `Commitment-Level` | Whether this is `informational`, `binding`, or `conditional` |
| `Priority` | Message priority (`low`, `normal`, `high`, `urgent`) |
| `Nonce` | Replay protection |
| `In-Reply-To` | Message ID this is responding to |

---

## 4. Body Types

The `body_type` field determines the message's semantics and which Pydantic model
validates the `body` payload. 49+ typed body schemas organized by HTTP verb analogy:

### Creating Work (POST)

| Body Type | Purpose |
|-----------|---------|
| `message` | Free-form text message with optional attachments |
| `task.create` | Create a new task with description, context, priority |
| `task.assign` | Assign an existing task to a specific agent |
| `task.delegate` | Delegate a task with full delegation chain context |
| `task.spawn` | Spawn a child task from a parent |
| `task.quote` | Request or provide a non-binding cost/time estimate |
| `notification` | One-way notification (no response expected) |

### Lifecycle Updates (PATCH)

| Body Type | Purpose |
|-----------|---------|
| `task.progress` | Report task progress (percentage, message) |
| `task.input_required` | Request additional input to continue |
| `task.escalate` | Escalate to a human or specific agent |
| `task.reroute` | Cancel or redirect a task |
| `task.transfer` | Transfer task ownership to another agent |
| `task.acknowledge` | Acknowledge receipt and acceptance |
| `task.reject` | Reject a task with reason |
| `task.complete` | Signal successful completion with result |
| `task.error` | Report a terminal error |

### Responding (PUT)

| Body Type | Purpose |
|-----------|---------|
| `task.response` | Structured response to a task |

### Session Management (v0.1.1)

| Body Type | Purpose |
|-----------|---------|
| `session.init` | Propose a new session (capabilities, nonce, ephemeral X25519 key) |
| `session.established` | Accept session (terms, nonce, ephemeral X25519 key, confirm nonce) |
| `session.confirm` | Confirm session (binding proof, echoed confirm nonce) |
| `session.ping` / `session.pong` | Keepalive |
| `session.pause` / `session.resume` | Suspend and resume |
| `session.close` | Graceful termination |

### Compliance

| Body Type | Purpose |
|-----------|---------|
| `data.consent_request` | Request consent for scoped access |
| `data.consent_response` | Grant or deny consent |
| `data.erasure_request` | GDPR erasure request |
| `data.erasure_response` | Erasure completion report |

### Extension Types

Unknown body types pass through validation unchanged — the raw dict is returned.
Extension types use reverse-domain prefixes:

```
com.yourplatform.custom_action
org.industry.specific_workflow
```

This enables platform-specific features without protocol changes.

### Context Schema

Domain-specific semantics go in `body.context` with a `Context-Schema` header:

```
Context-Schema: urn:schema:status-report:v1
→ body.context carries structured status data

Context-Schema: urn:schema:appointment-booking:v1
→ body.context carries date, time, service, provider

No schema header?
→ body.description is natural language, the AI figures it out
```

The protocol defines the header and URN format. It does NOT define domain schemas —
those are between the two communicating parties.

---

## 5. Trust Model

### Four Tiers

```
INTERNAL    Same organization. Full access. Minimal safety checks.
OWNER       The agent's owner/operator. Full access.
VERIFIED    Identity proven (JWT, DID, API key, mTLS). Standard access.
EXTERNAL    Unknown. Restricted. Full safety pipeline.
```

Trust is **unidirectional**. Agent A might consider B `verified` while B considers
A `external`. Each side resolves trust independently.

### Trust Resolution Chain

When a message arrives, the receiver resolves trust in order:

1. Same organization? → `INTERNAL`
2. Bearer JWT with owner scope? → `OWNER`
3. Bearer JWT with valid signature? → `VERIFIED`
4. DID proof: a compact EdDSA JWS signed by a `did:key`, with `aud` naming
   this agent, a lifetime of at most 300 s, a single-use `jti`, and the DID
   bound to the envelope sender (or to one of the sender's verified, linked
   DIDs)? → `VERIFIED`
5. API key registered via `register_api_key` (stored hashed, compared in
   constant time, capped at `VERIFIED`)? → `VERIFIED`
6. mTLS client certificate verified by the transport (the identity never
   comes from a request header)? → `VERIFIED`
7. Everything else → `EXTERNAL`

Requests can also authenticate with RFC 9421 HTTP message signatures
(Ed25519, with a required nonce and a 300 s freshness window). A credential
that is present but invalid gets a 401. It is never silently downgraded
to `EXTERNAL`. See WIRE-BINDING sections 12.1 and 12.15.

### Trust Score (0-1000)

Four tiers are a start, but `VERIFIED` is too broad — it covers everything from
"created a key 5 seconds ago" to "has been running reliably for 3 years." The
numeric trust score adds granularity:

| Factor | What it measures | Max |
|--------|-----------------|-----|
| Age | How long the agent has existed | 200 |
| Track record | Successful interactions over time | 200 |
| Clean history | Absence of incidents | 200 |
| Endorsements | Other trusted agents vouch for this one | 200 |
| Identity strength | How strong the identity proof is | 200 |

Total: 0-1000. The score maps to rate limits and content filtering:

| Score | Rate limit | Content filter |
|-------|-----------|---------------|
| 800+ | 1000 req/min | Off |
| 400-799 | 100 req/min | Off |
| 100-399 | 10 req/min | On |
| 0-99 | 1 req/min | On |

### Safety Pipeline

The trust tier determines which safety checks run:

| Check | INTERNAL | OWNER | VERIFIED | EXTERNAL |
|-------|----------|-------|----------|----------|
| Authentication | - | - | - | Yes |
| Rate limiting | - | - | Yes | Yes |
| Content filtering | - | - | - | Yes |
| Budget check | - | Yes | Yes | Yes |
| Loop detection | - | - | Yes | Yes |
| Kill switch | Yes | Yes | Yes | Yes |

---

## 6. Sessions

### Lifecycle

Sessions track conversations between two agents. They go through these states:

```
IDLE → INIT_SENT → ESTABLISHED → CONFIRMED → ACTIVE → CLOSED
                                              ↕
                                           PAUSED
```

### 3-Phase Handshake

```
Client → Server:  session.init
  "I want to talk. I support messaging + tools. Here's my nonce."

Server → Client:  session.established
  "OK. Session ID: sess-123. Your trust: verified (450/1000).
   We'll use messaging + tools. Here's my nonce, my ephemeral X25519
   key, and a single-use confirm nonce."

Client → Server:  session.confirm
  "Confirmed. Here's an HMAC proving I derived the same binding key,
   and your confirm nonce back."
```

The server verifies the proof before the session becomes active.

After the confirm, the session is `ACTIVE`. Every subsequent message carries the
`Session-Id` header.

### Session Binding (X25519 + HKDF + HMAC-SHA256)

Sessions are cryptographically bound to prevent hijacking:

1. During the handshake, both sides exchange random nonces and ephemeral
   X25519 public keys.
2. Each side derives the binding key on its own:
   `HKDF-SHA256(X25519 shared secret, salt = nonces, info = session ID + both public keys)`.
   The key is never sent.
3. The client proves it holds the key with `binding_proof`, an HMAC over the
   handshake transcript. The server verifies the proof before it activates
   the session.
4. Every message includes a `Session-Binding` header:
   `HMAC-SHA256(key, session_id ‖ 0x00 ‖ message_id ‖ 0x00 ‖ SHA-256(canonical body))`.
5. The receiver verifies the header using constant-time comparison.

If someone guesses the Session-Id (UUID) but doesn't know the binding key,
their messages are rejected. An observer who watched the handshake can't
compute the key either. The exact derivation is in WIRE-BINDING section 9.3.

### Implicit Sessions

Handshakes are optional. Sending `task.create` without a handshake still works —
the server creates an implicit session. The handshake is for agents that want
stronger guarantees.

---

## 7. Delegation

Agents delegate work through cryptographically signed chains:

```
Alice delegates to Bob:
  Scopes: [tool:read, tool:execute]
  Budget: $5.00 max
  Depth: 3 hops max
  Signed by Alice's Ed25519 key

Bob sub-delegates to Charlie:
  Scopes: [tool:read]          ← narrowed (never widened)
  Budget: $3.50 remaining      ← decremented
  Depth: 2 remaining           ← decremented
  Signed by Bob's key

Charlie verifies the entire chain before accepting.
```

### Constraints

- **Whole-link signature**: The delegator signs every link field, plus the
  parent's delegate, so a link can't be edited or moved to another chain
- **Scope narrowing**: Each hop can only narrow scopes, never widen
- **Budget decrement**: Budget never increases along the chain, and a hop
  can't drop its parent's budget
- **Depth limit**: Each child's `max_depth` is at most its parent's minus one.
  The chain can't be longer than the root's `max_depth`.
- **Loop detection**: `Visited-Agents` header prevents A→B→C→A cycles
- **Fan-out limit**: Maximum sub-delegations per link (default: 3), enforced
  by receivers that track counts

### Delegation Headers

| Header | Purpose |
|--------|---------|
| `Delegation-Depth` | Remaining hops allowed |
| `Visited-Agents` | Comma-separated chain for loop detection |
| `Chain-Budget` | Remaining budget (e.g. `3.50 USD`) |

---

## 8. Visibility & Access Control

### Four Visibility Levels

| Level | agent.json | Tools | Presence | Who can contact |
|-------|-----------|-------|----------|----------------|
| `public` | Full | Yes | Yes | Anyone |
| `authenticated` | Full after auth | After auth | After auth | Verified+ only |
| `private` | 401 | No | No | Delegation or invite only |
| `hidden` | 404 | No | No | Direct endpoint only |

### Five Contact Policies

| Policy | Who can send the first message |
|--------|-------------------------------|
| `open` | Anyone |
| `handshake_required` | Must complete handshake first |
| `verified_only` | Only verified, owner, or internal |
| `delegation_only` | Only via delegation from an authorized agent |
| `explicit_invite` | Only agents on an allowlist |

### Conditional agent.json

For `authenticated` visibility, different callers see different data:

- **Unauthenticated**: Only `protocol_version`, `identifiers`, `endpoint`, `visibility`
- **Verified+**: Full agent.json with all fields
- **Owner/Internal**: Full agent.json plus internal metadata

### Gateway Pattern

Internal agents sit behind a public gateway:

```
External world
    │
    ▼
agent://company.example.com  (gateway — public)
    │
    ├── Routes "task A" → Internal Agent 1 (private, no public address)
    ├── Routes "task B" → Internal Agent 2 (private, no public address)
    └── Routes "task C" → Internal Agent 3 (private, no public address)
```

The external agent talks to the gateway. Internal agent addresses never appear
in external-facing messages. In `Visited-Agents` headers, internal agents are
replaced with opaque tokens (`_internal_1`) to prevent structure leakage while
preserving loop detection.

---

## 9. Streaming

Real-time events via Server-Sent Events (SSE):

```
event: thinking        Agent is reasoning
event: tool_call       Agent is invoking a tool
event: tool_result     Tool returned a result
event: text_delta      Partial text response
event: state_change    Task status changed
event: agent_call      Agent is delegating to another agent
event: agent_result    Delegated agent returned
event: error           Something went wrong
event: heartbeat       Keepalive (every 15 seconds)
event: done            Stream complete
```

### Sequencing & Replay

Every event has a monotonic `seq` number starting at 1. If a client disconnects
and reconnects, it sends `Last-Event-ID` and the server replays events from that
point. A replay buffer retains recent events for reconnection.

### Fallback

If SSE isn't available (firewalls, proxies), agents fall back to polling:
`GET /agent/tasks/{task_id}/status` with a `Poll-Interval` header.

---

## 10. Compliance

Built into the protocol, not bolted on:

### Content Classification

Every message can carry a `Content-Classification` header:

```
public          → No restrictions
internal        → Organization-only
pii             → Contains personal data (name, email, phone)
sensitive-pii   → Contains sensitive personal data (health, financial)
confidential    → Restricted access
```

Agents that don't handle PII can reject messages classified as `pii` or above.

### GDPR Erasure

The protocol defines `data.erasure_request` and `data.erasure_response` body
types. Erasure requests propagate across the mesh — if Agent A processed data
through Agent B, the erasure request follows the delegation chain.

### Audit Logging

Hash-chain audit logs provide tamper detection. Each audit entry includes a
SHA-256 hash of the previous entry, creating a verifiable chain.

### Consent Management

`data.consent_request` and `data.consent_response` body types handle scoped
consent. Consent grants have TTLs, scope lists, and can be revoked.

---

## 11. Capabilities & Negotiation

### Eight Capability Groups

```
MESSAGING    — Text messages, conversations
TASKS        — Task creation, assignment, delegation
TOOLS        — Tool invocation
STREAMING    — Real-time SSE events
COMPLIANCE   — GDPR, PII handling, audit
DELEGATION   — Multi-hop task delegation
EVENTS       — Event subscriptions
SESSION      — Session management, handshake
```

### Six Progressive Levels

```
Level 0 — Receive only (can process messages, nothing else)
Level 1 — Basic (messaging + simple tasks)
Level 2 — Capable (+ tools, streaming)
Level 3 — Full agent (+ delegation, events)
Level 4 — Autonomous (+ compliance, cross-platform)
Level 5 — Platform (can host and manage other agents)
```

### Negotiation

When two agents connect, they negotiate capabilities:

1. Client proposes capabilities in `session.init`
2. Server responds with the intersection in `session.established`
3. Both sides use only the negotiated capabilities

If a client sends a message requiring a capability the server didn't negotiate,
the server responds with `task.reject` and `reason: "capability_not_negotiated"`.

---

## 12. Devices & Embodiment

Agents can declare their physical nature in agent.json:

```json
{
  "device": {
    "embodiment": "physical",
    "type": "traffic_signal_controller",
    "location": {"lat": 40.7128, "lon": -74.0060},
    "hardware": ["signal_controller", "camera"],
    "connectivity": {"type": "cellular_4g", "reliability": "intermittent"},
    "power": {"source": "solar_battery", "backup_hours": 6},
    "safety": {"classification": "safety_critical", "human_override_required": true}
  }
}
```

Cloud agents, laptops, phones, IoT devices, industrial robots, vehicles — all are
agents. The protocol adapts to their constraints.

---

## 13. Extensibility

The protocol provides primitives. Platforms compose them:

```
PROTOCOL PRIMITIVES               ANYONE CAN BUILD
──────────────────               ────────────────
task.create + context            Status reports, bookings, claims
Context-Schema header            Industry-specific schemas
Custom headers (X-Org-*)         Platform features
Custom body types (com.org.*)    Proprietary workflows
Extension capability groups      Domain capabilities
```

No domain-specific types in the core protocol. Ever. The protocol is the plumbing,
not the fixtures.

---

## 14. Security Summary

| Layer | Mechanism |
|-------|-----------|
| **Identity** | Ed25519 keys, DID, JWT, API keys, mTLS |
| **Authentication** | JWKS key fetching, DID resolution, API key validation |
| **Session security** | X25519 + HKDF binding key (never sent), verified binding proof, per-message HMAC over the body digest |
| **Message integrity** | RFC 9421 signatures with a covered content-digest, required nonce, caller-scoped dedup |
| **Authorization** | Trust tiers, capability negotiation, delegation chains |
| **Abuse prevention** | Rate limiting, concurrency limiting, circuit breakers |
| **Privacy** | Visibility levels, contact policies, delegation chain privacy |
| **Compliance** | Content classification, GDPR erasure, audit hash-chains |

---

## 15. What the Protocol Doesn't Do

These are each platform's competitive advantage:

- How agents are created (onboarding, configuration)
- Agent personality, instructions, or behavioral configuration
- Memory and knowledge management
- AI model selection and inference
- User interface and dashboards
- Internal orchestration logic
- Business logic and workflows
- Billing and subscription management

**The protocol defines how agents TALK. How they THINK is your business.**

---

## AMPI — Handler Contract

AMPI (Agent Message Processing Interface) is the reference programming model for
building AMP agents. It is to AMP what ASGI is to HTTP: a lightweight handler
contract you can implement once and run on many servers.

### AgentApp

`AgentApp` is the application object — the AMPI analog of ASGI's `application`
callable. It owns the route table, middleware stack, lifecycle hooks, and tool
registry for a single agent.

### The seven decorators

| Decorator | Purpose |
|-----------|---------|
| `@on(body_type)` | Register a handler for a specific `body_type` (e.g. `task.create`) |
| `@middleware` | Wrap every inbound message (auth, logging, tracing, rate limits) |
| `@tool(name)` | Expose a callable tool; the handler is invoked for `tool.invoke` |
| `@on_startup` | Run once when the app boots (open pools, warm caches) |
| `@on_shutdown` | Run once on graceful shutdown (flush, close, persist) |
| `@on_session_start` | Fire when a new session is established |
| `@on_error` | Last-resort handler for uncaught exceptions |

### AMPContext

`AMPContext` is the per-request handle passed to every handler. It exposes
the resolved `trust_tier`, the live `session`, the `delegation_chain`, and
methods: `send()`, `discover()`, `delegate()`, `emit()`, `audit()`.

### Testing — TestServer

`TestServer` runs an `AgentApp` in-process with no transport for fast unit
tests. Feed it envelopes, assert on the response.

### Running — ampro-server

The `ampro-server` CLI runs any `AgentApp` as a concrete HTTP agent:

```bash
ampro-server main:agent --port 8000
```

### See also

- [`examples/41_ampi_quickstart.py`](../examples/41_ampi_quickstart.py) —
  minimum viable AMPI agent in ~30 lines.

---

## Interop

`ampro.interop` serves and calls AMP agents over other agent protocols. Each
interop package is a `ProtocolAdapter` (`ampro.server.http`). You mount it on
an `AgentServer` with `server.mount(adapter)`, or with
`ampro-server --protocols amp,a2a,mcp`. The adapter translates its wire
format to and from `AgentMessage` and dispatches through the same AMPI
handlers, so one `AgentApp` serves every protocol:

- `ampro.interop.a2a`: Google A2A (HTTP+JSON and JSON-RPC bindings)
- `ampro.interop.pact`: PACT personal-agent identity and delegated authority
  on top of A2A
- `ampro.interop.mcp`: Model Context Protocol (exposes `@tool`s)

The server offers each request to the mounted adapters, in mount order,
before its native AMP routes. Only the message-size limit runs before
the adapters see a request. The native-route pipeline (WIRE-BINDING
Appendix D) does not run for adapter traffic, so each adapter has to
authenticate requests itself, using the shared `Authenticator` contract
in `ampro.server.auth`. Each adapter will be described in its own
`docs/INTEROP-*.md`.

