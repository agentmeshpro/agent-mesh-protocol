# ampro Examples

40 runnable examples demonstrating protocol features + 5 AMPI framework examples.

## Installation

```bash
pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
```

## Running

Python examples:

```bash
python examples/01_minimum_viable_agent.py
```

Examples that require a server (02, 31-38):

```bash
# For the pre-AMPI FastAPI example
uvicorn examples.02_fastapi_agent:app --port 8000

# For AMPI-based examples (41-45)
ampro-server examples.41_ampi_quickstart:agent --port 8000
```

## Core Concepts (01-09)

| # | File | Shows |
|---|------|-------|
| 01 | `01_minimum_viable_agent.py` | Smallest valid agent + agent.json |
| 02 | `02_fastapi_agent.py` | Raw FastAPI wiring (pre-AMPI) |
| 03 | `03_trust_and_auth.py` | Trust tiers + Authorization resolution |
| 04 | `04_addressing.py` | `agent://` URIs + resolution |
| 05 | `05_body_schemas.py` | Typed body schemas + validation |
| 06 | `06_delegation_chains.py` | Signed delegation chains |
| 07 | `07_security.py` | RFC 9421 signing + dedup + rate limit |
| 08 | `08_compliance.py` | Jurisdiction + PII + erasure |
| 09 | `09_capability_negotiation.py` | Capability headers + negotiation |

## Protocol Features (10-30)

| # | File | Shows |
|---|------|-------|
| 10 | `10_handshake.py` | 3-phase session handshake |
| 11 | `11_visibility.py` | Visibility and contact policies |
| 12 | `12_context_schema.py` | Context schema declaration |
| 13 | `13_key_revocation.py` | Key revocation lists |
| 14 | `14_challenge_response.py` | Challenge-response (anti-abuse) |
| 15 | `15_tool_consent.py` | Per-tool consent grants |
| 16 | `16_backpressure.py` | Streaming backpressure (ack/pause/resume) |
| 17 | `17_agent_lifecycle.py` | Orderly shutdown and migration |
| 18 | `18_cost_receipt.py` | Per-hop cost attribution |
| 19 | `19_registry_search.py` | Registry search and service discovery |
| 20 | `20_load_redirect.py` | Load-aware `task.redirect` |
| 21 | `21_tracing.py` | W3C Trace Context propagation |
| 22 | `22_task_revoke.py` | Task revocation with cascade |
| 23 | `23_jurisdiction.py` | Jurisdiction declaration and conflict detection |
| 24 | `24_consent_revoke.py` | Consent revocation and erasure propagation |
| 25 | `25_stream_multiplexing.py` | Multiple logical streams over one channel |
| 26 | `26_stream_checkpoint.py` | Checkpoints and reconnection |
| 27 | `27_identity_linking.py` | Identity linking across providers |
| 28 | `28_agent_migration.py` | Agent migration between hosts |
| 29 | `29_encryption.py` | End-to-end encryption |
| 30 | `30_trust_proof.py` | Zero-knowledge trust proofs |

## Reference Server SDK (31-35)

| # | File | Shows |
|---|------|-------|
| 31 | `31_simple_server.py` | Minimal `ReferenceServer` |
| 32 | `32_server_with_tools.py` | Tool registration |
| 33 | `33_server_with_auth.py` | Auth middleware |
| 34 | `34_server_with_sessions.py` | Session management |
| 35 | `35_server_with_streaming.py` | SSE streaming |

## Reference Client SDK (36-38)

| # | File | Shows |
|---|------|-------|
| 36 | `36_client_send_message.py` | Outbound message |
| 37 | `37_client_with_handshake.py` | Session handshake |
| 38 | `38_client_streaming.py` | Consume SSE stream |

## Multi-Agent (39-40)

| # | File | Shows |
|---|------|-------|
| 39 | `39_two_agents_talking.py` | Two agents in-process |
| 40 | `40_delegation_chain.py` | Multi-hop delegation |

## AMPI Framework (41-45) — new in 0.3.0

| # | File | Shows |
|---|------|-------|
| 41 | `41_ampi_quickstart.py` | Smallest `AgentApp` with `@on` |
| 42 | `42_ampi_with_tools.py` | `@tool`, `@middleware`, `@on_session_start` |
| 43 | `43_ampi_testing.py` | `TestServer` unit-test harness |
| 44 | `44_ampi_ctx_methods.py` | `ctx.send` / `.emit_event` / `.emit_audit` / `.discover` / `.delegate` |
| 45 | `45_ampro_server_cli.py` | Running an agent via the `ampro-server` CLI |

## Interop (46+)

| # | File | Shows |
|---|------|-------|
| 46 | `46_a2a_agent.py` | Serving an `AgentApp` over A2A 1.0 next to AMP; `A2AClient`, input-required, `AuthRequired`, AMP extension |
