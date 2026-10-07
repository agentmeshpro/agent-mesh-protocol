# Changelog

## [Unreleased]

## [0.4.0] - 2026-10-07

Interoperability and production-hardening release. **Breaking:** several
signed wire artefacts changed (session binding, delegation links,
federation proofs, RFC 9421 verification rules). 0.4.0 peers do not
interoperate with 0.3.x peers on those features; see "Changed" below.

### Added
- **A2A 1.0** (`ampro.interop.a2a`): serve any `AgentApp` as an A2A agent
  (Agent Card, HTTP+JSON and JSON-RPC bindings, SSE streaming, tasks,
  cancel, subscribe) and call A2A agents with `A2AClient`. AMP delegation
  and compliance data travel through the A2A extension
  `https://github.com/CatlystAI/agent-mesh-protocol/ext/amp/v1`. Verified
  against the official `a2a-sdk` client. See `docs/INTEROP-A2A.md`.
- **PACT** (`ampro.interop.pact`): host Brands as a PACT Provider —
  personal-agent JWT identity (ES256/RS256 via JWKS), OAuth 2.0 device-code
  delegation (RFC 8628, RFC 8414 metadata), consent pages, scopes and
  step-up, refresh-token rotation with reuse detection, signed receipts;
  plus a personal-agent client (`PASigner`, `PACTClient`). Passes the
  official PACT conformance suite (Identity 10/10, Delegated 9/9);
  `scripts/run_pact_conformance.py` reproduces the run. See
  `docs/INTEROP-PACT.md`.
- **MCP** (`ampro.interop.mcp`): expose `@tool`s (and an `amp_task` bridge)
  over Streamable HTTP to MCP clients, and import tools from remote MCP
  servers with `MCPToolSource`. Verified against the official `mcp` SDK.
  See `docs/INTEROP-MCP.md`.
- `ampro-server --protocols amp,a2a,mcp` serves one agent over several
  protocols; framework-free ASGI binding (`AgentServer.asgi()`).
- Security pipeline for `POST /agent/message` (WIRE-BINDING Appendix D):
  pluggable authenticators (`SignatureAuthenticator`,
  `TrustResolverAuthenticator`), `SecurityPolicy.production()`, per-caller
  rate limiting, sender binding, recipient check, loop detection,
  caller-scoped deduplication with response replay, concurrency limits,
  handler timeouts, Origin guard, JSON content-type enforcement.
- `ampro.security.ssrf`: one SSRF guard (DNS resolution of every address,
  CGNAT/NAT64/6to4/IPv4-mapped forms, numeric host forms) with DNS-pinned
  connections, used by the client, callbacks, JWKS and interop clients.
- Conformance vectors are now executed by `tests/test_vectors.py` with real,
  deterministically regenerated signatures (`tests/vectors/_generate.py`);
  new `rfc9421.json` and `session_binding.json`.
- `@app.tool(name, description=, input_schema=, scopes=)` metadata;
  `AMPContext.principal`, `.scopes`, `.protocol`, `.metadata`.
- Extras: `server`, `a2a`, `pact`, `mcp`, `flask`, `all`.
- **Machine-readable specification** in `spec/`:
  - JSON Schema 2020-12 for the envelope, every registered body type,
    `agent.json`, health, RFC 7807 problem details, the encrypted body and
    streaming events, each with a stable `$id`;
  - `spec/openapi.yaml` (OpenAPI 3.1) for the HTTP binding;
  - registries of body types, headers, error URNs, extension URIs (including
    the A2A extension) and stream events.

  `scripts/generate_spec.py` builds all of it from the reference models and
  the WIRE-BINDING tables, and its `--check` mode fails CI on drift. The
  published schemas accept and reject every schema-shaped test vector
  exactly as the reference does.
- **Black-box conformance suite**: `ampro.conformance` and the
  `ampro-conformance --url … [--level] [--signing-key --keyid] [--report json]`
  CLI. It tests any AMP implementation over HTTP:
  - discovery, health, problem details, envelope and body validation;
  - unknown body types, headers and fields;
  - size limits (413), content type (415), recipient check, loop detection
    (409), duplicate ids, rate limiting (429 and headers);
  - version negotiation (406, `Protocol-Version`);
  - with a key, RFC 9421 replay, tamper, freshness, nonce, algorithm and
    sender-binding checks.

  Each check cites its section and MUST/SHOULD level. See
  `docs/CONFORMANCE.md`.
- `GOVERNANCE.md`: the proposal process, protocol versioning, compatibility
  guarantees, deprecation windows and registration authority.
- `docs/EXTENSIONS.md`: naming rules for third-party body types, headers,
  problem types, stream events and extension URIs. `ampro.wire.extensions`
  implements them. Optional registration goes through `spec/third-party.json`.
- `conformance` extra (`jsonschema`). The `dev` extra adds `jsonschema`,
  `openapi-spec-validator` and `pyyaml`.
- HTTP bindings for `registry.federation_revoke`, `registry.federation_sync`,
  `registry.federation_sync_response` and `agent.metadata_invalidate`.
  `ProblemDetail` now carries `max_bytes` (413) and `supported_versions` (406).

### Fixed
- `ampro-server` / `AgentServer.from_app` could not run AMPI handlers
  (they were called without `ctx`); app middleware and `@on_error` now run.
- Client handshake omitted `confirm_nonce`, so `connect()` always failed.
- Examples 08, 10 and 27 crashed; every example now runs in CI.
- `check_version` rejected same-major versions such as `1.0.1`.
- Federation conflict resolution crashed on naive timestamps.
- The reference server now meets the WIRE-BINDING requirements that
  `ampro-conformance` checks:
  - a `POST /agent/message` without `Content-Type` is treated as JSON
    (section 3.2) instead of getting 415;
  - `X-RateLimit-*` headers appear on every message response (12.4), not
    only on a 429;
  - `Accept-Version` (HTTP header or envelope header) is negotiated, with
    406 and `supported_versions` for a malformed version or an unsupported
    MAJOR (18.4);
  - every message response carries `Protocol-Version`;
  - the `/agent/stream` placeholder emits a defined `heartbeat` event with
    `seq`.
- WIRE-BINDING Appendix B said `additionalProperties: false` for the
  envelope, which contradicted the forward-compatibility rule. It is now
  `true`. Section 15.4 lists 406, 410 and 415, and section 16.1.8 lists
  `agent.metadata_invalidate`.

### Security
- Delegation links sign every field (previously `trust_tier`,
  `chain_budget`, `jwks_url` and `max_fan_out` were unsigned and could be
  escalated by a relay); children cannot raise `max_depth`; fan-out and
  budgets are enforced; naive timestamps are rejected.
- Session binding key is derived with X25519 + HKDF on both sides and never
  transmitted; the server verifies `binding_proof`; per-message HMAC covers
  the body; resume tokens expire.
- RFC 9421: signature verified before the nonce is recorded (no nonce
  burning or tracker exhaustion); a body requires a covered, matching
  `content-digest`; `@method`, `@target-uri` and `@authority` must be
  covered; missing covered headers fail; malformed input never raises.
- did:key proofs require `exp`/`aud`/`jti` and are bound to the sender;
  key revocation fails closed on store errors; bounded public-key cache;
  API keys stored hashed with per-key owner identities; mTLS only from a
  transport-verified certificate.
- Federation trust proofs carry audience, timestamp and single-use nonce;
  revocations are signature-checked; a remote record cannot raise its own
  trust tier.
- DNS rebinding and SSRF bypasses closed in callbacks and the client.

### Changed
- Wire format: `session.init.client_ephemeral_key`,
  `session.established.server_ephemeral_key` (`binding_token` deprecated and
  never sent); new session-binding and delegation-link signature payloads;
  new federation proof and revoke payloads. See WIRE-BINDING §9, §11.11,
  §12 and PROTOCOL-CONTRACTS.
- `create_message_binding` / `verify_message_binding` require `body=`.
- `resolve_trust_tier` takes `sender_id`, `audience`, `sender_linked_dids`,
  `client_cert_identity`; DID auth without `audience` and `sender_id`
  resolves to EXTERNAL.
- The server binds to `127.0.0.1` by default; `--host` is honoured.
- `httpx` is now a runtime dependency.

## [0.3.4] - 2026-05-26

### Security
- **Adversarial-harness hardening.** Closed 23 exploits across identity,
  federation, replay protection, rate limiting, and stream/session
  management. Highlights:
  - `trust.resolver`: raw `did:key:` URIs without a signed JWT-style proof
    return `EXTERNAL` (previously `VERIFIED` with zero proof of possession).
    Transient resolver exceptions no longer negatively cache for 60 s.
  - `registry.federation`: `verify_federation_trust_proof` requires a
    host-registered `FederationTrustProofResolver` and fails closed by
    default. Remote tier claims can never escalate an agent above local
    tier; remote `last_seen` more than 60 s in the future is discarded.
    `RegistryFederationRequest.capabilities` capped (≤64 entries, ≤128
    chars, no control characters).
  - `security.rfc9421`: `alg` validated against an allow-list
    (`{ed25519}`); module-level default `NonceTracker` enforces replay
    protection even when callers forget to supply one. Nonceless
    signatures are rejected unless `max_age_seconds=None` is set
    explicitly.
  - `security.challenge`: `validate_challenge_solution` enforces
    `expires_at`; PoW `difficulty < MIN_POW_DIFFICULTY (8)` rejected;
    default captcha validator now fails closed.
  - `security.key_revocation`: canonical signature payload uses
    `model_dump(mode='json')` so extension fields are covered. The silent
    no-op default store is replaced with `_UnconfiguredRevocationStore`
    that logs a one-shot startup warning; `Strict…` and `AllowAll…`
    variants must be registered explicitly.
  - `session.binding`: empty `binding_token` rejected on both create and
    verify paths.
  - `session.handshake`: signed resume tokens carry an embedded `v: v1s`
    marker; stripped signatures and payload-rewrite attempts are
    rejected. Unsigned tokens are rejected by default
    (`allow_unsigned_resume_tokens(True)` opts in for tests/dev). Resume
    tokens capped at 64 KiB. `MAX_ISSUED_NONCES = 16` with TTL eviction.

### Changed
- **DoS amplifiers closed.** `NonceTracker`, `InMemoryDedupStore`,
  `RateLimiter` fail closed when full instead of evicting in-window
  entries. `RateLimiter` never displaces an active sender to admit a new
  one; per-sender timestamp list capped at `rpm`.
  `ConcurrencyLimiter` slots are TTL-leased (`slot_ttl_seconds=600`);
  forgotten releases no longer permanently hold a slot.
  `SenderTracker.record_success` drops the oldest failure instead of
  resetting the count.
  `streaming.bus` enforces per-task creator binding plus idle-stream LRU
  eviction; `streaming.checkpoint` rejects non-JSON-serializable values
  outright.
- **Hardened constructors.** `NonceTracker`, `InMemoryDedupStore`,
  `RateLimiter`, `ConcurrencyLimiter` reject non-positive bounds
  (`window` / `rpm` / `max`). `ConcurrencyLimiter.per_sender_pct` is
  floored so `per_sender_max ≥ 1`.

### Tests
- Test fixtures updated to encode the new hardened contracts (raw DID
  URIs return `EXTERNAL`; tier-claim hijack rejected; fail-closed
  trust-proof verification; PoW difficulty < 8 rejected; signed resume
  tokens by default). Full suite: 1185 passed.

## [0.3.3] - 2026-04-21

### Security
- **Replay protection in `verify_request`.** `ampro.security.rfc9421.verify_request`
  now enforces a `max_age_seconds` freshness window (default 300 s) against the
  signature's `created` timestamp and rejects stale or far-future signatures
  before performing any crypto work. Callers supplying a `NonceTracker` may
  additionally bind a `nonce` parameter into the signature via the new
  `nonce=` kwarg on `sign_request`; reused nonces fail closed. Previous
  behaviour (indefinite replay window) is reachable with
  `max_age_seconds=None` for fixture use only.
- **Revocation wired into `get_public_key`.** `ampro.trust.resolver.get_public_key`
  now calls `should_reject_cached_key()` on every invocation — cache hits
  included — so a revocation notice takes effect immediately rather than
  waiting for the 60 s TTL.
- New `docs/SECURITY-MODEL.md` documenting what the protocol does and does
  not guarantee, plus the host-platform checklist (trust anchoring, key
  storage, TLS, rate limits).

### Added
- Unified `ampro.errors` exception hierarchy (`AmpError` + `ValidationError` /
  `TrustError` / `CryptoError` / `SessionError` / `CompliancePolicyError` /
  `RateLimitError` / `TransportError` / `NotImplementedInProtocol`). Existing
  module-local exceptions re-parented to their category; public API unchanged.
- `ampro.trust.resolver.PublicKeyResolver` — pluggable key-resolution Protocol
  replacing the previous hardcoded HTTP path. Host platforms register a
  concrete resolver via `register_public_key_resolver()`.
- `AgentApp` + AMPI decorators — `@on` / `@tool` / `@middleware` /
  `@on_startup` / `@on_shutdown` / `@on_session_start` / `@on_error`.
  `AMPContext` with 26 fields + 12 methods; `TestServer` harness;
  `ampro-server` CLI. (Shipped in 0.3.0; now with full example coverage.)
- `ampro.security.encryption` — `EncryptionKeyOfferBody`,
  `EncryptionKeyAcceptBody`, `EncryptedBody.required_encryption` flag.
  Downgrade prevention via `SessionContext.session_requires_encryption` and
  `enforce_encryption_requirement()`.
- `ampro.security.key_revocation` — `KeyRevocationBroadcastBody`,
  pluggable `RevocationStore` registry, `should_reject_cached_key()`.
- `ampro.security.challenge` — `ChallengeType` enum + per-type validator
  dispatch (`proof_of_work`, `shared_secret`, `echo`, `captcha`) via
  `validate_challenge_solution()`; `register_challenge_validator()`.
- `ampro.streaming`:
  - `StreamingEvent.cross_channel_seq` for causal ordering across channels.
  - `MAX_SSE_EVENT_BYTES = 262_144` enforced in `to_sse()`.
  - `ChannelRegistry` + `MAX_CHANNELS_PER_SESSION = 16` with
    `ChannelQuotaExceededError`.
- `ampro.session.handshake` — `HandshakeTimeoutError` + `timeout_seconds`
  parameter (default 30s).
- `ampro.identity`:
  - `IdentityLinkProofBody.expires_at` + `is_link_proof_valid()`. Default
    lifetime 1 year.
  - `validate_migration_proof()` — dual-signature Ed25519 verification.
  - `register_cross_verification_policy(required: bool)` +
    `CrossVerificationRequiredError`.
- `ampro.transport.task_redirect`:
  - `TaskRedirectBody.visited_agents` (capped at 10) +
    `TaskRedirectBody.max_hops` (default 5, max 10).
  - `check_redirect_chain()` helper raising `RedirectLoopError`.
- `ampro.agent.schema`:
  - `MAX_MIGRATION_HOPS = 5` + `follow_migration_chain()` helper raising
    `MigrationChainTooLongError` on excessive hops or cycles.
  - `AgentMetadataInvalidateBody` (body type `agent.metadata_invalidate`)
    for push cache invalidation.
- `ampro.registry`:
  - `RegistryFederationRevokeBody` (body type `registry.federation_revoke`).
  - `RegistryFederationSyncBody` + `RegistryFederationSyncResponseBody`
    (body types `registry.federation_sync` / `…_response`) — pull-based
    delta sync with cursor pagination.
  - `resolve_federation_conflict(local, remote)` — trust-tier → recency →
    lexicographic agent-URI precedence.
  - `RegistrySearchRequest.cursor` + `limit` for cursor-based pagination;
    `max_results` retained as a read-only alias.
- `ampro.compliance`:
  - `TransferMechanism` enum (ADEQUACY / BCR / SCC / DEROGATION / NONE)
    + `AdequacyDecision` model + pluggable `AdequacyRegistry` +
    `check_cross_border_transfer()`.
  - `JurisdictionInfo.applicable_rules(data_region)` helper with
    primary-then-additional precedence.
  - `DataResidency.storage_regions` / `transit_regions` fields;
    `check_residency_violation()` now validates both at-rest and in-flight.
  - `ErasurePropagationStatusBody.retry_count` / `next_retry_at` /
    `last_error` / `final` with `compute_next_retry()` exponential-backoff
    helper.
  - `RetainedRecord` typed model (required `record_id`, `category`,
    `reason` Literal, `legal_basis`); `ErasureResponse.retained: list[RetainedRecord]`
    with legacy-`list[dict]` coercion for backwards compat.
- `ampro.core`:
  - `AgentMessage.sender` / `recipient` gain `max_length=512`.
  - `AgentMessage.headers` now `dict[str, str]` (RFC 7230 §3.2); non-string
    values rejected at validation time.
  - `AgentAddress.port: int | None` field.
  - `CostReceiptChain` tracks `self.currency`, rejects mixed-currency
    receipts, and uses `Decimal` arithmetic (`total_cost_usd: Decimal`;
    `total_cost_usd_float` property retained).
- `tests/vectors/README.md` indexing all 34 conformance vectors.
- `docs/PROTOCOL-CONTRACTS.md` — unified normative contracts doc covering
  error-handling strategy (tier model), schema-evolution policy, event
  ordering across channels, federation sync semantics, multi-jurisdiction
  precedence, and cache-invalidation push (closes the six documentation
  gaps previously tracked).

### Changed
- `parse_agent_uri` now supports IPv6 (`agent://[2001:db8::1]`), explicit
  ports (`agent://host:8443`), percent-encoding decode, NFKC/IDNA hostname
  normalization, and strict rejection of multiple `@` in the authority.
- `registry_resolve_url` enforces SSRF validation via
  `validate_attachment_url()` (previously advisory in docstring only).
- `check_version` rejects malformed semver strings up front.
- `negotiate_version` accepts an optional `fallback_version`; on no
  common version with a fallback provided, logs a warning and returns the
  fallback instead of raising.
- `Agent.clean()`-style matrix invariants retained; `AgentSuggestion` doc
  in `MASTER-CONTRACT.md` reconciled against the shipped schema.
- `HandshakeStateMachine` — `state` property now holds the lock on read
  (was already locked on transition); closes the re-audit follow-up.
- `InMemoryDedupStore` / `NonceTracker` — TTL-based eviction runs before
  LRU eviction so fresh entries are never discarded in favour of expired
  ones. Closes the replay window the v0.2.1 fix originally left open.
- `DataResidency.KNOWN_REGIONS` allowlist warns on unknown region codes
  without rejecting (forward-compat).

### Fixed
- Trust score clamps negative `age_days`, `interactions`, `endorsements`
  inputs (previously only `CLEAN_HISTORY` was floor-clamped).
- DID proof signature verification — the JWT-style DID proof path now
  verifies the EdDSA signature against the did:key-embedded Ed25519
  public key. Forged proofs fall back to `EXTERNAL`.
- `validate_message_body` raises `TypeError` on list/int/bool bodies
  (previously silently converted to `{}`) and now passes the sanitized
  body to the downstream validator.
- `ApiKeyStore` wraps `record_failure` / `is_blocked` / `reset_failures`
  with `threading.Lock`.
- `StreamAuthRefreshEvent.token` constrained to a URL-safe charset
  (`[A-Za-z0-9._-]`), 16-4096 chars; `method` restricted to a Literal
  whitelist.
- `CheckpointBody.state_snapshot` rejects payloads > 1 MiB.



## [0.3.2]

Not released — the version number was skipped.

## [0.3.1] — 2026-04-20

### Changed
- Documentation only. Added "reference implementation, not production-wired"
  banners to 14 submodules with zero first-party runtime callers but
  normative spec coverage. See
  `docs/superpowers/specs/2026-04-20-ws-d-ampro-shelfware-triage-design.md`
  for the per-module inventory and rationale.

  Affected modules:
  - `ampi.types`
  - `server.core`, `server.test`, `server.cli`, `server.__main__`
  - `registry.search`, `registry.federation`
  - `compliance.data_residency`, `compliance.jurisdiction`,
    `compliance.audit_attestation`, `compliance.erasure_propagation`
  - `transport.task_redirect`, `transport.task_revoke`,
    `transport.api_key_store`
  - `delegation.cost_receipt`
  - `security.rfc9421`, `security.circuit_breaker`

  No public API removed. No behaviour changed. No test removed.

## [0.3.0] — 2026-04-13

Introduces **AMPI — Agent Message Processing Interface**: an ASGI-for-agents framework for building AMP agents declaratively.

### Added
- **AMPI (Agent Message Processing Interface)** — ASGI for agents
  - `AgentApp` class with 8 decorators: `@on`, `@middleware`, `@tool`, `@on_startup`, `@on_shutdown`, `@on_session_start`, `@on_error`
  - `AMPContext` with 26 fields (trust, session, delegation, compliance, tracing) + 12 methods (send, discover, delegate, emit, audit)
  - `AMPError` hierarchy: `StreamLimitExceeded`, `BackpressureError`
  - `TestServer` — unit test harness for handler testing without transport
  - `ampro-server` CLI — `ampro-server main:agent --port 8000`
  - Type aliases: `HandlerFunc`, `MiddlewareFunc`, `AMPIServer` Protocol, `AMPIApp` TypedDict
  - Dict-based apps accepted alongside AgentApp
- `AgentServer.from_app(app)` — create server from AgentApp

### Changed
- Version bumped to 0.3.0
- `AgentServer` accepts AgentApp via `from_app()` classmethod

## [0.2.3] — 2026-04-16

### Security

Closed all 66 security findings (20 CRITICAL + 46 HIGH) from the 11-agent deep audit — Phase 0 sprint.

**Critical fixes (P0.C1 + P0.C2)**

- **C1**: Stream endpoint requires VERIFIED+ trust tier
- **C2**: Event subscription validates caller_id == subscriber
- **C3**: Stream validates caller owns job_id/session_id
- **C4**: Session.confirm replay protection via confirm_nonce
- **C5**: Binding token TLS requirement documented
- **C6**: Real did:key Ed25519 verification (multibase + multicodec)
- **C7**: Server-side PII detection overrides sender classification
- **C8**: Erasure requires owner authorization (is_authorized_to_erase)
- **C9**: MinorRegistry protocol (NoOp default, platform registers real impl)
- **C10**: Cost receipt mandatory Ed25519 signature verification
- **C11**: Registry slug validation (3-30 chars, lowercase alphanum+hyphens)
- **C12**: Federation trust_proof format validation (min 64 chars, base64)
- **C13**: StreamBus replay requires authorized_subscribers membership
- **C14**: Nonce store key: agent_id sanitized with strict regex
- **C15**: asyncio.Lock/threading.Lock on all 5 security modules
- **C16**: RateLimiter._evict_stale_senders enforces max_senders bound
- **C17**: consent_url SSRF: HTTPS-only + validate_attachment_url
- **C18**: Server levels 2-5 return 501 Not Implemented (not 404)
- **C19**: SSRF protection: octal, hex, IPv6-mapped, zone ID, percent-encoded
- **C20**: Delegation tests: real Ed25519 signatures, scope widening rejection

**High fixes (P0.D)**

- **1.4**: Audit log append-only storage (AuditStorage protocol)
- **1.5**: Attestation multi-party Ed25519 verification
- **1.6**: Jurisdiction from signed agent.json (not untrusted headers)
- **2.4**: JWT alg:none/HS256 rejection (ALLOWED_JWT_ALGS allowlist)
- **2.5**: TrustTier ordering (__lt__/__gt__) without breaking str serialization
- **2.6**: Clock skew tightened 60s → 30s
- **2.7**: Resume token HMAC-signed session state container
- **3.2**: Budget parsing fail-closed
- **3.3**: Delegation signature context binding (parent_delegate)
- **3.5**: Visited-agents URI normalization (case + whitespace)
- **3.6**: Scope wildcard prefix matching
- **3.7**: Trace context Ed25519 signing
- **4.5**: Timing-safe token comparison (hmac.compare_digest)
- **4.7**: Host-path whitelist on reference-server adapter
- **4.8**: Error response filtering by trust tier
- **5.2**: Rate limiter window boundary consistency
- **5.4**: Monotonic clock throughout security modules
- **5.5**: Stream seq server-assigned
- **5.6**: Body type empty/whitespace validation
- **5.7**: Field length limits on all body schemas
- **5.9**: Handler exception sanitization

**Infrastructure**

- **P0.E**: All error responses migrated to RFC 7807 ProblemDetail
- 976 protocol tests (was 457 at v0.2.1)
- 1597 runtime bridge tests passing

## [0.2.2] — 2026-04-10

### Added
- Reference server (`ampro/server/`) — minimal AMP agent in 10 lines
  - `AgentServer` class with `@server.on()` decorator pattern
  - Framework-agnostic `route()` method + FastAPI/Flask adapters
  - Auto-generated agent.json, health, SSE placeholder
  - RFC 7807 error responses on validation failure
- Client SDK (`ampro/client/`) — talk to any AMP agent
  - `send()` — one-shot message like httpx.post()
  - `discover()` — fetch agent capabilities
  - `stream()` — SSE streaming with reconnection
  - `connect()` — 3-phase handshake session with auto-binding
  - `AmpProtocolError` wrapping RFC 7807 responses
- 10 implementation guidance examples (31-40)
  - Server: simple, tools, auth, sessions, streaming
  - Client: send, handshake, streaming
  - Integration: two agents talking, delegation chain with costs

## [0.2.1] — 2026-04-10

### Security Fixes
- DID proof now fail-closed (returns EXTERNAL instead of VERIFIED without signature verification)
- Session binding rejects empty shared_secret
- HMAC nonce concatenation uses null byte delimiter to prevent collisions
- Key revocation now includes `validate_revocation_signature()` helper
- JWKS revocation check has defensive type validation
- Trust resolver logs at WARNING on failure (was DEBUG)
- API key validation uses constant-time comparison (hmac.compare_digest)
- Cross-verification did:key returns fail-closed until key extraction implemented
- Bearer token whitespace-only now correctly rejected
- DID base64 payload has length limit (10KB)
- RFC 9421 rejects URLs with newlines (signature base injection)
- IPv6 zone ID stripped before SSRF validation
- IPv6 loopback ::1 added to private hosts
- Empty hostname URLs now rejected
- Chain budget regex pre-compiled with non-backtracking pattern

### DoS Protection
- Dedup store bounded to 100K entries with LRU eviction
- Nonce tracker bounded to 100K entries with LRU eviction
- Rate limiter bounded to 100K senders with stale eviction
- Sender tracker bounded to 100K senders with eviction
- Stream bus bounded to 10K active streams
- Streaming queue bounded to 1K events (drops on overflow)
- Scope narrowing limited to 100 scopes per link
- Capability string parsing limited to 50 entries
- HandshakeStateMachine now thread-safe (threading.Lock)
- ApiKeyStore.is_blocked() race condition fixed (pop vs del)

### Code Quality
- Duplicate JurisdictionInfo renamed to ComplianceJurisdictionInfo in compliance/types.py
- TrustScore.tier validated against valid tier values
- TrustScore.factors validated (0-200 per factor)
- SessionConfig.max_messages capped at 10,000
- All 11 subpackage __init__.py files now re-export their contents with __all__
- Trust tier field descriptions updated across handshake and upgrade modules

## [0.2.0] — 2026-04-10

### Changed (BREAKING)
- **Package reorganized into subdirectories.** Modules moved from flat `ampro/*.py` into 11 subpackages: `core/`, `trust/`, `session/`, `identity/`, `delegation/`, `streaming/`, `security/`, `compliance/`, `registry/`, `agent/`, `transport/`
- Direct submodule imports (e.g. `from ampro.trust_score import ...`) must update to new paths (e.g. `from ampro.trust.score import ...`)
- **Public API unchanged.** `from ampro import X` still works for all 187 exports

### Migration Guide
| Old import | New import |
|------------|-----------|
| `from ampro.trust_score import ...` | `from ampro.trust.score import ...` |
| `from ampro.body_schemas import ...` | `from ampro.core.body_schemas import ...` |
| `from ampro.streaming import ...` | `from ampro.streaming.events import ...` |
| `from ampro.envelope import ...` | `from ampro.core.envelope import ...` |
| `from ampro import X` | `from ampro import X` (unchanged) |

See the full mapping in CONTRIBUTING.md.

## [0.1.9] — 2026-04-10

### Added
- `EncryptedBody` model + `CONTENT_ENCRYPTION_HEADER` — end-to-end JWE encryption
- `Content-Encryption` header
- `trust.proof` body type (`TrustProofBody`) — zero-knowledge trust proofs
- `CertificationLink` model + `certifications` array in `AgentJson`

### Changed
- Standard headers grew from 50 to 51
- Body type registry grew from 48 to 49
- Exports grew from 184 to 188

## [0.1.8] — 2026-04-10

### Added
- `identity.link_proof` body type — cryptographic proof two addresses are the same entity
- `registry.federation_request` / `registry.federation_response` body types — inter-registry trust
- `identity.migration` body type — agent address migration with proof
- `audit.attestation` body type — signed proof both parties agree on session events
- `moved_to` field on `AgentJson` — migration redirect pointer

### Changed
- Body type registry grew from 43 to 48
- Exports grew from 179 to 184

## [0.1.7] — 2026-04-09

### Added
- `StreamChannel` / `StreamChannelOpenEvent` / `StreamChannelCloseEvent` — stream multiplexing
- `StreamCheckpointEvent` — periodic state snapshots for reconnection
- `StreamAuthRefreshEvent` — mid-stream JWT renewal
- `Stream-Channel` header
- 4 new streaming event types (channel_open, channel_close, checkpoint, auth_refresh)

### Changed
- Standard headers grew from 49 to 50
- Streaming event types grew from 13 to 17
- Exports grew from 174 to 179+

## [0.1.6] — 2026-04-09

### Added
- `JurisdictionInfo` model + `validate_jurisdiction_code` + `check_jurisdiction_conflict` — cross-border jurisdiction declaration
- `Jurisdiction` + `Data-Residency` headers
- `erasure.propagation_status` body type — track erasure across delegation chains
- `data.consent_revoke` body type — revoke previously granted consent
- `DataResidency` model + `validate_residency_region` + `check_residency_violation`
- `ErasurePropagationStatus` enum (pending, completed, failed)
- `DataConsentRequestBody` + `DataConsentResponseBody` now exported from top-level

### Changed
- Standard headers grew from 47 to 49
- Body type registry grew from 41 to 43
- Exports grew from 163 to 174

## [0.1.5] — 2026-04-09

### Added
- `TraceContext` model + `generate_trace_id` / `generate_span_id` / `inject_trace_headers` / `extract_trace_context` — W3C Trace Context for delegation chains
- `task.revoke` body type (`TaskRevokeBody`) — revoke tasks with cascade and revoke_children flags
- `Priority` enum (batch, normal, priority, urgent, critical) — standardized priority levels
- `Trace-Id` + `Span-Id` headers

### Changed
- Standard headers grew from 45 to 47
- Body type registry grew from 40 to 41
- Exports grew from 156 to 163

## [0.1.4] — 2026-04-09

### Added
- `RegistrySearchRequest` / `RegistrySearchMatch` / `RegistrySearchResult` — structured service discovery
- `task.redirect` body type (`TaskRedirectBody`) — load-aware task redirection
- `X-Load-Level` header — agent load percentage (0-100)

### Changed
- Standard headers grew from 44 to 45
- Body type registry grew from 39 to 40
- Exports grew from 152 to 156

## [0.1.3] — 2026-04-09

### Added
- `agent.deactivation_notice` body type — orderly shutdown notification
- `AgentLifecycleStatus` enum (active, deactivating, decommissioned)
- `CostReceipt` + `CostReceiptChain` models — per-hop cost attribution in delegation chains
- `cost_receipt` field on `TaskCompleteBody`
- `Hop-Timeout` header — per-hop timeout declaration
- `status` field on `AgentJson` (active/deactivating/decommissioned)
- `status` + `gone` fields on `RegistryResolution` — 410 Gone support

### Changed
- Standard headers grew from 43 to 44
- Body type registry grew from 38 to 39
- Exports grew from 148 to 152+

## [0.1.2] — 2026-04-09

### Added
- `key.revocation` body type + `Key-Revoked-At` header — emergency key revocation broadcast
- `task.challenge` / `task.challenge_response` body types — anti-abuse challenge mechanism
- `tool.consent_request` / `tool.consent_grant` body types + `ToolDefinition` model — per-tool consent
- `stream.ack` / `stream.pause` / `stream.resume` streaming event types — backpressure flow control
- `trust.upgrade_request` / `trust.upgrade_response` body types — mid-conversation identity verification
- `Anonymous-Sender-Hint` header — pseudonymous rate limiting
- `previous_session_id` field on `SessionInitBody` — session resumption
- `resumed` field on `SessionEstablishedBody` — resumption status
- `RevocationReason` enum (key_compromise, key_rotation, agent_decommissioned)
- `ChallengeReason` enum (first_contact, suspicious_behavior, rate_limit_exceeded, trust_upgrade)
- 5 new test vector files, 4 new examples, 75 new tests

### Changed
- Standard headers grew from 41 to 43
- Streaming event types grew from 10 to 13
- Body type registry grew from 31 to 38
- Exports grew from 135 to 148+

## [0.1.1] — 2026-04-09

### Added
- 3-phase session handshake (session.init → session.established → session.confirm)
- 8 session body types: init, established, confirm, ping, pong, pause, resume, close
- HandshakeStateMachine with 8 states and validated transitions
- HMAC-SHA256 session binding (derive_binding_token, create/verify message binding)
- Trust scoring: 5-factor numeric score (0-1000) with tier mapping
- TrustPolicy: score-based rate limits and content filter policy
- Visibility control: 4 levels (public, authenticated, private, hidden)
- Contact policies: 5 levels (open, handshake_required, verified_only, delegation_only, explicit_invite)
- agent.json conditional filtering based on caller trust tier
- Context schema URN parsing and matching (urn:namespace:name:version)
- 6 new standard headers: Session-Binding, Trust-Score, Context-Schema, Transaction-Id, Correlation-Group, Commitment-Level
- AgentJson: visibility and supported_schemas fields
- 9 language-agnostic test vector files (tests/vectors/)
- 3 new examples: handshake, visibility, context schema

### Changed
- SessionState expanded from 4 to 8 states (added IDLE, INIT_SENT, INIT_RECEIVED, ESTABLISHED)
- Standard headers grew from 35 to 41
- Exports grew from ~108 to ~125+

## [0.1.0] — 2026-04-08

### Added
- `agent://` URI addressing with 3 forms (host, registry slug, DID)
- 23 body type schemas with Pydantic validation
- Multi-method authentication (JWT, DID, API key, mTLS)
- 4-tier trust resolution chain
- Ed25519 delegation chains with clock skew, fan-out, budget enforcement
- SSE streaming with heartbeat, sequencing, replay
- GDPR compliance (PII classification, audit hash-chain, erasure)
- Security: dedup, nonce, rate limiting, concurrency cap, poison message protection
- JWKS caching with key rotation and revocation
- Identifier cross-verification
- Capability negotiation with 8 groups, 6 levels
- Version negotiation with Accept-Version preference lists

### Changed
- Complete rewrite from v0.1.0 to match Agent OS Protocol spec
- `body_type` field added to AgentMessage (MUST per spec)
- 35 standard headers (was 15)
- 10 streaming event types (was 9, added heartbeat)
- `Visited-Spaces` renamed to `Visited-Agents`

### Removed
- `AgentCard` (replaced by `AgentJson`)
- `Endpoints` class (replaced by spec Section 9.5)
- `BodyStatus` enum (replaced by body type schemas)
