# Scaling ampro: many workers, many machines

An `AgentServer` keeps security-relevant state: replay caches, rate-limit
counters, deduplicated replies, A2A tasks, MCP sessions, PACT grants and
more. Every piece sits behind a small protocol with a **bounded in-memory
default**, and that default is right for a single process. Behind a load
balancer with several processes it is **wrong without any error**: each
worker keeps its own copy, so a replayed signature that reaches another
worker is accepted, and rate limits multiply by the number of workers.

`ampro.stores.redis` puts all of that state in Redis with one call:

```python
from ampro.server import AgentServer
from ampro.interop.a2a import A2AAdapter
from ampro.interop.mcp import MCPAdapter
from ampro.stores.redis import configure

server = AgentServer.from_app(agent, security=policy)
server.mount(A2AAdapter.for_server(server))
server.mount(MCPAdapter.for_server(server))
configure(server, url="redis://redis:6379/0", prefix="weather-agent")   # last
asgi_app = server.asgi()
```

or `ampro-server main:agent --protocols amp,a2a,mcp --store redis://redis:6379/0`
(`AMPRO_REDIS_URL` / `AMPRO_REDIS_PREFIX` work too). Install it with
`pip install 'ampro[redis]'`.

`configure()` replaces each **in-memory default** with its Redis version and
keeps your configured limits. Stores you plugged in yourself are left as they
are. Call it **after** mounting adapters and adding PACT Brands.

## Inventory

"Breaks" says what goes wrong with N per-process copies. **Redis** names the
shared implementation. `configure()` marks the ones that `configure()` wires
for you.

### Native AMP route and process-wide security state

| Component | Breaks if per-process | Interface | Redis |
|---|---|---|---|
| RFC 9421 nonce cache (`SignatureAuthenticator(nonce_tracker=)`, process default in `security.rfc9421`) | A signed request replayed to another worker is accepted. | `security.nonce_tracker.ReplayCache` (`is_replay`); `rfc9421.set_default_nonce_tracker()` | `RedisNonceTracker` (`SET NX PX`). `configure()` |
| DID-proof `jti` cache (`trust.resolver`) | A DID proof can be replayed once per worker. | `ReplayCache`; `resolver.set_did_proof_nonce_tracker()` | `RedisNonceTracker`. `configure()` |
| Rate limiter (`SecurityPolicy.rate_limiter`; also used by A2A, MCP, PACT) | The budget is N× the configured rpm. | `security.rate_limiter.RateLimiterBackend` (`check`) | `RedisRateLimiter` (Lua sliding window, Redis server clock). `configure()` |
| Concurrency limiter (`SecurityPolicy.concurrency`) | Capacity is N×, and so is the 50 % per-sender cap. | `security.concurrency_limiter.ConcurrencyBackend` | `RedisConcurrencyLimiter` (Lua leases with TTL, so a crashed worker can't leak slots). `configure()` |
| AMP response cache / dedup (`InMemoryResponseCache`) | A duplicate that reaches another worker runs the handler again, and two in-flight copies can both run. | `server.security.ResponseCache` (`reserve` / `complete` / `release`) | `RedisResponseCache` (`SET NX PX` in-flight mark plus a stored reply). `configure()` |
| Message dedup (`security.dedup`, library) | Same as above. | `security.dedup.DedupStore` | `RedisDedupStore` |
| Poison-message tracker (`security.sender_tracker`, library) | A sender spreads its failures across workers and never gets throttled. | `SenderTrackerBackend` | `RedisSenderTracker` (Lua) |
| Key revocation (`register_revocation_store`) | A revocation is never seen. The unconfigured default is permissive. | `security.key_revocation.RevocationStore` | `RedisRevocationStore` (`revoke()` / `unrevoke()`). `configure()` registers it when none is set |
| API-key allow-list (`register_api_key`) | Keys registered at startup are config and fine. Keys added at runtime exist on one worker only. | `trust.resolver.ApiKeyValidator` (`register_api_key_store`) | `RedisApiKeyValidator` (SHA-256 digests only). Wire it yourself |
| API-key brute-force blocks | An attacker gets N× the guesses. | `transport.api_key_store.ApiKeyFailureTracker`; `resolver.set_api_key_failure_tracker()` | `RedisApiKeyFailureTracker`. `configure()` |
| Federation `trust_proof` nonces (`registry.federation`) | A proof can be replayed to another registry worker. | `registry.federation.FederationNonceCache`; `register_federation_nonce_cache()` | `RedisFederationNonceCache`. `configure()` |
| Stream channel quota (`streaming.channel.ChannelRegistry`) | The per-session cap is N× when a session's connections land on several workers. | `ChannelRegistryBackend` | `RedisChannelRegistry` |
| Audit log (`compliance.audit_logger`) | Each worker builds its own hash chain. Before 0.4.0 the chain head was also cached per process, so loggers sharing one storage forked the chain. | `AuditStorage`, plus an optional `append_at(entry, seq) -> bool` compare-and-append | None: audit logs belong in durable append-only storage (a database or WORM bucket), not a cache. `AuditLogger` now chains from `storage.tail()` and retries on a lost `append_at`. |
| Public-key cache (`trust.resolver`, 60 s) | Nothing. It caches your resolver's answers, and revocation is checked before the cache. | — | Stays per-process on purpose |
| JWKS caches (`transport.jwks_cache`, PACT `JWKSCache`) | Nothing. These are caches of public keys. | — | Stays per-process on purpose |
| Circuit breaker, capability negotiation, heartbeat | Nothing. They describe this process's outbound connections. | — | Stays per-process on purpose |

### A2A adapter

| Component | Breaks if per-process | Interface | Redis |
|---|---|---|---|
| Tasks | Get, list and cancel on another worker return `TASK_NOT_FOUND`. | `a2a.store.TaskStore` | `RedisTaskStore` (hash per task, per-owner index, atomic owner check). `configure()` |
| Conversation contexts | A `contextId` issued by worker 1 is "unknown" on worker 2, or another caller can claim it there. | `ContextStore` | `RedisContextStore` (Lua claim). `configure()` |
| Idempotent replies `(contextId, messageId)` | A retry that lands on another worker runs the agent twice. | `IdempotencyStore` | `RedisIdempotencyStore` (`SET NX PX` in-flight mark). `configure()` |
| Live runs: subscribe fan-out, cancel, busy lock | `SubscribeToTask` on worker 2 gets only a snapshot. Cancel on worker 2 marks the task `CANCELED` but the handler keeps running on worker 1. Two input turns for one task can run at once. | `TaskBroker` (new; `InMemoryTaskBroker` default) | `RedisTaskBroker`: pub/sub per task, a cancel flag plus a control message, a liveness key with TTL, and a `SET NX PX` busy lock. `configure()` |

### MCP adapter

| Component | Breaks if per-process | Interface | Redis |
|---|---|---|---|
| Streamable HTTP sessions | `Mcp-Session-Id` from worker 1 gets 404 on worker 2, so clients re-initialize forever. | `mcp.server.SessionStore` | `RedisSessionStore` (idle TTL, absolute lifetime, per-caller LRU cap, global cap). `configure()` |
| Rate / concurrency limits | Same as the native route. | Shared from `SecurityPolicy` | `configure()` swaps the limiter references the adapter copied |

### PACT provider

| Component | Breaks if per-process | Interface | Redis |
|---|---|---|---|
| Device authorizations and user codes | A code approved on worker 1 is unknown when the PA polls worker 2. Redemption is not single-use. | `DeviceAuthorizationStore` | `RedisDeviceAuthorizationStore` (Lua compare-and-set `transition`). `configure()` |
| Grants | Revocation isn't seen everywhere. | `GrantStore` | `RedisGrantStore`. `configure()` |
| Refresh tokens | Rotation and **reuse detection** fail across workers. | `RefreshTokenStore` (`consume` = atomic mark-used) | `RedisRefreshTokenStore` (Lua). `configure()` |
| Consent sessions | The consent page and the decision POST can hit different workers. | `ConsentSessionStore` (`take` = single use) | `RedisConsentSessionStore` (`GETDEL`). `configure()` |
| PA-JWT `jti` replay store (optional) and Brand-login assertion nonces | Single use per worker only. | `NonceStore` | `RedisNonceStore`. `configure()` |
| Attempt limiters (user-code guesses, device starts, client) | N× brute-force budget. | `AttemptLimiter` | `RedisAttemptLimiter`. `configure()` |
| PACT contexts (ownership, §5.5 user binding) | Ownership and binding checks pass on a fresh worker. | `pact.stores.ContextStore` | `RedisPactContextStore`. `configure()` |
| Receipts (idempotent retries) | A retry on another worker gets a different receipt. | `ReceiptStore` (new) | `RedisReceiptStore`. `configure()` |
| Each Brand's A2A state | Same as the A2A rows. | `PACTProvider(a2a_stores=brand_id -> kwargs)` (new) | `configure()` sets the factory and patches existing Brands |
| Personal-agent registry | Startup registrations are config and fine. `set_enabled` / `remove` at runtime applies to one worker only. | `PersonalAgentRegistry` | `RedisPersonalAgentRegistry` (admin methods are `async`). Wire it yourself |
| **Provider signing keys** | `ProviderKeySet.generate()` creates a different key in each process, so tokens and receipts verify only on the worker that signed them. | Configuration: `ProviderKeySet.from_env()` (`PACT_PROVIDER_JWKS` / `_FILE`) | `configure()` **refuses** ephemeral keys (`ValueError`) unless `allow_ephemeral_keys=True` |

### State that is configuration, not shared state

Handlers, `agent.json`, `SecurityPolicy` knobs, allowed origins, the public-key
resolver, the PACT Brand list and RFC 9421 signing keys are loaded the same
way in every worker. Build them from code and environment, never at runtime
in one worker. Secrets such as `PACT_PROVIDER_JWKS`, resume-token HMAC keys
and API keys must be identical across the fleet.

## What still runs in one process, and why

- **A2A handler execution.** A message runs on the worker that received it,
  including `returnImmediately` background runs (an in-process `asyncio`
  task, at most `max_background_tasks` per worker). Other workers see the
  task in the store, stream its events through the broker, and can cancel
  it. If that worker **dies** mid-run, the task stays `WORKING` in the store.
  The liveness key expires after `live_ttl_seconds` (default 1 h, refreshed
  on every event), and subscribers on other workers then end their streams.
  Re-run or fail such tasks from your own job queue if you need
  at-least-once execution. A *graceful* shutdown does better (see below).
- **Event delivery is live-only.** Redis pub/sub delivers events published
  after a subscriber attached. The adapter subscribes *before* it reads the
  task, so nothing between the snapshot and the stream is lost. A client
  that disconnects simply resubscribes (A2A has no `Last-Event-ID` replay).
- **`streaming.StreamBus` ring buffer** (library primitive; the reference
  server's `/agent/stream` is a placeholder). SSE `Last-Event-ID` replay
  works only on the worker that holds the buffer. Use sticky routing for
  that endpoint if you build on it, or use A2A subscribe, which is shared.
- **Session handshake** (`session.handshake.HandshakeStateMachine`,
  `ClientHandshakeState`). These are per-connection objects held by the
  caller, and `AgentServer` does not serve the handshake. Keep a handshake
  on one connection, or persist the state in your own store. Resume tokens
  are HMAC-signed, so the HMAC key must be shared configuration. They are
  not single-use: replay is bounded by `max_age_seconds`.
- **`compliance.erasure.ErasureProcessor`** pending and completed maps.
  This is a helper the server does not wire, so persist requests in your
  own database.
- **Caches of public data** (public keys, JWKS, OIDC discovery). Keeping
  them per process is correct and cheap.

## Redis requirements and semantics

- Redis ≥ 6.2 (`GETDEL`; Lua uses `TIME`), on a single node or with Sentinel
  / a managed HA service. For **Redis Cluster**, use a hash-tag prefix such
  as `{weather-agent}`: the scripts touch several keys, so the keyspace must
  sit in one slot.
- Set **`maxmemory-policy noeviction`**. Under memory pressure an evicting
  policy would silently drop nonce and lease keys and reopen replay windows.
  Every key ampro writes has a TTL except explicit configuration
  (revocations, API keys, PA registrations), so memory stays bounded by
  traffic × TTL.
- Turn on persistence (AOF) if losing Redis must not log out delegated
  users. Grants and refresh tokens live there.
- Keys look like `{prefix}:{namespace}:{id}`. Caller-controlled ids that are
  long or contain separators are hashed. Values are JSON (never pickle) and
  size-checked: 1 MiB by default, 4 MiB for A2A tasks and replies. Use one
  prefix per agent deployment.
- **Failure is closed.** If Redis is unreachable, store calls raise and the
  request fails with a 5xx instead of skipping replay or rate-limit checks.
  `GET /agent/ready` returns 503 so the balancer drains the worker.
- The sync stores (replay cache, limiters) use the blocking `redis` client
  from the request path. Each call is one round trip, so keep Redis close
  (same AZ / VPC). The async stores use `redis.asyncio`.
- Run the ASGI binding (`server.asgi()`). The Flask adapter runs each
  request in a fresh event loop, which the async client does not support.

## Deployment

### Processes

```bash
# uvicorn: N worker processes, one import (and one configure()) per worker
uvicorn myagent:asgi_app --host 0.0.0.0 --port 8000 --workers 4 \
        --timeout-graceful-shutdown 30

# gunicorn + uvicorn workers
gunicorn myagent:asgi_app -k uvicorn.workers.UvicornWorker -w 4 \
         --bind 0.0.0.0:8000 --graceful-timeout 30
```

`myagent.py` builds the server, mounts adapters, calls `configure()` and
exposes `asgi_app = server.asgi()`. Redis connections open lazily inside each
worker, so `--preload` / fork is safe. Size `--workers` by CPU. The shared
limits are global, so adding workers does not raise any caller's budget.

### Health and readiness

| Endpoint | Meaning | Use as |
|---|---|---|
| `GET /agent/health` | The process is up and answering. It never touches dependencies. | Liveness probe |
| `GET /agent/ready` | 200 `{"status":"ready"}` when not draining **and** every `server.readiness_checks` passes (`configure()` adds a Redis `PING`). Otherwise 503 `{"status":"not_ready","reason":...}`. | Readiness probe / LB health check |

### Graceful shutdown

On ASGI `lifespan.shutdown`, `AgentServer.aclose(grace=10)`:

1. sets readiness to 503 (`draining`) so the balancer stops sending traffic;
2. calls `aclose(grace)` on every adapter. The A2A adapter waits up to
   `grace` seconds for `returnImmediately` runs, then cancels the rest,
   which records them as `CANCELED` in the shared store instead of leaving
   them `WORKING`;
3. runs `server.shutdown_callbacks` (`configure()` closes its Redis clients
   there), then the app's own `@on_shutdown` hooks.

Give the ASGI server a graceful timeout longer than `grace` so open SSE
streams can finish.

### Kubernetes

```yaml
spec:
  terminationGracePeriodSeconds: 45
  containers:
    - name: agent
      image: myagent:1.0
      command: ["ampro-server", "myagent:agent", "--host", "0.0.0.0",
                "--protocols", "amp,a2a,mcp"]
      env:
        - name: AMPRO_REDIS_URL
          valueFrom: {secretKeyRef: {name: agent-redis, key: url}}
        - name: AMPRO_REDIS_PREFIX
          value: "{weather-agent}"
        - name: PACT_PROVIDER_JWKS          # only for PACT providers
          valueFrom: {secretKeyRef: {name: pact-keys, key: jwks}}
      readinessProbe:
        httpGet: {path: /agent/ready, port: 8000}
        periodSeconds: 5
        failureThreshold: 2
      livenessProbe:
        httpGet: {path: /agent/health, port: 8000}
        periodSeconds: 10
      lifecycle:
        preStop:
          exec: {command: ["sleep", "5"]}   # let endpoints update before SIGTERM
```

Run any number of replicas behind a plain Service or Ingress. No sticky
sessions are needed. Keep clocks NTP-synced: JWT and signature freshness
checks use each node's wall clock, while rate limits and leases use Redis's
clock.
