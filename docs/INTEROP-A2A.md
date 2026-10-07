# A2A 1.0 interop

`ampro.interop.a2a` serves an AMP agent over Google A2A 1.0 and calls A2A
agents. It has no dependency on the official `a2a-sdk`. The test suite uses
the SDK (1.2.x) as a conformance oracle: its client talks to our server, and
its protobuf models parse our card and responses strictly.

```python
from ampro.server import AgentServer
from ampro.interop.a2a import A2AAdapter

server = AgentServer.from_app(app)
server.mount(A2AAdapter.for_server(server, public_url="https://agent.example"))
asgi = server.asgi()          # AMP and A2A from one process
```

`ampro-server module:app --protocols amp,a2a` mounts an adapter with the
default options. See `examples/46_a2a_agent.py` for a full example.

## Routes

`{base}` is `base_path`. It defaults to `/a2a` and can be nested, for example
`/a2a/{brandId}`. The interface URL in the card is `{public_url}{base}`.

| Method | Path | Operation |
|---|---|---|
| GET | `/.well-known/agent-card.json` (unless `serve_root_card=False`) | Agent card, no auth |
| GET | `{base}/.well-known/agent-card.json` | Agent card, no auth |
| POST | `{base}` | JSON-RPC 2.0: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, push-config methods, `GetExtendedAgentCard` |
| POST | `{base}/message:send` | SendMessage |
| POST | `{base}/message:stream` | SendStreamingMessage (SSE) |
| GET | `{base}/tasks` | ListTasks (`pageSize` 1–100, default 50) |
| GET | `{base}/tasks/{id}` | GetTask (`historyLength`) |
| POST | `{base}/tasks/{id}:cancel` | CancelTask |
| GET, POST | `{base}/tasks/{id}:subscribe` | SubscribeToTask (SSE) |
| any | `{base}/tasks/{id}/pushNotificationConfigs[/{cfg}]` | `PUSH_NOTIFICATION_NOT_SUPPORTED` |
| GET | `{base}/extendedAgentCard` | `EXTENDED_AGENT_CARD_NOT_CONFIGURED` |

* Any other path under `{base}` returns `404`. A known path called with the wrong
  method returns `405` with `Allow`. Neither has a body. Paths outside `{base}`
  fall through to the AMP routes.
* The order of checks is: route, then authentication, then rate and concurrency
  limits, then body parsing.
* The `A2A-Version` header is optional. A major version other than `1` gets
  `VERSION_NOT_SUPPORTED`.
* Request bodies may be sent as `application/json` or `application/a2a+json`.
  HTTP+JSON responses use `application/a2a+json`, JSON-RPC responses use
  `application/json`, and streams use `text/event-stream`.
* Errors on the HTTP+JSON binding use the AIP-193 envelope
  `{"error": {"code", "status", "message", "details": [ErrorInfo]}}`. The
  reason is in `details[0].reason` and the domain is `a2a-protocol.org`.
  JSON-RPC errors use the SDK codes (`-32001` TASK_NOT_FOUND …
  `-32009` VERSION_NOT_SUPPORTED), with `data` set to `[ErrorInfo]`.
* Handler exceptions are logged server-side together with the request id
  (`X-Request-Id` or a minted one). The client only receives `INTERNAL_ERROR`.

## Mapping

### Inbound: A2A to AMP

| A2A | AMP |
|---|---|
| Message without `taskId` | `task.create` with `{description: text[:8192], text, task_id: <minted>, data?, attachments?}`. If the app has no `task.create` handler but has a `message` handler, the message goes to `message` instead. |
| Message whose `taskId` names an `INPUT_REQUIRED` or `AUTH_REQUIRED` task | `task.response` with `{task_id, text, data?, attachments?}` |
| text parts | joined with `\n` into `text` |
| data parts | `body["data"]`: a single object part as-is, otherwise `{"parts": [...]}` |
| url and raw parts | `body["attachments"]` entries `{url\|raw, filename?, media_type?}` |
| `messageId` | `AgentMessage.id` |
| `contextId` | `headers["Session-Id"]` |
| principal id (`a2a://anonymous` if none) | `sender` |
| raw `Message` and `SendMessageRequest` | `ctx.metadata["a2a.message"]`, `ctx.metadata["a2a.request"]` |
| — | `ctx.protocol == "a2a"`, plus `ctx.principal`, `ctx.scopes`, `ctx.trust_tier` |

### Outbound: handler result to A2A

| Handler returns | A2A reply |
|---|---|
| `str` | `Message` (role agent) with a text part |
| `dict`, `list` or `BaseModel` | `Message` with a data part |
| `task.response` or `message` body | `Message` with text and data parts |
| `task.complete` | `Task` `COMPLETED`, with an artifact holding `result` and `attachments` |
| `task.input_required` | `Task` `INPUT_REQUIRED`. The status message is `prompt`, with `options` as a data part. |
| `task.error` | `Task` `FAILED`. The status message is `detail` or `reason`. |
| `task.reject` | `Task` `REJECTED` |
| `task.acknowledge` or `task.progress` | `Task` `WORKING`. The task is stored and the client polls it. |
| `raise AuthRequired(scopes, uri)` | `Task` `AUTH_REQUIRED`. The metadata holds the missing scopes and the verification URI. |
| `AMPError` | `Task` `FAILED` (`no_handler` maps to `UNSUPPORTED_OPERATION` instead) |
| any other exception | `INTERNAL_ERROR` |
| handler timeout | `Task` `FAILED` with "The agent did not respond in time." |

A result counts as AMP-shaped when it is an `AgentMessage`, or a `dict` with
a `body_type` key. In the dict case the body is the `body` key, or else the
remaining keys. When the inbound message continued a task, a plain result
completes that task and becomes an artifact. Every Task is stored, including
terminal ones, so `GetTask` and `ListTasks` can find it.

`AuthRequired` metadata keys are set by `auth_required_keys`. The default
is `missingScopes` / `verificationUriComplete`. The PACT profile uses
`PACT_AUTH_KEYS`, which is `pact.missingScopes` / `pact.verificationUriComplete`.
`AuthRequired` skips the app's `@on_error` hook.

### Streaming

On `message:stream`, `ctx.emit()` and `ctx.emit_event()` send events into
the SSE stream:

| Handler emits | A2A event |
|---|---|
| first event | a `task` event in `WORKING`, sent before it |
| `text_delta` | `artifactUpdate` on the `response` artifact (`append` from the 2nd chunk on) |
| other `StreamingEvent` types | `statusUpdate` `WORKING`, with a data part `{type, ...data}` and metadata `amp.event` |
| `emit_event(topic, data)` | `statusUpdate` `WORKING`, with a data part `{topic, data}` |
| A2A `TaskStatusUpdateEvent` or `TaskArtifactUpdateEvent` | passed through unchanged |
| heartbeat or stream-control events | dropped |
| handler returns | new artifacts, then a final `statusUpdate` |

A handler that emits nothing produces a single `message` or `task` event. A
streaming handler that returns an async iterator of `StreamingEvent` gets
the same mapping, and the `result` of its `done` event becomes the final result.

Limits on streams:

* The queue is bounded at 256 events. When it is full, `emit` waits.
* An event larger than 256 KiB raises `StreamLimitExceeded`.
* When the client disconnects, the handler is cancelled.

`configuration.returnImmediately` returns a `WORKING` task at once and runs
the handler in the background. The task can be polled, subscribed to, or
cancelled while it runs.

Background runs count against the server's concurrency limit until they
finish, not just until the response is sent. At most `max_background_tasks`
runs (default 100) exist at once; beyond that the caller gets `503` with no body.

## Authentication hook

The adapter uses the server-wide contract in `ampro.server.auth`, re-exported
from `ampro.interop.a2a`:

```python
class Authenticator(Protocol):
    async def authenticate(self, request: HTTPRequest) -> Principal | None: ...

Principal(id, trust_tier, scopes: frozenset[str], claims: dict, auth_method)
```

* Authenticators are tried in order, and the first principal returned wins.
* Returning `None` means the authenticator does not recognise the credential,
  and the next one is tried.
* Raising `Unauthorized` returns `401` with
  `WWW-Authenticate: Bearer realm="a2a"` and no body. `InvalidToken` adds
  `error="invalid_token"` to that header.
* When no authenticator claims the request, the caller is `ANONYMOUS` at the
  `EXTERNAL` tier. With `require_auth=True` the caller gets `401` instead.
* `authenticators`, `require_auth` and the handler timeout default to
  `server.security`.
* `server.security.rate_limiter` and `server.security.concurrency` also apply
  to A2A. They are keyed by principal id, or by `ip:<peer>` for anonymous
  callers. Over the limit, the caller gets `429` with `Retry-After`, or `503`.
  Neither has a body.

The principal fills in the `AMPContext` fields `sender_address`, `trust_tier`,
`scopes`, `auth_method` and `principal`.

## Contexts, tasks and idempotency

* Without a `contextId`, the server mints an opaque one. Each context belongs
  to the principal that created it.
* A context id that belongs to another principal, or that the server never
  issued, gets `INVALID_PARAMS`. The error does not say whether the context
  exists. Set `accept_unknown_contexts=True` to let clients choose their own
  context ids.
* A closed context gets `UNSUPPORTED_OPERATION`. A context is closed by
  `ctx.close_session()` in a handler or by `adapter.close_context(id)`.
* Tasks are scoped to their principal. Another principal gets `TASK_NOT_FOUND`.
  Anonymous callers share one identity, so `ListTasks` always returns an empty
  list for them.
* If the same `messageId` is sent again in the same context, the stored reply
  is returned and the handler is not run again. While the first copy is still
  in flight, the retry gets `INVALID_PARAMS`.
* Each kind of state has its own protocol so a shared store can replace it:
  `TaskStore`, `ContextStore` and `IdempotencyStore`. The defaults are bounded
  LRU+TTL in-memory stores. Pass replacements as `task_store=`,
  `context_store=` and `idempotency_store=`.
* Input limits:
  * `max_parts` (64)
  * `max_text_chars` (65 536)
  * `max_metadata_bytes` (16 KiB)
  * the server's `max_message_bytes` for the whole body
* `input_modes=TEXT_MODES` rejects data and file parts with
  `CONTENT_TYPE_NOT_SUPPORTED`.

## AMP extension

* URI: `https://github.com/agentmeshpro/agent-mesh-protocol/ext/amp/v1`
* The card lists it with `required: false` and these params:
  `agent_id`, `amp_endpoint`, `protocol_version`.
* A client activates it with `A2A-Extensions: <uri>`. The server echoes
  activated extensions in the response `A2A-Extensions` header.
* While the extension is active, the object found at `metadata[<uri>]` (or at
  `metadata["amp"]`) on the request or message is read into `AMPContext`:

  | metadata key | AMPContext |
  |---|---|
  | `delegationChain` (list of links or `{links}`, at most 50) | `delegation_chain`, **only** after the adapter's `chain_verifier` accepts it (see [Delegation chains](#delegation-chains)). Without a verifier it is `metadata["amp.unverifiedDelegationChain"]` only and `delegation_chain` stays `None`. |
  | `jurisdiction`, `dataResidency` | `jurisdiction`, `data_residency` |
  | `traceId` | `trace_id`. Must equal the `traceparent` trace-id when both are sent. |
  | `spanId` | `metadata["amp.parentSpanId"]` and `parent_span_id`. Must equal the `traceparent` parent-id when both are sent. |
  | `transactionId`, `correlationGroup`, `priority`, `remainingBudget`, `visitedAgents` | fields of the same name. The `visitedAgents` count is also a floor for `hop_count`. |
  | `sender` | `metadata["amp.claimedSender"]` only. Identity always comes from authentication. |

* Replies carry `metadata[<uri>]` with these fields:
  * `agentId`, `protocolVersion`, `traceId`, `spanId`
  * `jurisdiction`, when set
  * `costReceipt`, `costUsd` and `durationSeconds`, when the handler returned
    them in `task.complete`
* The `amp_metadata_key` adapter option changes the key name.

## Trace context and hop count

AMP's loop detection (`Visited-Agents`) and trace ids live inside the AMP
envelope. To keep them across protocol boundaries (AMP → A2A → MCP → AMP)
every adapter and client also carries [W3C Trace Context](https://www.w3.org/TR/trace-context/)
and a hop count, whether or not the AMP extension is active
(`ampro.interop.propagation`):

| A2A carrier | AMPContext | Notes |
|---|---|---|
| `traceparent` HTTP header, or `metadata["traceparent"]` on the request / message | `trace_id`, `parent_span_id` (+ `metadata["amp.parentSpanId"]`); a new `span_id` is minted | Strict W3C parsing: version `00` is exactly `00-<32 hex>-<16 hex>-<2 hex>`, lowercase, non-zero ids; `ff` is invalid; a higher version is read per the spec's forward-compatibility rule. Anything else is `INVALID_PARAMS`. Several sources must agree exactly. |
| `tracestate` HTTP header / `metadata["tracestate"]` | `trace_state` | Read only with a valid `traceparent`. W3C key/value grammar, at most 32 members, no duplicate keys, otherwise `INVALID_PARAMS`; truncated to 512 characters by dropping whole members (long ones first). |
| `AMP-Hop-Count` HTTP header, `metadata["amp.hopCount"]` | `hop_count` | 1–4 ASCII digits / a non-negative integer. The **largest** of these and the `visitedAgents` count is used; above `max_hops` the request is rejected with `INVALID_PARAMS` "Hop limit exceeded" before any state changes. |

* `max_hops` (adapter option) defaults to `server.security.max_visited_agents`
  (20), the same limit as `Visited-Agents`.
* The handler runs inside its span: `A2AClient`, `MCPToolSource`, `PACTClient`
  and the native AMP client called from it send `traceparent` (this hop's
  span as parent-id), the `tracestate` received, and `AMP-Hop-Count:
  hop_count + 1`. `A2AClient` also stamps `metadata["amp.hopCount"]` on
  messages (never lowering a larger value the caller set).
* A client refuses to send (`HopLimitExceeded`) when the next hop would
  exceed the smaller of its own `max_hops` and the inbound limit. Outside any
  handler a client starts a new trace at hop 1.
* When `send_message(amp={"traceId": ..., "spanId": ...})` names ids, the
  `traceparent` is built from them so the two never disagree; ids that are
  not W3C-shaped suppress the `traceparent` (the hop count is still sent).

## Delegation chains

A delegation chain received in the AMP extension is a claim made by the
caller. The adapter treats it the way it treats a claimed `sender`: it never
becomes authority unless you verify it.

```python
from ampro.delegation.chain import validate_chain
from ampro.interop.a2a import A2AAdapter

PUBLIC_KEYS: dict[str, bytes] = load_delegator_keys()   # agent id -> Ed25519 key

async def verify_chain(chain, ctx):
    ok, reason = validate_chain(chain, PUBLIC_KEYS)
    if ok and chain.links[-1].delegate != ctx.agent_address:
        return False, "chain is not delegated to this agent"
    return ok, reason

adapter = A2AAdapter.for_server(server, chain_verifier=verify_chain)
```

* `chain_verifier` is a `ChainVerifier`:
  `async (DelegationChain, AMPContext) -> (ok: bool, reason: str)`.
* Accepted (`(True, ...)`): the chain becomes `ctx.delegation_chain`.
* Rejected — `(False, ...)`, an exception, a non-`(bool, str)` result, or no
  answer within `chain_verifier_timeout` (10 s): the request fails with
  `INVALID_PARAMS` and the generic message "Delegation chain rejected"
  before the handler runs. The reason is logged, never returned.
* No verifier configured: `ctx.delegation_chain` stays `None` and the parsed
  chain is available only as `ctx.metadata["amp.unverifiedDelegationChain"]`
  (the copy in `ctx.metadata["amp.extension"]` has the chain removed).
* A malformed chain, or one with more than 50 links, is `INVALID_PARAMS`
  before the verifier is called.

## Client

```python
async with A2AClient("https://agent.example", auth="<token>") as client:
    reply = await client.send_message("hi", amp={"jurisdiction": "EU"})
    async for event in client.stream_message("go"): ...
    await client.get_task(task_id); await client.cancel_task(task_id)
    await client.list_tasks(pageSize=10)
kind = await discover_protocol("https://agent.example")   # "amp" or "a2a"
```

* The client picks an interface by binding and version, not by its position
  in the card: HTTP+JSON 1.x first, then JSON-RPC 1.x.
* Every request has a timeout.
* Redirects are followed only within the same origin, up to 3.
* Responses, SSE events and each buffered SSE line (comment lines
  included) are capped by `max_response_bytes`.
* A streaming call must finish within `stream_timeout` (default 300 s).
* `auth` is sent only to interfaces on the same origin as the fetched card
  URL, or to origins listed in `trusted_origins`. A card passed in directly
  is trusted as given.
* When the client creates its own HTTP connection, each URL is checked with
  `ampro.security.ssrf.validate_url_async`, and the connection is pinned to the
  validated addresses. Only HTTPS and public addresses are allowed unless you
  pass `allow_http` or `allow_private`. With an injected `http_client`, only
  the `url_validator` you supply is applied.
* `discover_protocol` prefers AMP when a server offers both protocols.

## Differences from the SDK and from PACT

* **Internal error reason:** the SDK uses `INTERNAL_ERROR` and PACT's table
  says `INTERNAL`. We follow the SDK.
* **Content type of REST errors:** the SDK sends `application/json`. We send
  `application/a2a+json`, which is what PACT requires; SDK clients ignore the
  difference.
* **Missing `A2A-Version`:** the SDK server treats it as 0.3 and rejects the
  request. We accept it as 1.0, because PACT only says clients SHOULD send it.
* **Unparseable JSON on HTTP+JSON:** we return `INVALID_REQUEST`, as the SDK
  does. PACT lists bad JSON under `INVALID_PARAMS`. Schema violations get
  `INVALID_PARAMS` on both bindings.
* **Unknown `contextId`:** the SDK accepts any client-chosen id. We follow PACT
  and return `INVALID_PARAMS` by default; see `accept_unknown_contexts`.
* **Card shape:** the SDK adds v0.3 compatibility fields (`url`,
  `preferredTransport`, …) to the cards it serves. We emit only the 1.0 shape,
  and the SDK parses it.
* **`ErrorInfo.metadata`:** values are sent as strings, since the proto type is
  `map<string,string>`.

## Limitations

* The gRPC binding, push notifications, the extended agent card, signed cards
  and tenant path segments are not supported.
* Streaming state and subscriptions live in one process. Use a sticky load
  balancer, or accept that `SubscribeToTask` on another worker returns only
  the current task snapshot.
* On the AMP side, cancelling a task only cancels the running handler; there
  is no `task.cancel` handler hook.
* Delegation chains are verified only by the `chain_verifier` you supply; the
  adapter ships no default key source. Without one, chains are never exposed
  as `ctx.delegation_chain`.
* Trace context is read on `SendMessage` / `SendStreamingMessage` only (the
  requests that run a handler); other operations ignore it.
