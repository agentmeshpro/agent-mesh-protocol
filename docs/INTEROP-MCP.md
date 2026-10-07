# MCP interop

`ampro.interop.mcp` connects AMP agents to the
[Model Context Protocol](https://modelcontextprotocol.io) in both directions:

* **Serve:** `MCPAdapter` publishes an AMPI agent's `@agent.tool` functions as MCP
  tools over Streamable HTTP. It also publishes the agent's `task.create` handler
  as one extra tool, `amp_task`. MCP hosts such as Claude Code, Claude Desktop and
  Cursor can then call any AMP agent.
* **Consume:** `MCPToolSource` connects to a remote MCP server and registers its
  tools into an `AgentApp`. AMPI handlers call those tools like local ones, and
  an `MCPAdapter` on the same agent can publish them again.

The server and client are implemented natively. The official `mcp` SDK is not a
runtime dependency. The test suite uses it as a conformance oracle (its
`Client` in `legacy`, `auto` and `2026-07-28` modes against our ASGI app and a
real uvicorn socket, and our client against its `MCPServer`).

## Quick start

```python
from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext

agent = AgentApp("agent://travel.example.com", "http://127.0.0.1:8000/agent/message")

@agent.tool("fare_quote")
async def fare_quote(origin: str, destination: str, passengers: int = 1,
                     ctx: AMPContext | None = None) -> dict:
    """Quote an economy fare in EUR between two IATA airport codes."""
    ...

@agent.on("task.create")
async def plan(msg, ctx):
    """Plan a short trip from a natural-language request."""
    ...
```

```bash
ampro-server agent:agent --protocols amp,mcp --port 8000   # MCP at http://127.0.0.1:8000/mcp
```

Or mount the adapter yourself:

```python
from ampro.server import AgentServer
from ampro.interop.mcp import MCPAdapter

server = AgentServer.from_app(agent)
server.mount(MCPAdapter.for_server(server))       # path="/mcp" by default
asgi_app = server.asgi()                          # any ASGI server
```

To run everything in one process without sockets, see
`examples/47_mcp_tools.py`.

### Connecting MCP hosts

**Claude Code:**

```bash
claude mcp add --transport http travel http://127.0.0.1:8000/mcp
# with auth:
claude mcp add --transport http travel https://agent.example.com/mcp \
    --header "Authorization: Bearer $TOKEN"
```

You can also put the server in a project `.mcp.json`:

```json
{ "mcpServers": { "travel": { "type": "http", "url": "http://127.0.0.1:8000/mcp" } } }
```

**Claude Desktop:** to add a remote server, open *Settings → Connectors* and add
its URL. A local `http://127.0.0.1` server can instead be bridged through stdio in
`claude_desktop_config.json`:

```json
{ "mcpServers": { "travel": { "command": "npx", "args": ["mcp-remote", "http://127.0.0.1:8000/mcp"] } } }
```

**Cursor:** add `{"mcpServers": {"travel": {"url": "http://127.0.0.1:8000/mcp"}}}`
to `~/.cursor/mcp.json`.

## Protocol revisions

| Era | Revisions | Selected by | Session |
|---|---|---|---|
| Handshake | `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25` (latest) | `initialize` (no or handshake `MCP-Protocol-Version` header) | `Mcp-Session-Id` |
| Modern | `2026-07-28` | `MCP-Protocol-Version: 2026-07-28` header | stateless |

These match the registry in the official SDK (`mcp_types.version`).

* **Handshake era.** `initialize` echoes a supported `protocolVersion`, or offers
  `2025-11-25` in its place. The server returns a 256-bit `Mcp-Session-Id`, and
  every later request must send it. A missing ID gets `400`. An unknown,
  expired or foreign ID gets `404`, and the client must re-initialize. If an
  `MCP-Protocol-Version` header is sent, it must equal the negotiated version.
  A request without the header is accepted. JSON-RPC batches are accepted only
  on `2025-03-26` sessions, and `initialize` may never be batched.
* **Modern era.** No handshake and no sessions. `server/discover` advertises
  `supportedVersions`. Every request carries `params._meta` with
  `io.modelcontextprotocol/protocolVersion` and `…/clientCapabilities`. The
  `MCP-Protocol-Version`, `Mcp-Method` and (for `tools/call`) `Mcp-Name` headers
  must match the body (base64 `=?base64?…?=` values are decoded). The checks run
  in order and the first failure is returned: `-32602` for a missing envelope,
  `-32020` for a header mismatch, `-32022` for an unsupported version (with
  `data.supported`). Results carry `resultType`, and `tools/list` / discover
  results also carry `ttlMs: 0` and `cacheScope: "private"`. `serverInfo` is
  stamped in `result._meta`. Errors use the spec's HTTP statuses: `400`, or
  `404` for `-32601`.

## Routes

Everything is served from the adapter's single path (default `/mcp`). Other
paths fall through to the native AMP routes.

| Method | Behaviour |
|---|---|
| `POST` | One JSON-RPC message, or a batch on 2025-03-26 sessions. Requests get `200 application/json`; notifications and responses get `202`. |
| `GET` | `405` with an `Allow` header. The server never opens a server-initiated SSE stream, and the spec makes that stream optional. |
| `DELETE` | Ends the session (`200`). Unknown or foreign sessions get `404`. Modern-era requests get `405`. |

`POST` must accept `application/json` (otherwise `406`) and send
`Content-Type: application/json` (otherwise `415`). Responses are always JSON,
which the spec allows in place of SSE.

Supported methods: `initialize`, `notifications/initialized`, `ping` (handshake
era), `server/discover` (modern), `tools/list`, `tools/call`. Any other method
returns `-32601`.

## Mapping

| AMP | MCP |
|---|---|
| `app.tools[name]` | tool `name` |
| docstring, or `@tool(description=...)` | `description` |
| signature and type hints (pydantic), or `@tool(input_schema=...)` | `inputSchema` (`additionalProperties: false` unless the function takes `**kwargs`) |
| parameter named `ctx` / annotated `AMPContext` | not in the schema; receives an `AMPContext` with `protocol == "mcp"`, the caller's trust tier, and `sender_address` = principal id |
| `@tool(scopes=[...])` | tool listed and callable only by principals holding every scope |
| return `dict` / pydantic model | `structuredContent` + the same JSON as a text block |
| return `str` | one text block |
| return other JSON (list, number, ...) | JSON text block |
| tool raises | `isError: true`, generic text with a reference id |
| bad arguments | `isError: true`, naming only the offending fields |
| unknown tool | JSON-RPC `-32602` |
| `traceparent` / `tracestate` HTTP headers | `AMPContext.trace_id`, `parent_span_id`, `trace_state` (new `span_id` per request). Strict W3C parsing; malformed values get `400` JSON-RPC `-32600` before the body is read. |
| `AMP-Hop-Count` HTTP header | `AMPContext.hop_count`; above `max_hops` (default `security.max_visited_agents`, 20) the request gets `400` "Hop limit exceeded". Tools run inside the request's span, so clients they call send `hop_count + 1`. |
| `task.create` handler | tool `amp_task` (`description`, `context`, `priority`, `task_id`, `timeout_seconds`). It is dispatched as an AMP `task.create` `AgentMessage` through `ampro.ampi.dispatch.dispatch`, so app middleware and `@on_error` run. |

`amp_task` can be turned off with `expose_tasks=False`. Scopes can be set on it
through `app.tool_meta["amp_task"] = {"scopes": [...]}`. On a plain
`AgentServer` without an app, its `@server.on("task.create")` handler is used.

Arguments are validated strictly in JSON mode before the function runs. Strings
are never coerced to numbers and floats are never truncated, while JSON
encodings of dates, UUIDs and enums are accepted. An explicit `input_schema` is
what gets published. Its `required` list is enforced, and the signature model
still checks the types.

## Security

The MCP transport spec makes Origin validation mandatory. It also exposes tools
that can act, so the adapter is strict by default.

* **Origin (DNS rebinding).** Each request's `Origin` is checked first. A
  missing Origin is allowed, because non-browser clients do not send one. By
  default only `http(s)://localhost`, `127.0.0.1` and `[::1]` origins pass, on
  any port. `allowed_origins=[...]` replaces that list. It accepts exact
  origins, `"http://host:*"` port wildcards, or `"*"`. A rejected Origin gets
  `403`.
* **Authentication.** The adapter uses the server-wide contract in
  `ampro.server.auth`. `authenticators=[...]` takes `Authenticator` objects:
  each returns a `Principal`, returns `None` when it has no credential, or
  raises `Unauthorized`. The first principal wins. A rejected or crashing
  authenticator gets `401` with `WWW-Authenticate: Bearer realm="mcp",
  error="invalid_token"`, so the adapter fails closed. With
  `require_auth=True`, anonymous requests also get `401`. A simple
  `authenticator=async (request) -> principal | None` callable is accepted
  too; any exception it raises counts as a rejection. Principals may be
  `ampro.server.auth.Principal`, dicts, or objects with `id`, `scopes` and
  `trust_tier`.
* **`for_server` inherits the server's `SecurityPolicy`.** Unless you pass your
  own values, it takes `authenticators`, `require_auth`, `rate_limiter`,
  `concurrency` and `handler_timeout_seconds`. MCP callers therefore pass the same gate as
  native AMP callers. For example, `SecurityPolicy.production([...])` turns on
  required authentication for MCP too.
* **Recommendation.** With no authenticators, any process that can reach the
  port can call every unscoped tool. That is acceptable on the default
  loopback bind, and the adapter logs a reminder. **Before binding beyond
  `127.0.0.1` (`--host 0.0.0.0`, containers, reverse proxies), configure
  authenticators and `require_auth=True`**, and set `allowed_origins` to the
  web origins you expect.
* **Scopes.** A tool with `scopes` is hidden from `tools/list` unless the
  principal holds every scope. Calling it without them gets `403` with
  `WWW-Authenticate: …error="insufficient_scope", scope="…"`, or `401` for an
  anonymous caller when authenticators are configured. With no authenticators
  configured, scoped tools are unusable: the adapter fails closed.
* **Sessions.** Session IDs come from `secrets.token_hex(32)`. Each session is
  bound to the principal that created it, and any other caller, including an
  anonymous one, gets the same `404` as for an unknown ID. Sessions live in a
  `SessionStore`, an async protocol (`create` / `get` / `save` / `delete`).
  The default `InMemorySessionStore` holds at most 1024 sessions, with a 1-hour
  idle timeout and a 24-hour maximum lifetime. Each caller (principal ID, or
  `ip:<client>` when anonymous) may hold at most `max_sessions_per_owner`
  sessions (default 8). Opening another evicts that caller's least recently
  used session, whose client then re-initializes, so no single caller can fill
  the store. When the store is full anyway, it purges expired sessions, then
  refuses new ones with `503` instead of evicting other callers' live
  sessions. `initialize` is rate limited like `tools/call`. For several workers, implement `SessionStore` on shared storage or use
  sticky routing.
* **Limits.** `initialize` and `tools/call` are rate limited per principal ID,
  or per peer address (`ip:<client>`) for anonymous callers. Over the limit,
  they get `429` with `Retry-After`. `tools/call`, including `amp_task`, also
  holds a slot in the concurrency limiter, keyed the same way, for as long as
  it runs. When the caller's share or the global cap is exhausted, it gets
  `503` with `Retry-After: 1`. Each call runs under `tool_timeout`, which defaults to the
  policy's `handler_timeout_seconds` (or 30 s). A timed-out call returns
  `isError`. Synchronous tools run in a worker thread, so they cannot block the
  event loop. Arguments are capped at `max_argument_bytes` (256 KiB, `-32602`).
  The request body is also capped by the server's `max_message_bytes`.
  `tools/list` is paginated with an opaque cursor (`page_size`, default 100).
* **No exception text leaves the server.** Tool, task and dispatch failures
  return `"Tool execution failed (reference <id>)"`. The traceback is logged
  server-side with the same reference ID. A deliberately raised `AMPError`
  exposes only its `code`. Argument errors name only field paths, never the
  values.

## Consuming MCP servers

```python
from ampro.interop.mcp import MCPToolSource

async with MCPToolSource("https://tools.example.com/mcp",
                         headers={"Authorization": f"Bearer {token}"}) as source:
    names = await source.register_into(agent, prefix="files.")
    # agent.tools["files.read"](path="README.md") -> structuredContent or text
```

* Speaks the handshake era (default `2025-11-25`). It accepts both
  `application/json` and SSE responses, follows `nextCursor`, ends the session
  with `DELETE` on close, and re-initializes once if the server answers `404`.
* `register_into(app, prefix="", overwrite=False)` adds async proxies to
  `app.tools`, and the remote description and schema to `app.tool_meta`. A
  proxy returns `structuredContent` if present, otherwise the joined text. It
  raises `MCPToolError` when the remote tool reports `isError`. Existing local
  tools are kept unless `overwrite=True`.
* **Outbound safety:**
  * When the source creates its own HTTP client, the URL must pass
    `ampro.security.ssrf.validate_url_async`: HTTPS only, no userinfo, and
    every resolved address must be public. The client dials only those pinned
    addresses, and environment proxies are ignored.
    `allow_private=True` (which also allows plain HTTP) opts out for local
    development.
  * Only `307`/`308` redirects within the same origin are followed. Anything
    else is an error, so a session ID or token is never sent to another
    host.
  * Every exchange runs under an overall `timeout` (30 s), and responses are
    capped at `max_response_bytes` (4 MiB).
  * If you pass your own `http_client`, you are responsible for its egress
    policy.
* **Trace context and hop count:** every request carries `traceparent`,
  `tracestate` and `AMP-Hop-Count` from the handler or tool it is called
  from (a new trace at hop 1 outside any handler). A call whose hop count
  would exceed `max_hops` (default 20) or the inbound limit raises
  `HopLimitExceeded` without sending anything. See
  [INTEROP-A2A.md](INTEROP-A2A.md#trace-context-and-hop-count) and
  WIRE-BINDING Section 12.14.1.

## Limitations

* Tools only: no resources, prompts, completions, logging, sampling or
  elicitation. The server advertises `{"tools": {"listChanged": false}}`.
* No SSE responses or server-initiated streams, so there are no progress
  notifications. No resumability (`Last-Event-ID`).
* `Mcp-Param-*` headers (`x-mcp-header` schema annotations, 2026-07-28) are
  not validated.
* `tools/list` derives schemas on every call. Results are cheap but not cached.
* `MCPToolSource` speaks only the handshake era. It does not use
  `server/discover` or the stateless 2026-07-28 envelope; servers that support
  both eras, including this one, accept it.
* The OAuth 2.1 authorization-server flow (protected resource metadata,
  dynamic client registration) is not implemented. Plug a token-verifying
  `Authenticator` in instead.
