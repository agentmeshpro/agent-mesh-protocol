# Contributing to Agent Mesh Protocol

Thank you for your interest in contributing to the Agent Mesh Protocol!

## How to Contribute

There are several ways to contribute:

- **Report bugs** — open an issue describing the problem and how to reproduce it
- **Suggest protocol features** — open an issue with the `proposal` label (see below)
- **Fix bugs** — submit a pull request with tests
- **Add test vectors** — help other implementations validate compliance
- **Improve examples** — show protocol features in action
- **Improve documentation** — fix typos, clarify explanations

## Proposing Protocol Changes

The protocol defines primitives that all implementations must agree on. Changes to the
protocol affect everyone, so they go through a review process.

**Before writing code**, open a GitHub issue with:

1. **What** you want to add or change (body type, header, event type, schema field)
2. **Why** it's needed — what use case does it enable that the current protocol can't handle?
3. **Why it belongs in the protocol** — would two independent implementations need to agree on this to interoperate? If only one side needs to know about it, it's implementation guidance, not protocol.

We'll discuss the proposal in the issue before any code is written. This prevents
wasted work on features that don't fit the protocol's scope.

### What belongs in the protocol

| In the protocol | Not in the protocol |
|-----------------|---------------------|
| Body types and their fields | Which algorithms to use |
| Standard headers | Retry/backoff strategies |
| Streaming event types | Deployment patterns |
| State machines and transitions | Load balancing algorithms |
| agent.json schema fields | Rate limit allocation policies |
| Registry endpoint schemas | Platform-specific orchestration |

**The test:** If two agents from different platforms need to agree on it to talk to
each other, it's protocol. Everything else is implementation guidance — show it in
an example instead.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/agentmeshpro/agent-mesh-protocol.git
cd agent-mesh-protocol

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## Code Standards

- **Python 3.11+** required
- **Type annotations** on all public functions and model fields
- **Pydantic v2** for all data models with `model_config = {"extra": "ignore"}`
- **Field descriptions** on every Pydantic field — these are the protocol documentation
- **`from __future__ import annotations`** at the top of every module
- **No platform-specific imports** — only pydantic and stdlib. The package is PURE.
- **No mocks in tests** — test real behavior
- **Module docstrings** on every file explaining what it implements

### Commit messages

Use imperative mood (`add`, `fix`, `remove`), prefix with `feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `chore:` where applicable. Keep first line ≤ 72 chars.

### Formatting

Code is formatted with `ruff format` and linted with `ruff check`. Type-hinted public APIs verified with `mypy`.

## Adding a New Body Type

This is the most common type of protocol change. Here's the process:

1. **Open a proposal issue** explaining the new body type and why it's needed
2. **Get approval** from maintainers
3. **Create the model** in the appropriate module (or a new module if it's a new feature area)
4. **Register it** in `body_schemas.py` → `_BODY_TYPE_REGISTRY`
5. **Export it** from `__init__.py` and add to `__all__`
6. **Write tests** covering construction, validation, optional fields, and edge cases
7. **Add test vectors** in `tests/vectors/` (see below)
8. **Add an example** in `examples/` showing the body type in use
9. **Submit a pull request**

## Adding a New Header

1. Add the header name to `STANDARD_HEADERS` in `envelope.py`
2. Add a test vector in `tests/vectors/headers.json`
3. Update the header count assertion in `tests/test_protocol.py`

## Test Vectors

Test vectors are JSON files in `tests/vectors/` that define protocol compliance tests.
Any implementation in any language (Python, TypeScript, Go, Rust) can validate against
them. This is how the protocol gets adopted — not by reading a spec, but by running
tests until they all pass.

### Format

```json
{
  "description": "What this vector file tests",
  "vectors": [
    {
      "input": "the input to test",
      "expected": {"the": "expected result"},
      "valid": true
    },
    {
      "input": "invalid input",
      "expected": null,
      "valid": false,
      "error": "why it's invalid"
    }
  ]
}
```

### Adding test vectors

- Every new body type needs vectors showing valid construction and invalid inputs
- Every new header needs vectors in `headers.json`
- State machines need vectors showing valid and invalid transition sequences
- Test vectors are the protocol's contract — if your implementation passes all vectors, it's compliant

## Module Structure

The package is organized into 13 subpackages under `ampro/`:

| Subpackage | Purpose |
|------------|---------|
| `ampro.agent` | Agent identity, agent cards, visibility filters |
| `ampro.ampi` | Handler framework (AgentApp, decorators, AMPContext, TestServer) |
| `ampro.client` | Client SDK for outbound AMP calls |
| `ampro.compliance` | Jurisdiction, data residency, erasure, PII, audit attestation |
| `ampro.core` | Core types, addressing, body schemas, priority |
| `ampro.delegation` | Delegation chains, cost receipts, tracing |
| `ampro.identity` | Auth methods, cross-verification |
| `ampro.registry` | Registry search, federation |
| `ampro.security` | RFC 9421 signing, rate limiting, dedup, nonce, SSRF, revocation, circuit breakers |
| `ampro.server` | Reference server, CLI, middleware stack |
| `ampro.session` | Session handshake, binding, state machine |
| `ampro.streaming` | SSE streaming, backpressure, bus |
| `ampro.transport` | HTTP transport, attachments, JWKS cache, API key store |
| `ampro.trust` | Trust resolver, tiers, upgrade, score |
| `ampro.wire` | Wire binding spec helpers |

## Versioning

See [RELEASING.md](RELEASING.md) for the release + versioning policy.

## Extending AMPI

AMPI (`ampro.ampi`) is the handler framework — the in-process application surface that sits
on top of the wire protocol. Extension points:

- **Handlers** — write `async def handler(ctx: AMPContext, body) -> dict` and register via
  `@app.on("body.type")`. The handler receives a validated body model and a context with
  caller identity, trust tier, and session state.
- **Middleware** — write `async def mw(ctx, body, call_next)` and register via
  `@app.middleware`. Middleware runs in registration order around every handler call; use
  it for auth, logging, rate limiting, or cross-cutting policy.
- **Tools** — decorate a callable with `@app.tool("name")` to expose it as an invocable
  tool to agents. Tool schemas are inferred from type hints.

Every new handler, middleware, or tool MUST ship with a `TestServer`-based unit test that
exercises the registered behavior end-to-end against a real ASGI transport (no mocks).

See `ampro/ampi/app.py` for the AMPI framework source and `tests/test_ampi_*.py` for
reference tests.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure of protocol vulnerabilities.

## Code Review Process

1. All changes require a pull request — no direct pushes to `main`
2. PRs must include tests (unit tests + test vectors where applicable)
3. PRs must pass all existing tests (`pytest tests/ -v`)
4. New body types and headers need at least one example in `examples/`
5. Maintainers review for protocol scope (does this belong?), correctness, and consistency

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write your changes following the code standards above
4. Write tests for your changes
5. Ensure all tests pass (`pytest tests/ -v`)
6. Submit a pull request with a clear description of what and why

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.
