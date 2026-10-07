# AMP Conformance Testing

AMP has three conformance tools. None of them assumes the implementation
is written in Python.

| Tool | Tests | Use it when |
|---|---|---|
| [`spec/schemas/`](../spec/schemas/) (JSON Schema 2020-12) | Message shapes | You need to validate envelopes, bodies, agent.json or problem details in your own code |
| [`tests/vectors/`](../tests/vectors/) | Parsers, validators and signers, byte for byte | You are building the library layer: canonical JSON, Ed25519 signatures, RFC 9421, session binding |
| `ampro-conformance` | A running agent, over HTTP | You have a server and want to know whether it speaks AMP |

This document covers `ampro-conformance`, the black-box suite.

## Install and run

```bash
pip install "ampro[conformance] @ git+https://github.com/agentmeshpro/agent-mesh-protocol.git"

ampro-conformance --url https://agent.example.com
```

The `conformance` extra adds `jsonschema`, so responses are validated
against the published schemas. Without it, the suite still runs every
check, but it only verifies required fields.

Options:

| Option | Meaning |
|---|---|
| `--url` | Origin of the agent under test. Use the externally visible origin, because signatures cover `<url>/agent/message`. |
| `--level 0..5` | Highest conformance level to test. The default is the level declared in `agent.json` (`capabilities.level`), with a minimum of 1. |
| `--signing-key`, `--keyid` | An Ed25519 key that the target accepts, and its RFC 9421 `keyid`. The key can be a PEM (PKCS#8) file, or a 32-byte seed in hex or base64, given inline or in a file. With a key, every request is signed and the signature checks run. |
| `--sender` | Envelope `sender`. The default is the `agent://` part of the keyid, or `agent://conformance.invalid`. |
| `--sender-bound` | The key is bound to `--sender`. Also checks that sending as anyone else gets 403. |
| `-H 'Name: value'` | Extra header on every request, for example `-H 'Authorization: Bearer …'`. Repeatable. |
| `--probe-rate-limit N` | Send up to N messages to provoke a 429, then check its format. |
| `--skip-large` | Skip the two 10 MiB message-size checks. |
| `--only PREFIX` | Run only checks whose id starts with PREFIX, for example `--only version.`. Repeatable. |
| `--report table\|json`, `--output FILE` | Output format, and an optional copy of the JSON report. |
| `--list` | Print every check and exit. |

Exit status:

- `0`: every MUST check passed. SHOULD failures and skips do not fail the run.
- `1`: at least one MUST check failed.
- `2`: a usage error.

The suite sends about 40 requests at level 1. With `--probe-rate-limit`
it sends up to N more, and the two size checks upload about 10 MiB each.
Point it at a staging deployment, or at one whose limits you control.

### From Python

```python
import httpx
from ampro.conformance import Signer, run_conformance

report = await run_conformance(
    "http://testserver",
    transport=httpx.ASGITransport(app=my_asgi_app),   # or omit for real HTTP
    signer=Signer(seed, "agent://me.example.com#key-1"),
)
assert report.ok, report.to_table()
```

## Checks

Each check verifies one requirement in [WIRE-BINDING](WIRE-BINDING.md). It
fails only on behaviour the specification constrains.

| Check | Level | Req. | Section | Verifies |
|---|---|---|---|---|
| `discovery.agent-json` | 0 | MUST | 4.1.2 | 200, `application/json`, required fields, schema |
| `discovery.protocol-version` | 0 | MUST | 4.1.2 | `protocol_version` is SemVer |
| `discovery.caching` | 0 | SHOULD | 4.1.5 | `ttl_seconds` or `Cache-Control` |
| `discovery.health` | 0 | MUST | 4.2 | 200/503, `status` + `protocol_version`, status agrees with HTTP code |
| `errors.unknown-route` | 0 | MUST | 7.1 | Errors are `application/problem+json` |
| `message.accepted` | 1 | MUST | 20.2 | A valid `message` envelope is accepted (2xx, or 501 if no handler) |
| `message.response-envelope` | 1 | MUST | 20.2 | A 2xx reply is an `AgentMessage` envelope |
| `message.content-type-default` | 1 | MUST | 3.2 | A missing `Content-Type` means JSON |
| `message.content-type-unsupported` | 1 | MUST | 3.2 | `text/plain` gets 415 `content-type-mismatch` |
| `message.invalid-json` | 1 | MUST | 7.2.1 | 400 `invalid-message` |
| `message.invalid-envelope` | 1 | MUST | 5.1.1 | A missing `sender` gets 400 |
| `message.invalid-body` | 1 | MUST | App. D step 4 | A `task.create` with no `description` gets 400 |
| `message.unknown-body-type` | 1 | MUST | 5.1.4 | An unknown body type is never rejected with 400 |
| `message.unknown-headers` | 1 | MUST | 5.1.5 | Unknown headers are ignored |
| `message.unknown-fields` | 1 | MUST | PROTOCOL-CONTRACTS 2 | Unknown envelope fields are ignored |
| `message.size-limit` | 1 | MUST | 3.4 | Over the limit gets 413 `payload-too-large` |
| `message.size-minimum` | 1 | MUST | 3.4 | 10 MiB is accepted |
| `message.recipient-mismatch` | 1 | MUST | 5.1.3, App. D step 6 | A wrong `recipient` gets a 4xx problem (400 recommended) |
| `message.loop-detected` | 1 | SHOULD | App. D step 7 | `Visited-Agents` containing this agent gets 409 `loop-detected` |
| `message.loop-limit` | 1 | SHOULD | 19 | More than 20 visited agents gets 409 |
| `message.duplicate-id` | 1 | SHOULD | 12.5 | A repeated id returns the original response |
| `ratelimit.headers` | 1 | SHOULD | 12.4 | `X-RateLimit-Limit/Remaining/Reset` |
| `version.protocol-version-header` | 1 | MUST | 18.4 | `Protocol-Version` response header |
| `version.same-major` | 1 | MUST | 18.4 | `Accept-Version: <major>.999.0` is accepted with the same MAJOR |
| `version.unsupported-major` | 1 | MUST | 18.4 | `999.0.0` gets 406 `version-mismatch` |
| `version.malformed` | 1 | MUST | 18.4 | A non-SemVer version gets 406 |
| `auth.signed-request` | 1 | MUST | 12.15.5 | A valid signature is accepted |
| `auth.signature-replay` | 1 | MUST | 12.15.4 | The same `(keyid, nonce)` twice gets 401 |
| `auth.signature-tamper` | 1 | MUST | 12.15.2 | A body changed after signing gets 401 |
| `auth.signature-stale`, `auth.signature-future` | 1 | MUST | 12.15.4 | `created` more than 300 s off gets 401 |
| `auth.signature-no-nonce` | 1 | MUST | 12.15.1 | A signature without a nonce gets 401 |
| `auth.signature-alg` | 1 | MUST | 12.15.1 | `alg` other than `ed25519` gets 401 |
| `auth.signature-unknown-key`, `auth.signature-wrong-key` | 1 | MUST | 12.15.5 | An unknown or mismatched key gets 401 |
| `auth.sender-binding` | 1 | MUST | 12.15.5, App. D step 5 | A bound key sending as another agent gets 403 (`--sender-bound`) |
| `ratelimit.429` | 1 | MUST | 7.2.10 | A 429 carries `Retry-After` and a `rate-limited` problem |
| `tools.list`, `tools.unknown` | 2 | MUST | 20.3 | Tool list, and 404 for unknown tools |
| `stream.events` | 3 | MUST | 8.3, 20.4 | SSE with a defined event type, a JSON `data` object and an integer `seq` |
| `tasks.unknown` | 3 | MUST | 20.4 | 404 for unknown tasks |

The suite skips a check rather than failing it when it cannot run:

- the endpoint requires authentication and no credentials were given;
- no key was supplied for the signature checks;
- the baseline message was not accepted;
- no 429 was seen.

Every check that expects an error also validates the full problem
document: the content type, the `type`, `title` and `status` members, the
match between `status` and the HTTP code, and the published schema. Where
the spec names a URN, the check also requires that URN.

### What is not covered yet

Some behaviour is hard to test from outside, or needs cooperation from
the target, and is left to the [vectors](../tests/vectors/) and to unit
tests:

- the three-phase session handshake and session binding (Level 4);
- delegation-chain validation;
- compliance flows (erasure, consent, residency);
- DID, JWT, API-key and mTLS authentication, beyond passing a header
  with `-H`;
- the in-flight duplicate (409) race;
- callbacks;
- stream reconnection and backpressure.

Contributions are welcome. Add a check in `ampro/conformance/suite.py` with
its section and requirement level.

## Results for the reference server

`tests/test_conformance_suite.py` runs the suite against `ampro`'s own
`AgentServer`. It runs anonymously and with RFC 9421 signatures, both
in-process through `httpx.ASGITransport` and over real HTTP with uvicorn on
127.0.0.1. Levels 0 and 1 pass with no failures. This covers all 37 checks
at those levels, including the rate-limit probe and every signature check.

Two caveats apply to the reference server:

- `AgentServer` returns whatever the handler returns. A handler that
  returns a plain `dict` therefore produces a non-envelope 2xx reply and
  fails `message.response-envelope`. Return an `AgentMessage` (usually
  `task.complete`, `task.acknowledge` or `task.reject`) to conform.
- `AgentServer` answers the Level 2 and 3 endpoints with 501 stubs, so it
  declares level 0 in `agent.json` and is tested at level 1.
