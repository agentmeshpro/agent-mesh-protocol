# Extending AMP

AMP is built to be extended without forking. Three things make that
possible. You name your additions in a namespace you control. Every
receiver MUST ignore what it does not understand. And you can register
your names so others can find them. This document is the contract for
third-party extensions. To change AMP itself, see
[GOVERNANCE.md](../GOVERNANCE.md).

## What receivers guarantee

Every conforming receiver MUST:

| Unknown thing | Required behaviour | Spec |
|---|---|---|
| Body type | Accept the message. MUST NOT return 400 because of the type. MAY reply `task.reject` or 501. Never validates the body against a schema. | WIRE-BINDING 5.1.4, 18.1 |
| Envelope header | Ignore it. | 5.1.5, 18.2 |
| Envelope field, or field inside a known body | Ignore it. | PROTOCOL-CONTRACTS 2 |
| `agent.json` member | Ignore it. | 4.1.2 |
| Capability group | Ignore it when computing the level. | 18.3 |
| Stream event type | Ignore it. | 8.4, `spec/schemas/stream/event.json` |
| Problem `type` URN | Fall back to the HTTP status. | 7.1 |

`ampro-conformance` tests the first three, with
`message.unknown-body-type`, `message.unknown-headers` and
`message.unknown-fields` ([CONFORMANCE.md](CONFORMANCE.md)). So you can
send an extension to any conforming agent, and agents that do not know
it will not break.

## Naming rules

Put every name in a namespace you control. The reference implementation
checks these rules in `ampro.wire.extensions`, and the spec generator
applies the same checks to registrations.

### Body types and stream event types

Use one of these forms:

| Form | Example | Use for |
|---|---|---|
| Reverse-DNS of a domain you control, with at least three labels | `com.acme.order_confirmation` | Published extensions |
| `x-<vendor>.<name>` | `x-acme.order_confirmation` | Experiments and private deployments |
| Absolute `https` URI you control | `https://acme.example/amp/order-confirmation/v1` | Extensions that want a dereferenceable name |

- Use lowercase, digits, `-` and `.`. The last segment may also use `_`.
- The first label MUST NOT be a reserved AMP namespace: `agent`, `amp`,
  `audit`, `data`, `encryption`, `erasure`, `identity`, `key`, `message`,
  `notification`, `registry`, `session`, `stream`, `task`, `tool` or
  `trust`. For example, `task.my_thing` is not allowed. The registry lists
  them under `reserved_namespaces` in `spec/registry/body-types.json`.
- Put a version in the name when the shape may change incompatibly, for
  example `com.acme.order.v2` or `…/order/v2`. Never change the meaning of
  a published name.

### Headers

- Use `X-<Vendor>-<Name>`, for example `X-Acme-Request-Id` (18.2).
- The `X-AMP-` prefix is reserved for AMP.
- Header values are strings (5.1.1).

### Problem types

- Use `urn:<reverse-domain>:error:<name>`, for example
  `urn:com.acme:error:out-of-stock` (7.1.2).
- Always pair the type with the right HTTP status and a standard
  `title`, so that clients that do not know your URN still behave
  correctly.
- `urn:amp:` is reserved.
- To say "the caller needs more authority", do not define a new type:
  use `urn:amp:error:authority-required` (WIRE-BINDING 7.2.14) and put
  your requirement in a `required_constraints` entry whose `type` is in
  your namespace (for example `com.acme:region`).

### Extension URIs

An extension URI names a bundle of related behaviour, such as metadata
carried through another protocol.

- Use an absolute `https` URI under a domain you control, ending in a
  version segment, for example `https://acme.example/amp-ext/v1`.
- The URI SHOULD resolve to the extension's specification.
- AMP's own extension for A2A is
  `https://github.com/agentmeshpro/agent-mesh-protocol/ext/amp/v1`
  ([INTEROP-A2A.md](INTEROP-A2A.md#amp-extension)).

### `agent.json` and capabilities

- Advertise extension capability groups in reverse-DNS form, for example
  `"groups": ["messaging", "com.acme.payments"]` (18.3).
- Put extension configuration under a top-level `extensions` object keyed
  by extension URI:

  ```json
  "extensions": {
    "https://acme.example/amp-ext/v1": {"required": false, "regions": ["eu"]}
  }
  ```

  Consumers that do not know the URI ignore it.

## Defining an extension

An extension specification should state:

1. **Names.** List the body types, headers, problem types, events and
   extension URI.
2. **Schemas.** Give a JSON Schema 2020-12 for each body, with an `$id`
   under your own domain. Ours in `spec/schemas/` are a template.
3. **Semantics.** Describe the request and response pairs (reply with
   standard types such as `task.acknowledge`, `task.complete` or
   `task.reject` where possible), idempotency and the error cases.
4. **Negotiation.** Say how a peer learns support: through `agent.json`
   (a capability group, or an `extensions` entry), or by sending and
   handling `task.reject` / 501.
5. **Security.** Say what is signed, what is trusted and what is
   PII-classified.
6. **Version.** Say how it evolves. The same MINOR / MAJOR rules as AMP
   apply within one name.

Extensions MUST NOT change the meaning of standard AMP elements. For
example, an extension cannot make an AMP header mandatory, redefine a
standard body field, or bypass the security pipeline (Appendix D). If an
extension needs one of those things, it needs an AMP proposal.

## Implementing one with `ampro`

```python
from ampro.ampi.app import AgentApp

agent = AgentApp(agent_id="agent://shop.acme.example", endpoint="https://shop.acme.example/agent/message")

@agent.on("com.acme.order_confirmation")
async def confirm(msg, ctx):
    request_id = msg.headers.get("X-Acme-Request-Id")
    ...
```

Envelopes with extension body types pass validation unchanged. Validate
the body yourself against your own schema.

## Registering

Registration is optional, because a name in your own namespace already
works. Registering makes the name discoverable to other implementers and
protects it from accidental reuse.

1. Add an entry to [`spec/third-party.json`](../spec/third-party.json) in
   the right section (`body_types`, `headers`, `error_types`,
   `stream_events` or `extension_uris`). Every entry needs `owner`,
   `contact`, `spec` (a URL) and `description`. Problem types also need
   an integer `status`. For example:

   ```json
   "body_types": [
     {
       "name": "com.acme.order_confirmation",
       "owner": "Acme Corp",
       "contact": "amp@acme.example",
       "spec": "https://acme.example/amp/order-confirmation",
       "schema": "https://acme.example/amp/schemas/order-confirmation.json",
       "description": "Confirms a placed order"
     }
   ]
   ```

2. Run `python scripts/generate_spec.py`. It checks the naming rules,
   required fields, duplicates and clashes with AMP names, and merges the
   entry into `spec/registry/` with `"status": "registered"`.
3. Open a pull request.

Maintainers review only the naming rules, completeness and clashes, not
merit. Names are first-come-first-served. See
[GOVERNANCE.md](../GOVERNANCE.md#extensions-and-registration).

## From extension to standard

A widely used extension can become part of AMP through an AMP proposal
([GOVERNANCE.md](../GOVERNANCE.md#how-a-change-is-made)). The standard
version gets a name in an AMP namespace, and the extension name stays
registered for the deprecation window so that existing deployments keep
working.
