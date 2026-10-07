# Test Vectors

Portable conformance vectors for the Agent Mesh Protocol. A Go, Rust or
TypeScript implementation can load these JSON files and check that it
accepts, rejects and signs exactly what the Python reference does.

All 36 files (391 cases) are executed by
[`tests/test_vectors.py`](../test_vectors.py) on every test run. Use that
runner as the reference for how to interpret each file.

## Format

Each file is a JSON object with:

- `description`: what the file covers. For signed artefacts it also states
  the exact canonicalisation rule.
- `keys` (crypto files only): the fixed test keys used to produce the
  file. See [Test keys](#test-keys).
- one or more case lists, usually `vectors`. Some files split cases into
  `parse_vectors` / `match_vectors`, `contact_policy_vectors` /
  `filter_vectors`, or `negative_vectors`.

Most cases have a `valid` boolean (accept or reject) and an input:
`body` + `body_type`, `envelope`, `input`, `value`, `agent_json` or
`certification`. When `valid` is false, `expected_error` names the
offending field or a phrase from the error. Other files use `expected`
objects, `expected_violation`, `expected_conflict`, `allowed`, and so on;
the runner shows how each one is checked.

### Envelope bodies

When an envelope carries the `Content-Encryption` header, its `body` is an
`EncryptedBody` and is validated as one (WIRE-BINDING section 12.11).
Otherwise the body is validated against the schema for `body_type`.
Unknown `body_type`s are passed through unvalidated.

### Signed artefacts

Cases that carry a signature also carry the exact bytes that were signed,
for example `expected_canonical`, `signed_canonical`,
`expected.signature_base` or `expected.confirm_transcript`. A conforming
implementation MUST:

1. rebuild those bytes from the case's fields using its own
   canonicalisation code and compare them byte for byte;
2. verify the signature with the public key named by the case; and
3. for Ed25519, re-sign with the committed seed and get the identical
   signature (RFC 8032 signatures are deterministic).

A `"sign": {"kind": ..., "key": ...}` object marks a case whose
signature fields are produced by the generator. When a case also has
`"tamper"`, the body was changed after signing, so the signature MUST NOT
verify. A `"known_gap"` field marks an expectation that the reference
implementation does not meet yet: the runner xfails that case, and fails
once the gap is fixed.

## Test keys

These keys are public and used only for test vectors. Never use them for
anything else.

| Name | Type | Source |
|------|------|--------|
| `ed25519-a`, `ed25519-b`, `ed25519-c` | Ed25519 | RFC 8032 section 7.1, TEST 1 / 2 / 3 secret keys |
| `x25519-client` | X25519 | RFC 7748 section 6.1, Alice's private key |
| `x25519-server` | X25519 | `SHA-256("ampro test vector x25519 server")` |
| `a256gcm` | AES-256 | `SHA-256("ampro test vector a256gcm key")` |

Every file that uses a key embeds that key's seed or private key and its
public key in `keys`. The runner also checks that each public key really
derives from the committed private key.

## Regenerating

```bash
python tests/vectors/_generate.py          # rewrite the crypto values in place
python tests/vectors/_generate.py --check  # exit 1 if anything is stale
```

The generator fully writes `rfc9421.json`, `session_binding.json` and
`delegation_chain.json`. In every other file it recomputes the cases that
carry a `sign` directive. It produces the bytes with ampro's own
canonicalisation helpers, so a diff after a code change means the wire
format changed. `test_generator_is_up_to_date` fails if the committed
vectors are stale.

## Index

| Vector | Cases | Protocol surface | Crypto |
|--------|------:|------------------|:------:|
| addressing.json | 7 | `agent://` URI parsing (host, slug@registry, DID) | |
| agent_lifecycle.json | 11 | `agent.deactivation_notice`, lifecycle status in agent.json, registry resolution `gone` | |
| audit_attestation.json | 9 | `audit.attestation` body | |
| backpressure.json | 12 | `stream.ack` / `stream.pause` / `stream.resume` events | |
| body_types.json | 19 | Core body types, including the `session.*` handshake bodies (`client_ephemeral_key`, `server_ephemeral_key`, `confirm_nonce`; no `binding_token`) | |
| certifications.json | 10 | `CertificationLink` in agent.json | |
| challenge.json | 11 | `task.challenge` / `task.challenge_response` | |
| consent_revoke.json | 11 | `data.consent_revoke` | |
| context_schema.json | 11 | Context-schema URN parsing and matching | |
| cost_receipt.json | 13 | `CostReceipt`, `CostReceiptChain` (signature check, nonce replay, Decimal totals), `task.complete.cost_receipt` | yes |
| data_residency.json | 13 | `DataResidency`, region validation, violation checks, `Data-Residency` header | |
| delegation_chain.json | 17 | Signed delegation chains: canonical form, `parent_delegate` binding, depth, scope narrowing, fan-out, budgets, expiry, naive timestamps | yes |
| encryption.json | 10 | `EncryptedBody` and `Content-Encryption`. A256GCM cases decrypt with the `a256gcm` key | yes |
| envelope.json | 3 | `AgentMessage` envelope | |
| erasure_propagation.json | 12 | `erasure.propagation_status` | |
| handshake.json | 4 | Session handshake state machine transitions | |
| headers.json | 8 (+ header list) | Standard header registry | |
| identity_link.json | 11 | `identity.link_proof`, including the required `expires_at` | |
| identity_migration.json | 10 | `identity.migration`, `AgentJson.moved_to` | |
| jurisdiction.json | 15 | `JurisdictionInfo`, code validation, conflict checks | |
| key_revocation.json | 10 | `key.revocation`: Ed25519 signature over all fields except `signature` | yes |
| priority.json | 10 | `Priority` enum | |
| registry_federation.json | 14 | Federation request/response schemas, signed trust proofs (audience, `issued_at`, single-use nonce), signed revokes | yes |
| registry_search.json | 12 | Registry search request/match/result (`limit`; `max_results` is a deprecated alias) | |
| rfc9421.json | 16 | RFC 9421 HTTP message-signature profile: content-digest, `@authority`, signature base, freshness, nonce, alg allow-list, replay | yes |
| session_binding.json | 4 | X25519 + HKDF-SHA256 binding key, `binding_proof`, per-message `Session-Binding` HMAC, low-order-key rejection | yes |
| stream_channel.json | 11 | Stream channel open/close, `Stream-Channel` multiplexing | |
| stream_checkpoint.json | 10 | Stream checkpoint events | |
| task_redirect.json | 11 | `task.redirect`, `X-Load-Level` | |
| task_revoke.json | 8 | `task.revoke` | |
| tool_consent.json | 11 | `tool.consent_request` / `tool.consent_grant` | |
| tracing.json | 10 | Trace context format (32/16 lowercase hex) and header injection | |
| trust_proof.json | 10 | `trust.proof` body (schema only; ampro treats the proof as opaque) | |
| trust_scoring.json | 5 | Trust-score factors and tier | |
| trust_upgrade.json | 12 | `trust.upgrade_request` / `trust.upgrade_response` | |
| visibility.json | 20 | Contact policies and agent.json visibility filtering | |

## Using these vectors from another implementation

1. Load each file. Read `keys` if present, decoding the hex and base64url
   fields.
2. For every case in every list, feed the input to your equivalent parser,
   validator or signer.
3. Assert the recorded outcome: `valid`, the `expected*` fields, or for
   RFC 9421 `verify.expect` at `verify.at` (Unix seconds) with a fresh
   replay cache. An `expect` list means: verify that many times in a row
   with the same cache.
4. For signed cases, compare canonical bytes, verify the signature, and
   re-sign deterministically (see [Signed artefacts](#signed-artefacts)).

Watch for these portability traps:

- Canonical JSON means sorted keys, `,` and `:` separators, and UTF-8.
  Most artefacts emit non-ASCII characters raw (`ensure_ascii=False`).
  Key revocations escape them (`\uXXXX`).
- `cost_usd` is signed as Python's `json` module renders the float, for
  example `0.005` or `5.0`. JavaScript's `JSON.stringify(5.0)` gives `5`.
- Session-binding HMACs are keyed with the UTF-8 bytes of the hex binding
  key (64 ASCII characters), not the raw 32 bytes. Public keys enter the
  HKDF `info` and the confirm transcript as base64url strings without
  padding.

## Adding a vector

- Add `<surface>.json` with a top-level `description`.
- Add a handler for it in `tests/test_vectors.py`.
  `test_every_vector_file_has_a_handler` enforces this.
- For a signed artefact, add a `sign` kind or a builder to `_generate.py`
  and run it. Never hand-write signatures.
- Add a row to the index above, keeping rows in alphabetical order.
