# AMP Security Model

> Status: pre-1.0. This document captures what the **protocol** guarantees,
> what it explicitly does **not** guarantee, and what a host platform MUST
> provide to make an AMP deployment safe to run in production. Everything
> below is RFC 2119 normative when written in **MUST / SHOULD / MAY**.

AMP is a wire protocol for agent-to-agent communication. A protocol
defines *envelopes, types, and verification rules* — not operational
concerns like key storage, certificate issuance, or network hygiene.
Those are the host platform's job. The protocol draws a firm line
between the two, and this document is where the line is documented.

---

## What the protocol guarantees

1. **Message integrity.** A signed request is bound to its covered
   components (RFC 9421). Whenever the request has a body, the
   signature MUST cover `content-digest` (RFC 9530), and the digest
   MUST match the body actually received. `verify_request` rejects a
   non-empty body that is not covered or that does not match, so the
   body of a signed request cannot be swapped. A covered header that is
   missing fails verification. Any other tampering makes the signature
   invalid. See WIRE-BINDING section 12.15.

   Gap: the verifier does not yet require `@method`, `@target-uri` and
   `@authority` to be covered (WIRE-BINDING 12.15.2).

2. **Sender authentication.** If the caller registers a
   `PublicKeyResolver`, signatures are verified against the resolved
   key bytes using Ed25519. With no resolver, verification fails
   closed. When a key, DID proof or client certificate is bound to an
   agent address, the reference server rejects envelopes whose
   `sender` differs.

3. **Replay protection.** Every RFC 9421 signature MUST carry a
   `nonce` parameter; `verify_request` rejects signatures without one.
   It also rejects signatures whose `created` timestamp is more than
   300 s from the verifier's clock, in either direction.

   The nonce is checked only **after** the signature verifies, so a
   forged request can neither burn a legitimate nonce nor fill the
   cache. Nonces are scoped per `keyid`: the pair `(keyid, nonce)` is
   accepted once.

   The `NonceTracker` (default window 3,600 s, 100,000 entries) evicts
   expired entries and then the oldest live entry when it is full. It
   does not fail closed, so a nonce flood cannot lock out legitimate
   traffic. Size it so that `max_size` exceeds the peak verified-request
   rate × 300 s, because a nonce evicted early could otherwise be
   replayed inside the freshness window.

   DID proofs (single-use `jti`), federation trust proofs (single-use
   nonce, ±300 s) and session confirms (single-use `confirm_nonce`)
   have their own replay checks. See `ampro/security/rfc9421.py` and
   `ampro/security/nonce_tracker.py`.

4. **Revocation propagation.** `ampro.trust.resolver.get_public_key`
   consults the registered `RevocationStore` on every call, cache hits
   included, and again after a fresh resolver lookup. A key that the
   host marks revoked stops verifying immediately.

   If the store raises, for example because its backend is unreachable,
   the key is treated as **revoked** (fail closed), so an outage cannot
   re-enable a compromised key.

   The public-key cache is a bounded LRU: 1,024 entries with a 60 s TTL.
   An attacker who sends many distinct `keyid` values cannot grow it
   without bound. See `ampro/security/key_revocation.py`.

   Note: when *no* store is registered, the default store is permissive
   and logs a warning. Production deployments MUST register a store.

5. **Structural validation.** Envelopes, addresses, trust proofs,
   delegation chains, cost receipts, erasure responses, and registry
   syncs all use typed Pydantic models with length caps and
   content-constraint validators. Malformed input is rejected before
   it reaches application code.

6. **Deterministic wire binding.** The test vectors under
   `tests/vectors/` pin the canonical byte representation of every
   signed protocol artefact, along with deterministic Ed25519
   signatures made with fixed test keys. `tests/test_vectors.py` runs
   them against the reference implementation on every test run, so
   independent implementations (Go / Rust / TS) can check that they
   sign exactly the same bytes.

7. **Session binding without a transmitted secret.** The session
   binding key is derived independently by both peers. Each peer
   computes an ephemeral X25519 shared secret and runs it through
   HKDF-SHA256, binding the result to the session ID, both nonces and
   both public keys. The key is never sent on the wire, so it does not
   depend on TLS for secrecy, and a passive observer of the handshake
   cannot compute it.

   The server MUST verify the client's `binding_proof` (an HMAC over
   the handshake transcript, including the single-use `confirm_nonce`)
   before the session becomes active. Every message in the session
   then carries an HMAC over the session ID, the message ID and the
   SHA-256 of the canonical body.

   The key agreement is not authenticated by itself. Protection against
   an active man-in-the-middle still requires authenticated handshake
   messages, through TLS or RFC 9421 signatures. See WIRE-BINDING
   sections 9.2 and 9.3.

---

## What the protocol explicitly does NOT guarantee

Each item below is a deliberate design choice — not a bug and not a
roadmap item. Deployers MUST read this list before shipping AMP to
production.

### 1. Trust anchoring (self-attesting origin)

A signed envelope proves *"the holder of the private key matching
`sig_kid` sent this"*. It does **not** prove *"this `sig_kid` belongs
to the principal the sender claims to be"*. That binding comes from
the `PublicKeyResolver` the host registers, and the protocol takes it
on faith.

Production deployments SHOULD back the resolver with one of:

- **DNS-anchored JWKS** (resolver fetches from
  `https://<domain>/.well-known/amp/jwks.json`, verifies TLS chain).
- **Certificate Transparency-style log** (resolver refuses keys not
  present in an append-only log witnessed by independent auditors).
- **did:web / did:key with rotation proofs** — see
  `ampro.identity.migration` for the protocol-level primitive.
- **Private key directory** (org-scoped, operated by a party the
  relying agent trusts directly).

Until one of these is in place, an attacker who controls the resolver
controls the entire trust graph. The protocol ships no opinion on
which mechanism you pick — that's an ecosystem decision.

### 2. Key storage, rotation, and hardware isolation

The protocol accepts a 32-byte Ed25519 private key and signs with it.
It does not say where that key should live. In particular:

- Keeping a long-lived private key in process memory is **fine for
  demos, unsafe for production**. Process memory is readable by
  anything running as the same UID, survives core dumps, and can leak
  through swap.
- Production deployments SHOULD back the signer with an HSM, a TEE
  (e.g. AWS Nitro, GCP Confidential VMs), a KMS with per-request
  signing (AWS KMS, GCP Cloud KMS), or at minimum a kernel keyring
  with restricted process access.
- Rotation frequency is a host policy. The protocol provides
  `KeyRevocationBody` + `KeyRevocationBroadcastBody` so a rotated key
  can be announced across the mesh; using them is up to the host.

### 3. Encryption at the protocol layer

AMP does not encrypt envelope payloads by default. Confidentiality in
transit is delegated to the underlying transport — typically TLS 1.3.
This is a conscious choice so that:

- Intermediaries (relays, load balancers) can route without
  decrypting.
- Operators can MITM their own traffic for debugging and audit with
  their own TLS termination.
- The protocol does not become another key-management surface.

When confidentiality *must* survive a compromised transport — e.g.
delegation to an untrusted relay — callers use `EncryptedBody` from
`ampro.security.encryption` to wrap the payload with an ephemeral
symmetric key negotiated via `EncryptionKeyOfferBody` /
`EncryptionKeyAcceptBody`. This is opt-in, per-message, and the
`SessionContext.session_requires_encryption` flag lets a session
enforce that every envelope be encrypted (anti-downgrade).

Deployers MUST either:
- run AMP exclusively over TLS 1.3 with verified peer certificates, or
- set `session_requires_encryption=True` and negotiate encryption at
  session start.

### 4. Denial of service

The protocol provides primitives with bounded memory: `RateLimiter`,
`ConcurrencyLimiter`, `NonceTracker`, `InMemoryDedupStore`, and the
server's `InMemoryResponseCache`.

The reference `AgentServer` wires them onto `POST /agent/message`
through `SecurityPolicy` (WIRE-BINDING Appendix D). The pipeline runs
in this order:

1. size limit
2. authentication
3. per-principal rate limit
4. validation
5. sender and recipient checks
6. loop detection
7. caller-scoped dedup
8. concurrency limit
9. handler timeout

`SecurityPolicy.production()` requires authentication.

When these stores are full they evict entries rather than rejecting new
work: `NonceTracker` drops expired entries and then the oldest, and the
response cache drops the oldest. This keeps a flood from locking out
legitimate callers, at the cost of a shorter effective memory under
attack. Size them for your peak rate.

The federation nonce cache is the exception. It fails closed when it is
full of live entries.

Choosing quotas, running several workers against a shared store, and
shedding load under pressure remain host responsibilities.

### 5. Cross-jurisdiction compliance

`ampro.compliance` ships typed models for adequacy decisions, data
residency, retention policy, and erasure responses. It does **not**
know your jurisdictions' current rules. The host is responsible for
populating `AdequacyDecision` records and keeping them current as
regulators change positions.

### 6. Side channels

Ed25519 via `cryptography` is constant-time for the private-key
operation. The protocol does **not** otherwise attempt side-channel
hardening: string comparisons in header parsing are not constant-time,
and revoked-key lookups are not blinded. Hosts that care about
timing attacks should run AMP behind a reverse proxy that normalises
response timing.

---

## Host platform checklist

A platform shipping AMP to production MUST provide:

- [ ] A `PublicKeyResolver` whose trust root is **externally verifiable**
      (DNS + TLS, CT log, did:web, etc.). Never ship with an in-memory
      directory in production.
- [ ] A `RevocationStore` backed by durable shared storage (KV / DB)
      so every verifier converges on the revoked set within a bounded
      staleness window.
- [ ] A signing surface (HSM / KMS / keyring) that the Python process
      can call — not a raw `bytes` object passed around in memory.
- [ ] TLS 1.3 at every hop, with verified peer certificates, **or**
      session-level encryption via `session_requires_encryption=True`.
- [ ] Rate limits wired onto every ingress handler, sized to the
      platform's tenancy model. Use `SecurityPolicy.production()` or an
      equivalent pipeline that authenticates before deduplicating.
- [ ] Replay caches (`NonceTracker`, the dedup cache) sized above the
      peak verified-request rate × their freshness window, and shared
      across workers.
- [ ] A logging pipeline that captures rejected signatures, revocation
      hits, and rate-limit trips so operators can detect attacks.

The protocol does its share. The platform MUST do its share.

---

## Reporting a vulnerability

See `SECURITY.md` in the repository root. Coordinated disclosure,
90-day embargo window, GPG key for encrypted reports.
