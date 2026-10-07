# Agent Mesh Protocol — Edge Case Analysis (Retrospective)

> **Audited version**: v0.2.0 (2026-04-10)
> **Total issues**: 68
> **Status**: **All CRITICAL+HIGH edge cases addressed in v0.2.3.** See `CHANGELOG.md` §0.2.3.
>
> Retained as a historical record of edge-case analysis. Does NOT describe current (post-v0.2.3) protocol behaviour.

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 18 |
| HIGH | 30 |
| MEDIUM | 20 |

---

## 1. Security (16 issues)

### 1.1 DID Proof Accepted Without Signature Verification (CRITICAL)
**File**: `ampro/trust/resolver.py:77-123`

The DID trust resolver accepts `did:key` proofs WITHOUT verifying the JWT signature. The code parses the payload but never checks the signature. An attacker can forge any DID identity.

**Exploit**: Craft JWT `header.{"did":"did:key:z6Mk..."}.fakesig` — passes as VERIFIED.

### 1.2 Empty Shared Secret in Session Binding (CRITICAL)
**File**: `ampro/session/binding.py:60-86`

`derive_binding_token()` accepts empty `shared_secret` with no validation. Empty key = predictable HMAC. Attacker knowing the nonces (transmitted in plaintext during handshake) can forge Session-Binding headers.

### 1.3 Dedup/Nonce Tracker Memory Leak (CRITICAL)
**File**: `ampro/security/nonce_tracker.py:20-32`, `ampro/security/dedup.py:24-28`

Both use cleanup-on-access pattern. If an attacker sends messages with unique IDs but no legitimate traffic triggers cleanup, the store grows unbounded. 100 msgs/sec × 3600s window = 360,000 entries before any cleanup.

### 1.4 Rate Limiter Unbounded Growth (CRITICAL)
**File**: `ampro/security/rate_limiter.py:14-50`

Attacker rotating through 1M unique sender IDs causes `_requests` dict to grow to 1M entries. Same issue in `ApiKeyStore._failures` and `._blocked`.

### 1.5 Handshake State Machine Not Thread-Safe (HIGH)
**File**: `ampro/session/handshake.py:234-276`

`transition()` reads `_state`, computes next state, writes `_state` — no lock. Concurrent threads can cause invalid state transitions.

### 1.6 No Key Exchange for Encryption (HIGH)
**File**: `ampro/security/encryption.py:30-39`

`EncryptedBody` defines ciphertext/iv/tag/algorithm but no mechanism for agents to agree on encryption keys. `recipient_key_id` has no validation. No downgrade prevention — encrypted sessions can be silently switched to plaintext.

### 1.7 Key Revocation Has No Propagation (HIGH)
**File**: `ampro/security/key_revocation.py:41-67`

Revocation message defined but no mechanism to reach agents that cached the old key. `jwks_url` is optional. Compromised keys remain trusted until TTL expires.

### 1.8 Challenge Response Has No Solution Validation (HIGH)
**File**: `ampro/security/challenge.py:47-53`

The body type defines challenge/response but provides zero guidance on solution validation. Each implementation validates differently — no interoperability.

### 1.9 Nonce Reuse Across Sessions (HIGH)
**File**: `ampro/session/binding.py` + `ampro/session/handshake.py`

No requirement that nonces be globally unique. Weak PRNG could repeat nonces, making binding tokens identical across sessions. No delimiter between concatenated nonce+session_id.

### 1.10 Trust Resolver Silent Downgrade (HIGH)
**File**: `ampro/trust/resolver.py:53-74`

If JWT resolver module is missing or fails, silently downgrades to EXTERNAL tier. Only logged at DEBUG level. Attacker can cause resolver crash via malformed JWTs to force downgrade.

### 1.11 Stream Auth Token Not Validated (CRITICAL)
**File**: `ampro/streaming/auth.py:13-22`

`StreamAuthRefreshEvent` token format unspecified. No signature. Attacker on network can inject fake auth refresh events to hijack streaming sessions.

### 1.12 No Channel Authentication (HIGH)
**File**: `ampro/streaming/channel.py`

Any session can open any channel. No verification that `task_id` belongs to requesting agent. Data leakage between sessions possible.

### 1.13 Percent-Encoding Not Decoded (HIGH)
**File**: `ampro/core/addressing.py`

`parse_agent_uri("agent://127%2e0%2e0%2e1")` doesn't decode percent-encoding. SSRF protection bypass possible.

### 1.14 Unicode Hostnames Not Normalized (MEDIUM)
**File**: `ampro/core/addressing.py`

No NFKC normalization. Cyrillic homoglyphs pass as valid hostnames.

### 1.15 Cross-Verification Is Optional (HIGH)
**File**: `ampro/identity/cross_verification.py`

Verification is async and not part of handshake. Agent can claim identifiers, use them, and verification fails after messages already delivered.

### 1.16 Clock Skew Tolerance Too Large (MEDIUM)
**File**: `ampro/trust/tiers.py:58`

60-second tolerance enables replay attacks within that window. Combined with 3600s nonce window, creates exploitable gaps.

---

## 2. Data Integrity (12 issues)

### 2.1 Trust Score Accepts Negative Inputs (HIGH)
**File**: `ampro/trust/score.py:97-104`

Only `CLEAN_HISTORY` has `max(0, ...)` guard. `age_days=-365` or `interactions=-1000` produce negative factors, corrupting tier assignment.

### 2.2 Floating-Point Cost Accumulation (HIGH)
**File**: `ampro/delegation/cost_receipt.py:72`

`total_cost_usd += receipt.cost_usd` — IEEE 754 precision drift. 0.1 + 0.2 != 0.3. Financial audits produce incorrect totals.

### 2.3 Currency Mixing in Cost Chains (HIGH)
**File**: `ampro/delegation/cost_receipt.py:31`

`add_receipt()` sums costs without checking currencies match. Agent A reports USD, Agent B reports EUR — total is meaningless.

### 2.4 Unknown Body Types Bypass Validation (HIGH)
**File**: `ampro/core/body_schemas.py`

`validate_body("x-attack.payload", {"shell_command": "..."})` returns raw dict with zero validation. Custom types have no sanitization.

### 2.5 Empty body_type Accepted (MEDIUM)
**File**: `ampro/core/body_schemas.py`

`body_type=""` passes envelope validation and registry lookup returns None, silently treated as extension type.

### 2.6 Non-Dict Body Silently Becomes Empty (MEDIUM)
**File**: `ampro/core/message_middleware.py`

`body = msg.body if isinstance(msg.body, dict) else {}` — string body silently becomes empty dict. Message content lost.

### 2.7 No Max String Length on Any Field (MEDIUM)
**File**: Multiple body schema models

`description="x" * 100_000_000` accepted. Database inserts, logging, and storage systems can crash.

### 2.8 Negative Cost/Timeout Values Accepted (MEDIUM)
**File**: `ampro/core/body_schemas.py`

`estimated_cost_usd: float` has no `ge=0` constraint. `timeout_seconds: int` has no constraint. Negative values create invalid semantics.

### 2.9 Extra Fields Silently Ignored (MEDIUM)
**File**: All body models

`model_config = {"extra": "ignore"}` — typos in field names are silently discarded. Integration bugs go undetected.

### 2.10 No Checkpoint Schema Versioning (MEDIUM)
**File**: `ampro/streaming/checkpoint.py`

`state_snapshot` schema not versioned. Agent upgrade changes snapshot format — old checkpoints crash on replay.

### 2.11 No Schema Versioning for agent.json (HIGH)
**File**: `ampro/agent/schema.py`

`protocol_version` is protocol version, not schema version. Adding/removing fields has no versioning. Consumers don't know which fields to expect.

### 2.12 Stale Registry Results (MEDIUM)
**File**: `ampro/registry/search.py`

No freshness indicator on search results. Endpoint may have gone offline since search returned it.

---

## 3. Availability (14 issues)

### 3.1 All Streaming State Lost on Restart (CRITICAL)
**File**: `ampro/streaming/bus.py`

`_active_streams` is in-memory only. Server restart = all streams, events, ring buffers gone. No persistence.

### 3.2 No Distributed Deployment for Streaming (CRITICAL)
**File**: `ampro/streaming/bus.py`

Single-process, single-machine. No message queue backend. Load balancing across instances impossible — sticky sessions required but undocumented.

### 3.3 SSE Reconnect Silently Drops Events (CRITICAL)
**File**: `ampro/streaming/bus.py:94-105`

Ring buffer capacity is 100. If client reconnects after buffer has cycled, `replay_from()` returns empty list with no error. Silent data loss.

### 3.4 Backpressure Is Advisory Only (CRITICAL)
**File**: `ampro/streaming/backpressure.py`

`stream.pause` has no enforcement. Misbehaving producer can ignore pause. No timeout for paused streams. No protocol-level penalty.

### 3.5 No Channel Limit (HIGH)
**File**: `ampro/streaming/channel.py`

Client can open thousands of channels on single connection. No per-session quota. No cleanup on stale channels.

### 3.6 Unbounded Async Queue (HIGH)
**File**: `ampro/streaming/bus.py:40-42`

`asyncio.Queue()` has no max size. Producer can enqueue infinitely many events. No error response on overflow.

### 3.7 No Handshake Timeout (HIGH)
**File**: `ampro/session/handshake.py`

State machine enforces valid transitions but not time limits. Client can leave handshake stuck in INIT_SENT indefinitely. Server holds resources.

### 3.8 No Default Rate Limiting (MEDIUM)
**File**: `ampro/core/message_middleware.py`

`check_message_size()` enforces 10MB limit but no rate limit per sender. Attackers flood with valid messages at no cost.

### 3.9 10MB × 100 Concurrent = 1GB Memory (MEDIUM)
**File**: `ampro/core/message_middleware.py`

Default max 10MB per message. No per-sender memory limit. 100 concurrent messages = 1GB.

### 3.10 No Redirect Loop Detection (MEDIUM)
**File**: `ampro/transport/task_redirect.py`

Agent A redirects to B, B redirects to A. Infinite loop. No max-hops limit in protocol.

### 3.11 Migration Chains Can Be Infinite (HIGH)
**File**: `ampro/identity/migration.py`

`moved_to` can point to another agent with its own `moved_to`. No depth limit. A→B→C→...→Z = DoS via 26 HTTP requests.

### 3.12 Thundering Herd on agent.json TTL (MEDIUM)
**File**: `ampro/agent/schema.py`

10,000 consumers cache agent.json with same TTL. All retry when TTL expires. DDoS spike on agent's endpoint.

### 3.13 No Federation Revocation (CRITICAL)
**File**: `ampro/registry/federation.py`

Once federated, forever federated. Compromised registry continues sharing agents. No unilateral revocation mechanism.

### 3.14 Instant Decommissioning Allowed (HIGH)
**File**: `ampro/agent/lifecycle.py`

Agent can jump from ACTIVE to DECOMMISSIONED with no grace period. In-flight tasks orphaned. No enforcement of draining.

---

## 4. Compliance (8 issues)

### 4.1 Jurisdiction Conflict Detection Is Naive (CRITICAL)
**File**: `ampro/compliance/jurisdiction.py:38-64`

Algorithm: "no conflict if same primary or all sender frameworks exist in receiver." Real GDPR adequacy decisions expire, require binding corporate rules, standard contractual clauses. False confidence in cross-border transfers.

### 4.2 Multi-Jurisdiction Semantics Undefined (HIGH)
**File**: `ampro/compliance/types.py`

Agent with `primary=DE, additional=[US, SG]` — which rules apply? Ambiguous. Agent can claim whichever framework is most convenient.

### 4.3 Data Transit vs Storage Distinction Missing (HIGH)
**File**: `ampro/compliance/data_residency.py`

Only checks stored residency. GDPR also governs data in transit. No way to declare transit path.

### 4.4 Region Strings Not Validated Against Reality (MEDIUM)
**File**: `ampro/compliance/data_residency.py:17-44`

`region="totally-fake-region"` passes format validation. No registry of real regions. Self-certified, unverified.

### 4.5 Erasure Has No Retry for Offline Agents (CRITICAL)
**File**: `ampro/compliance/erasure.py`

If downstream agent is offline during erasure propagation, no retry mechanism. GDPR mandates erasure within 30 days.

### 4.6 Partial Erasure Untrackable (CRITICAL)
**File**: `ampro/compliance/types.py:57-64`

`retained` is free-form list. No schema to correlate which records remain at which downstream agent. GDPR audit fails.

### 4.7 Link Proofs Never Expire (HIGH)
**File**: `ampro/identity/link.py`

No `expires_at` or `ttl_seconds`. Once linked, always linked. Compromised key keeps links valid forever.

**Resolved**: `IdentityLinkProofBody` now has a required `expires_at`, which
must be strictly after `timestamp`. Freshly minted proofs default to a
one-year lifetime (`DEFAULT_LINK_PROOF_LIFETIME`), and
`is_link_proof_valid()` returns `False` once the proof has expired.

### 4.8 Cached Visibility Changes Don't Propagate (HIGH)
**File**: `ampro/agent/visibility.py`

If agent changes from PUBLIC to PRIVATE, cached agent.json stays public until TTL expires. No invalidation broadcast.

---

## 5. Protocol Gaps (18 issues)

### 5.1 No IPv6 Support (MEDIUM)
**File**: `ampro/core/addressing.py`

`agent://[2001:db8::1]` fails parsing. IPv6-only networks broken.

### 5.2 No Port Number Support (MEDIUM)
**File**: `ampro/core/addressing.py`

`agent://example.com:8080` treats `:8080` as part of hostname.

### 5.3 No Version Negotiation Fallback (MEDIUM)
**File**: `ampro/core/versioning.py`

No common version = hard ValueError. No graceful degradation.

### 5.4 Inconsistent Error Handling (MEDIUM)
Envelope: no validation errors. Body schemas: pydantic.ValidationError. Addressing: ValueError. No unified error strategy.

### 5.5 No Registry Search Pagination (MEDIUM)
**File**: `ampro/registry/search.py`

max_results capped at 100. No cursor. Can't browse beyond first page.

### 5.6 No Relevance Scoring Algorithm (MEDIUM)
**File**: `ampro/registry/search.py`

"Ranked" results but no ranking algorithm defined. Different registries rank differently.

### 5.7 No Federation Sync Protocol (HIGH)
**File**: `ampro/registry/federation.py`

How do agents from Registry-A appear in Registry-B? No sync protocol, no consistency guarantees.

### 5.8 No Federation Conflict Resolution (CRITICAL)
**File**: `ampro/registry/types.py`

Same agent_uri in two federated registries with different endpoints. No resolution algorithm. MITM possible.

### 5.9 No Migration Acceptance Verification (CRITICAL)
**File**: `ampro/identity/migration.py`

New identity doesn't publish acceptance. Compromised old identity can falsely claim migration to unrelated new identity.

### 5.10 No Migration Chain Depth Limit (HIGH)
`moved_to` chains can grow arbitrarily. No cycle detection (A→B→A possible).

### 5.11 No Cache Invalidation Push (MEDIUM)
**File**: `ampro/agent/schema.py`

TTL-based polling only. No push notification for changes. Thundering herd on TTL expiry.

### 5.12 Event Ordering Across Channels Undefined (HIGH)
**File**: `ampro/streaming/channel.py`

No ordering guarantees between events from different channels. Replay can't reconstruct cross-channel ordering.

### 5.13 Large SSE Events Exceed Frame Limits (HIGH)
**File**: `ampro/streaming/events.py:54-62`

No size limit on events. 10MB tool result → 20MB SSE line → TCP frame overflow.

### 5.14 No Checkpoint Size Limit (HIGH)
**File**: `ampro/streaming/checkpoint.py`

`state_snapshot` unbounded. Long-running tasks accumulate gigabytes.

### 5.15 Headers Accept Non-String Types (HIGH)
**File**: `ampro/core/envelope.py`

`headers: dict[str, Any]` allows dicts, lists as values. HTTP headers must be strings per RFC 7230.

### 5.16 No Sender/Recipient Length Validation (HIGH)
**File**: `ampro/core/envelope.py`

Unrestricted `str` fields. Gigabyte-sized sender URIs cause memory exhaustion.

### 5.17 Lazy Registration Silently Fails (MEDIUM)
**File**: `ampro/core/body_schemas.py`

`except ImportError: pass` means missing modules produce incomplete registries. Agents disagree on available body types.

### 5.18 Only Forward-Compatible Schema Evolution (MEDIUM)
New required fields break old versions. No backward compatibility strategy.

---

## Priority Matrix

### Fix First (blocks any production use)
1. DID proof signature verification (1.1)
2. Empty shared secret rejection (1.2)
3. Bounded dedup/nonce/rate limiter stores (1.3, 1.4)
4. Thread-safe state machine (1.5)
5. Trust score input validation (2.1)
6. Streaming persistence (3.1, 3.2)
7. Backpressure enforcement (3.4)

### Fix Before Multi-Agent Deployment
8. Key revocation propagation (1.7)
9. Encryption key exchange (1.6)
10. Session binding nonce delimiter (1.9)
11. Handshake timeout (3.7)
12. Channel limits and auth (3.5, 1.12)
13. Redirect loop detection (3.10)
14. Migration chain limits (3.11)

### Fix Before Cross-Border Deployment
15. Jurisdiction logic (4.1, 4.2)
16. Erasure retry mechanism (4.5)
17. Data residency transit paths (4.3)
18. Region validation (4.4)

### Fix Before Scale Deployment
19. Registry pagination (5.5)
20. Federation sync + conflict resolution (5.7, 5.8)
21. Cache invalidation (5.11)
22. Schema versioning (2.11)
23. IPv6 + port support (5.1, 5.2)
