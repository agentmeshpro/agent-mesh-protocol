# Agent Mesh Protocol — v0.2.1 Security Re-Audit (Retrospective)

> **Audited version**: v0.2.1 (2026-04-10)
> **Purpose at time of audit**: Verify v0.2.1 fixes are effective, find bypasses and new attack vectors.
> **Status**: **All CRITICAL+HIGH bypasses and logic bugs identified here were closed in v0.2.3.** See `CHANGELOG.md` §0.2.3 — the "Security — Phase 0 Sprint" section maps each C1–C20 / 1.4–5.9 finding to its remediation.
>
> This document is retained as a historical record of the protocol's
> security-review process — specifically the self-critical re-audit
> that caught incomplete fixes and regressions before they reached a
> tagged release. It does **not** describe current (post-v0.2.3)
> protocol behaviour.

---

## Executive Summary (v0.2.1 snapshot)

At the time of this re-audit, the v0.2.1 fixes were **partially
effective but introduced new attack vectors**. Of 47 fixes applied:

- **19 are correctly implemented** and effective
- **8 are incomplete** — fix exists but can be bypassed or has gaps
- **6 introduced NEW vulnerabilities** — the fix itself creates a new attack surface
- **5 are cosmetic** — docstring warnings with no code enforcement
- **9 have edge cases** that weren't considered

All of the above were addressed in v0.2.3. The remainder of this
document is the raw re-audit as filed.

---

## CRITICAL: Fix Bypasses Still Exploitable

### 1. SSRF: Percent-Encoded IP Bypass (I1 fix bypassed)
```
https://127%2e0%2e0%2e1/ → urlparse().hostname = "127%2e0%2e0%2e1"
ipaddress.ip_address() raises ValueError → exception caught → PASSES validation
```
**Status**: SSRF to localhost still works via percent-encoding.

**Update (0.4.0)**: Fixed. All outbound URL checks now go through the shared `ampro.security.ssrf` guard. It rejects percent-encoded hostnames outright, and rejects any
literal or resolved address in a blocked range.

### 2. SSRF: Octal/Hex/Decimal IP Bypass (I1 fix bypassed)
```
https://0177.0.0.1/    → octal loopback, not parsed by ipaddress
https://0x7f000001/    → hex loopback, not parsed by ipaddress
https://2130706433/    → decimal loopback, not parsed by ipaddress
```
**Status**: All bypass SSRF validation.

**Update (0.4.0)**: Fixed. All outbound URL checks now go through the shared `ampro.security.ssrf` guard. It parses every numeric form that `inet_aton` accepts (octal,
hex, single-integer and shortened dotted forms) before the blocked-range
check (`parse_ip_literal`).

### 3. RFC 9421: Encoded Newline Bypass (I4 fix bypassed)
```
URL with %0a (percent-encoded newline) → not caught by literal \n check
URL with U+2028/U+2029 (Unicode line separators) → not caught
URL with \x00 (null byte) → not caught
```
**Status**: Signature base injection still possible.

### 4. DNS Rebinding (I3 fix = docstring only)
```
HEAD request resolves DNS → passes validation
POST request re-resolves DNS → different IP
```
**Status**: Vulnerability fully intact. Fix was documentation, not code.

**Update (0.4.0)**: Fixed. All outbound URL checks now go through the shared `ampro.security.ssrf` guard with DNS pinning. `validate_url` / `validate_url_async` resolve
the hostname once and check every returned address.
`pinned_async_transport` then dials only those pinned addresses, while
the `Host` header and TLS SNI and certificate verification stay bound to
the original hostname. A second DNS answer can therefore not redirect
the request. Callback delivery (`ampro.transport.callback`) uses the
pinned transport.

### 5. Registry Resolve SSRF (I7 fix = docstring only)
```
cross_verification.py still calls fetch_agent_json(registry_url) directly
No validate_attachment_url() call before fetch
```
**Status**: Vulnerability fully intact.

---

## CRITICAL: New Vulnerabilities From Fixes

### 1. O(n) API Key Validation DoS (from C7 fix)
The constant-time fix iterates ALL stored keys on every validation.
- 100K keys → 100K iterations per validation
- At 1K req/s → 100M iterations/sec
- **Impact**: CPU exhaustion, renders auth unusable at scale

### 2. Legitimate Entry Eviction Enables Replay (from D1/D2 fix)
LRU eviction in dedup/nonce stores removes entries still within their TTL window.
- Attacker floods with 100K+1 unique messages
- Oldest 10K legitimate entries evicted
- Replaying those evicted messages now succeeds
- **Impact**: Defeats dedup and nonce replay protection

### 3. O(n log n) CPU Spike on Every Eviction (from D1/D2 fix)
`sorted(self._seen.items())` runs on every request over max_size.
- 100K entries → 1.7M comparisons per eviction
- At 5K req/s with constant overflow → sustained CPU load
- **Impact**: CPU DoS via eviction hammer

### 4. Random Rate Limiter Eviction Bypass (from D5 fix)
`random.sample()` evicts random senders, including the attacker.
- 10% chance per eviction cycle that attacker is evicted → rate limit reset
- Expected throughput: 6 req/s instead of intended 1 req/s
- **Impact**: Rate limiting partially defeated

### 5. Silent Streaming Event Loss (from D4 fix)
`except asyncio.QueueFull: pass` drops events without notification.
- Consumer has no way to know events were dropped
- No gap detection mechanism
- **Impact**: Silent data corruption in streaming

### 6. State Property Race Condition (D11 fix incomplete)
`threading.Lock()` protects `transition()` but NOT the `state` property getter.
- Also: threading.Lock is NOT safe with asyncio (blocks event loop)
- **Impact**: Stale state reads, asyncio deadlocks

---

## Logic Bugs Found

| # | Issue | Severity | File |
|---|-------|----------|------|
| L1 | TrustScore validator allows "owner" but calculate_trust_score() never produces it | MEDIUM | trust/score.py |
| L2 | Self-delegation (A→A) not prevented in chain validation | MEDIUM | delegation/chain.py |
| L3 | filter_agent_json() shallow copy — nested dicts still mutate original | MEDIUM | agent/visibility.py |
| L4 | caller_tier not validated in visibility filter — arbitrary strings accepted | MEDIUM | agent/visibility.py |
| L5 | Missing CONFIRMED→CLOSED transition — can't abort after confirm | MEDIUM | session/handshake.py |
| L6 | Jurisdiction conflict asymmetric — sender=[] no conflict, receiver=[] conflict | MEDIUM | compliance/jurisdiction.py |
| L7 | validate_jurisdiction_code() never called by check_jurisdiction_conflict() | LOW | compliance/jurisdiction.py |
| L8 | body_type=None treated as unknown extension, not error | LOW | core/body_schemas.py |
| L9 | Body type registry is case-sensitive — "Task.Create" silently passes through | LOW | core/body_schemas.py |
| L10 | Double registration silently overwrites without warning | LOW | core/body_schemas.py |
| L11 | validate_revocation_signature() defined but NEVER CALLED anywhere | CRITICAL | security/key_revocation.py |
| L12 | Sender tracker: blocked state persists after failure entry evicted | MEDIUM | security/sender_tracker.py |
| L13 | Capability truncation is silent — agents with 51+ capabilities fail | MEDIUM | core/message_middleware.py |

---

## Fix Effectiveness Summary

| Fix | Claimed | Reality | Verdict |
|-----|---------|---------|---------|
| C1: DID fail-closed | ✓ | Correctly returns EXTERNAL | **EFFECTIVE** |
| C2: Empty secret rejection | ✓ | ValueError raised, untested | **EFFECTIVE** (needs test) |
| C3: HMAC delimiter | ✓ | Inconsistent between derive/create | **PARTIAL** |
| C4: Revocation signature | ✓ | Function exists, never called | **ORPHANED** |
| C5: JWKS type check | ✓ | Defensive checks correct | **EFFECTIVE** |
| C6: WARNING logging | ✓ | Logging-dependent | **EFFECTIVE** |
| C7: Constant-time compare | ✓ | Correct but O(n) iteration | **REGRESSION** |
| C9: Cross-verify fail-closed | ✓ | No path returns true without check | **EFFECTIVE** |
| C13: Whitespace strip | ✓ | Correct, null bytes not covered | **EFFECTIVE** |
| I1: IPv6 zone ID | ✓ | Bypassed by percent-encoding, octal, hex | **BYPASSED** (bypasses fixed in 0.4.0, `ampro.security.ssrf`) |
| I2: ::1 added | ✓ | Correct | **EFFECTIVE** |
| I3: DNS rebinding | Docstring | Vulnerability intact | ~~NOT FIXED~~ **FIXED in 0.4.0** (shared `ampro.security.ssrf` guard with DNS pinning) |
| I4: Newline reject | ✓ | Bypassed by %0a, U+2028 | **BYPASSED** |
| I7: Registry SSRF | Docstring | Vulnerability intact | **NOT FIXED** |
| D1: Dedup bounded | ✓ | CPU DoS + legitimate data loss | **PARTIAL** |
| D2: Nonce bounded | ✓ | CPU DoS + replay possible | **PARTIAL** |
| D3: Stream bounded | ✓ | Slot exhaustion by attacker | **PARTIAL** |
| D4: Queue bounded | ✓ | Silent data loss | **PARTIAL** |
| D5: Rate limiter bounded | ✓ | Random eviction bypass | **PARTIAL** |
| D11: Thread-safe | ✓ | Property unprotected, asyncio-unsafe | **INCOMPLETE** |

---

## Remaining Attack Surface (Post v0.2.1)

### Memory: ~5 GB still achievable
- Streaming: 10K streams × 500KB = 5 GB (dominates)
- Stores: 4 × 20MB = 80 MB (bounded, acceptable)

### CPU: O(n log n) per eviction
- Dedup: 1.7M comparisons per eviction at 100K entries
- Nonce: same, but 1-hour window means constant eviction at 28+ req/s
- Rate limiter: random.sample() at 100K is O(n)

### Auth: Replay possible under load
- Nonce eviction allows replay of evicted nonces
- Dedup eviction allows duplicate message processing
- Attack cost: flood with 100K+1 unique IDs

### SSRF: Multiple bypass routes
- Percent-encoded IPs (fixed in 0.4.0)
- Octal/hex/decimal IPs (fixed in 0.4.0)
- DNS rebinding (fixed in 0.4.0: DNS pinning)
- Registry resolve URL

---

## Priority Fixes for v0.2.2

### P0: Must fix
1. URL-decode hostname before SSRF validation (`urllib.parse.unquote`)
2. Reject encoded newlines (%0a, %0d) and Unicode line separators in RFC 9421
3. Integrate `validate_revocation_signature()` into revocation handling
4. Use time-based eviction FIRST in dedup/nonce (evict expired before LRU)
5. Replace O(n) API key iteration with hashed lookup
6. Lock the `state` property in HandshakeStateMachine

### P1: Should fix
7. DNS pinning in callback delivery (resolve once, use IP)
8. Replace O(n log n) sort with heapq.nsmallest for eviction
9. Validate registry URL before fetching in cross_verification
10. Add CONFIRMED→CLOSED transition
11. Deep copy in filter_agent_json() for nested dicts
12. Validate caller_tier in visibility filter

### P2: Nice to have
13. Notify on dropped streaming events (counter header)
14. Validate jurisdiction codes before conflict check
15. Prevent self-delegation
16. Add tests for empty shared_secret ValueError
