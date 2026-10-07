/**
 * Envelope canonicalization + signing / verification helpers.
 *
 * SIMPLIFIED ILLUSTRATION — NOT THE AMP SIGNATURE PROFILE.
 *
 * AMP 0.4.0 signs HTTP requests with its RFC 9421 profile
 * (docs/WIRE-BINDING.md §12.15): Signature / Signature-Input HTTP headers
 * covering "@method", "@target-uri", "@authority" and an RFC 9530
 * content-digest of the body, label sig1, alg "ed25519", with required
 * created / keyid / nonce parameters and a 300 s freshness window.
 *
 * The demo never makes real HTTP hops between agents, so there is no
 * method, target URI or authority to cover. Instead it signs a
 * deterministic JSON serialization (keys sorted, no whitespace) of
 *   { sender, recipient, id, body_type, body, signed_at, nonce }
 * with Ed25519 and carries the result in custom envelope headers
 * (WIRE-BINDING §18.2 recommends the X- prefix for custom headers):
 *   - X-Signature      — base64url(Ed25519(canonical))
 *   - X-Signer-Key     — base64url(raw public key) used for the signature
 *   - X-Signed-At      — ISO timestamp included in the canonical form
 *   - X-Signature-Alg  — "Ed25519"
 *
 * What it does show faithfully: Ed25519 signatures, a per-message nonce,
 * and a verifier that resolves the sender's key from a directory and
 * fails closed on any mismatch. The UI labels it as a simplified scheme.
 */

export type TrustState = 'valid' | 'invalid' | 'unsigned' | 'pending'

export interface SignedEnvelopeFields {
  sender: string
  recipient: string
  id: string
  body_type: string
  body: Record<string, unknown>
  signed_at: string
  nonce: string
}

const textEncoder = new TextEncoder()

/**
 * Deterministic JSON serialization. Keys sorted, no whitespace. This is
 * what gets signed on both sides — any disagreement is a verification
 * failure, which is what we want.
 */
export function canonicalize(fields: SignedEnvelopeFields): string {
  return stableStringify(fields)
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return (
    '{' +
    keys
      .map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k]))
      .join(',') +
    '}'
  )
}

export function b64urlEncode(bytes: Uint8Array): string {
  let str = ''
  for (const b of bytes) str += String.fromCharCode(b)
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  const bin = atob(normalized)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Compute a short SHA-256 fingerprint of a base64url-encoded public key.
 * Returns the first 8 hex chars, formatted as "ab12:cd34" — short enough
 * to display, long enough to be comparison-meaningful for humans, and
 * doesn't expose the raw key bytes themselves.
 */
export async function keyFingerprint(b64Key: string): Promise<string> {
  const raw = b64urlDecode(b64Key)
  const u8 = new Uint8Array(raw.byteLength)
  u8.set(raw)
  const hashBuf = await crypto.subtle.digest('SHA-256', u8.buffer.slice(0))
  const hashBytes = new Uint8Array(hashBuf)
  const hex = Array.from(hashBytes.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return `${hex.slice(0, 4)}:${hex.slice(4, 8)}`
}
