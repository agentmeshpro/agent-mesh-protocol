/**
 * Envelope canonicalization + signing / verification helpers.
 *
 * An AMP envelope is signed over a deterministic JSON serialization of
 *   { sender, recipient, id, body_type, body, signed_at, nonce }
 * using Ed25519. The signature + signer public-key fingerprint live in
 * envelope.headers:
 *   - X-Signature      — base64url(Ed25519(canonical))
 *   - X-Signer-Key     — base64url(public-key) used for the signature
 *   - X-Signed-At      — ISO timestamp included in the canonical form
 *   - X-Signature-Alg  — "Ed25519"
 *
 * The public key for each agent must resolve to the same bytes advertised
 * at /.well-known/amp-keys/<sender>.json . If it doesn't, verification
 * fails closed. If anything along the chain is missing, we return
 * 'unsigned' rather than 'valid'.
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
