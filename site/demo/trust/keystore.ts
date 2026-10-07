/**
 * Server-side Ed25519 keystore for the demo agents.
 *
 * PRIVATE KEYS NEVER LEAVE THIS MODULE. They are held in server memory
 * only: never serialized, never persisted, never logged, and never sent
 * to the browser. The browser only receives public keys (from
 * /api/amp-demo/keys) and verifies signatures with them.
 *
 * Two modes:
 * - AMP_DEMO_SIGNING_SEED unset (default): each server instance generates
 *   fresh ephemeral keys on first use. Simple, but on platforms that run
 *   several instances (Vercel) the browser may fetch the key directory
 *   from one instance and receive envelopes signed by another; the
 *   client refetches once on a mismatch, which usually recovers.
 * - AMP_DEMO_SIGNING_SEED set: every instance derives the same keys,
 *   per agent, as HMAC-SHA256(seed, agent) used as the Ed25519 private
 *   seed. Use a long random value and treat it as a secret. It only
 *   protects demo signatures; it grants no other access.
 *
 * Uses the global Web Crypto API so the same verification code runs in
 * the browser.
 */

import {
  b64urlEncode,
  canonicalize,
  type SignedEnvelopeFields,
} from './envelope-crypto'

type KeyRecord = {
  publicKey: CryptoKey
  privateKey: CryptoKey
  publicKeyRawB64: string
}

// Survive Next.js dev HMR reloads. Without this, every file save
// regenerates keys and invalidates every signature the browser already
// holds — causing mass INVALID pills until the page is reloaded.
type Globalish = typeof globalThis & {
  __ampKeystore?: Map<string, KeyRecord>
}
const g = globalThis as Globalish
const store: Map<string, KeyRecord> =
  g.__ampKeystore ?? (g.__ampKeystore = new Map<string, KeyRecord>())

/**
 * Generate or retrieve the keypair for an agent identified by its
 * agent:// URL. Same agent → same keypair for the lifetime of the
 * process.
 */
export async function getAgentKeys(agent: string): Promise<KeyRecord> {
  const existing = store.get(agent)
  if (existing) return existing

  const pending = inflight.get(agent)
  if (pending) return pending
  const p = createKeys(agent)
    .then((record) => {
      store.set(agent, record)
      return record
    })
    .finally(() => inflight.delete(agent))
  inflight.set(agent, p)
  return p
}

const inflight = new Map<string, Promise<KeyRecord>>()

// PKCS#8 DER prefix for an Ed25519 private key; the 32-byte seed follows.
const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

async function createKeys(agent: string): Promise<KeyRecord> {
  const seed = process.env.AMP_DEMO_SIGNING_SEED?.trim()
  if (!seed) {
    const kp = (await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
    return {
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      publicKeyRawB64: b64urlEncode(rawPub),
    }
  }

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(textBytes(seed)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const derived = new Uint8Array(
    await crypto.subtle.sign('HMAC', hmacKey, toArrayBuffer(textBytes(`amp-demo-ed25519:${agent}`))),
  )
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32)
  pkcs8.set(PKCS8_ED25519_PREFIX)
  pkcs8.set(derived.subarray(0, 32), PKCS8_ED25519_PREFIX.length)
  // Extractable only so the public half can be read back as a JWK; the
  // private key object itself is never exported anywhere.
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(pkcs8),
    { name: 'Ed25519' },
    true,
    ['sign'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', privateKey)
  if (!jwk.x) throw new Error('Ed25519 key derivation failed')
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    { name: 'Ed25519' },
    true,
    ['verify'],
  )
  return { publicKey, privateKey, publicKeyRawB64: jwk.x }
}

/**
 * Produce the demo signature headers for an envelope (simplified scheme,
 * see envelope-crypto.ts). Returns X-Signature / X-Signer-Key /
 * X-Signed-At / X-Signature-Alg. `fields.signed_at` and `fields.nonce` should be set by the
 * caller (or left to the wrapper helper in the route).
 */
export async function signEnvelopeHeaders(
  fields: SignedEnvelopeFields,
): Promise<{
  'X-Signature': string
  'X-Signer-Key': string
  'X-Signed-At': string
  'X-Signature-Alg': string
}> {
  const keys = await getAgentKeys(fields.sender)
  const canonical = canonicalize(fields)
  const canonicalBytes = textBytes(canonical)
  const sig = new Uint8Array(
    await crypto.subtle.sign('Ed25519', keys.privateKey, toArrayBuffer(canonicalBytes)),
  )
  return {
    'X-Signature': b64urlEncode(sig),
    'X-Signer-Key': keys.publicKeyRawB64,
    'X-Signed-At': fields.signed_at,
    'X-Signature-Alg': 'Ed25519',
  }
}

function textBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

/**
 * Copy a Uint8Array into a fresh ArrayBuffer so WebCrypto doesn't
 * complain about SharedArrayBuffer-ish inputs under strict typings.
 */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u8.byteLength)
  new Uint8Array(out).set(u8)
  return out
}

/**
 * Directory dump — used by the well-known endpoint so the client can
 * build a stable map of { agent: publicKey }. The browser fetches this
 * once at demo start; every verification afterward is client-side.
 */
export async function listPublicKeys(): Promise<Record<string, string>> {
  const out: Record<string, string> = {}
  for (const [agent, rec] of store) {
    out[agent] = rec.publicKeyRawB64
  }
  return out
}

/**
 * Ensure all three demo agents have keys at module load so the
 * well-known endpoint isn't empty before any envelope is sent.
 */
export async function ensureDemoKeys(agents: string[]): Promise<void> {
  await Promise.all(agents.map(getAgentKeys))
}
