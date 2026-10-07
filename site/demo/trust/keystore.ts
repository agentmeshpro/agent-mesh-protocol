/**
 * In-process Ed25519 keystore for demo agents.
 *
 * Keys are generated once per server process and remembered in module
 * state. This is deliberate — the point of the demo is to show signature
 * verification working end-to-end, not to rotate keys or persist them
 * across deploys. On restart, new keys are issued; public keys are served
 * from the well-known endpoint so the client always fetches whatever the
 * process currently holds.
 *
 * Uses Node 20's global Web Crypto API (no 'crypto' import required) so
 * the same verification code works server-side and in the browser.
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

  const kp = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const record: KeyRecord = {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    publicKeyRawB64: b64urlEncode(rawPub),
  }
  store.set(agent, record)
  return record
}

/**
 * Produce a signed envelope. Returns the full envelope object with
 * X-Signature / X-Signer-Key / X-Signed-At / X-Signature-Alg headers
 * populated. `fields.signed_at` and `fields.nonce` should be set by the
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
