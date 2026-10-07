'use client'

/**
 * Client-side envelope verification. Fetches the directory of public
 * keys from /api/amp-demo/keys once and caches CryptoKey objects. Every
 * envelope's signature is verified against:
 *   1. Presence of X-Signature, X-Signer-Key, X-Signed-At, X-Signature-Alg
 *   2. X-Signer-Key must exactly match the directory's public key for
 *      the envelope's `sender`. If it doesn't, we treat the envelope as
 *      INVALID — a matching signature by the wrong key is still a
 *      trust failure.
 *   3. Ed25519(canonical(envelope)) against that public key must return true
 *
 * All verification runs in the browser against locally-cached keys —
 * the server is not trusted to self-attest.
 */

import {
  b64urlDecode,
  canonicalize,
  keyFingerprint,
  type SignedEnvelopeFields,
  type TrustState,
} from './envelope-crypto'

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u8.byteLength)
  new Uint8Array(out).set(u8)
  return out
}

type KeyDir = {
  alg: 'Ed25519'
  keys: Record<string, string> // agent-url -> base64url(raw public key)
}

let keyDirPromise: Promise<KeyDir | null> | null = null
const importedKeyCache = new Map<string, CryptoKey>()

function fetchKeyDir(): Promise<KeyDir | null> {
  return (async () => {
    try {
      const res = await fetch('/api/amp-demo/keys', { cache: 'no-store' })
      if (!res.ok) return null
      return (await res.json()) as KeyDir
    } catch {
      return null
    }
  })()
}

async function loadKeyDirectory(): Promise<KeyDir | null> {
  if (!keyDirPromise) keyDirPromise = fetchKeyDir()
  return keyDirPromise
}

/**
 * Force a refresh of the key directory. Used when verification fails
 * because of a key-mismatch / unknown sender — the server may have
 * rotated keys (HMR restart in dev) and our cached snapshot is stale.
 */
async function refreshKeyDirectory(): Promise<KeyDir | null> {
  keyDirPromise = fetchKeyDir()
  importedKeyCache.clear()
  return keyDirPromise
}

async function importKey(
  agent: string,
  keyB64: string,
): Promise<CryptoKey | null> {
  const cached = importedKeyCache.get(agent)
  if (cached) return cached
  try {
    const raw = b64urlDecode(keyB64)
    const k = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(raw),
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    importedKeyCache.set(agent, k)
    return k
  } catch {
    return null
  }
}

export interface VerifyResult {
  state: TrustState
  reason?: string
  /** SHA-256 fingerprint of the key actually used on the wire. */
  signerFingerprint?: string
  /** SHA-256 fingerprint of the key the directory expects for this sender. */
  expectedFingerprint?: string
  /** True if those fingerprints match. */
  signerKeyMatchesDirectory?: boolean
}

export async function verifyEnvelope(envelope: {
  sender: string
  recipient: string
  id: string
  body_type: string
  headers: Record<string, string>
  body: Record<string, unknown>
}): Promise<VerifyResult> {
  const first = await verifyOnce(envelope)
  // If the cached directory is stale (server keys rotated, e.g. dev HMR
  // restart), the most common failures are "Sender not in key directory"
  // or "Signer key does not match directory entry". Refetch once and try
  // again — this turns a confusing red pill into the correct green one
  // without forcing a manual page reload.
  if (
    first.state === 'invalid' &&
    (first.reason === 'Sender not in key directory' ||
      first.reason === 'Signer key does not match directory entry')
  ) {
    await refreshKeyDirectory()
    return verifyOnce(envelope)
  }
  return first
}

async function verifyOnce(envelope: {
  sender: string
  recipient: string
  id: string
  body_type: string
  headers: Record<string, string>
  body: Record<string, unknown>
}): Promise<VerifyResult> {
  const sig = envelope.headers['X-Signature']
  const signerKey = envelope.headers['X-Signer-Key']
  const signedAt = envelope.headers['X-Signed-At']
  const alg = envelope.headers['X-Signature-Alg']
  const nonce = envelope.headers['Nonce']

  if (!sig || !signerKey || !signedAt || !alg) {
    return { state: 'unsigned', reason: 'Missing signature headers' }
  }
  if (alg !== 'Ed25519') {
    return { state: 'invalid', reason: `Unsupported alg: ${alg}` }
  }
  if (!nonce) {
    return { state: 'invalid', reason: 'Missing nonce' }
  }

  const dir = await loadKeyDirectory()
  if (!dir) {
    return { state: 'pending', reason: 'Key directory unavailable' }
  }

  const expected = dir.keys[envelope.sender]
  const matches = Boolean(expected) && expected === signerKey
  const signerFingerprint = await keyFingerprint(signerKey)
  const expectedFingerprint = expected ? await keyFingerprint(expected) : undefined

  if (!expected) {
    return {
      state: 'invalid',
      reason: 'Sender not in key directory',
      signerFingerprint,
    }
  }
  if (!matches) {
    return {
      state: 'invalid',
      reason: 'Signer key does not match directory entry',
      signerFingerprint,
      expectedFingerprint,
      signerKeyMatchesDirectory: false,
    }
  }

  const pubKey = await importKey(envelope.sender, expected)
  if (!pubKey) {
    return { state: 'invalid', reason: 'Failed to import public key' }
  }

  const fields: SignedEnvelopeFields = {
    sender: envelope.sender,
    recipient: envelope.recipient,
    id: envelope.id,
    body_type: envelope.body_type,
    body: envelope.body,
    signed_at: signedAt,
    nonce,
  }
  const canonical = canonicalize(fields)

  let ok = false
  try {
    const sigBytes = b64urlDecode(sig)
    const canonicalBytes = new TextEncoder().encode(canonical)
    ok = await crypto.subtle.verify(
      'Ed25519',
      pubKey,
      toArrayBuffer(sigBytes),
      toArrayBuffer(canonicalBytes),
    )
  } catch {
    ok = false
  }

  if (!ok) {
    return {
      state: 'invalid',
      reason: 'Signature does not verify',
      signerFingerprint,
      expectedFingerprint,
      signerKeyMatchesDirectory: true,
    }
  }

  return {
    state: 'valid',
    signerFingerprint,
    expectedFingerprint,
    signerKeyMatchesDirectory: true,
  }
}
