/**
 * Request guards shared by the demo API routes.
 *
 * Rate limiting is an in-memory token bucket per client IP plus a global
 * hourly budget and a concurrency cap. On Vercel, requests are spread
 * over several function instances and instances are recycled, so these
 * limits are BEST-EFFORT: each instance keeps its own counters and the
 * effective limit is roughly (limit x live instances). That is an
 * acceptable trade-off for a demo; put a shared store (Redis, Vercel KV,
 * a WAF rule) in front if you need hard guarantees. The AI Gateway's own
 * spend limits remain the real backstop.
 */

import { LIMITS } from './limits'
import { DEMO_ENABLED } from './site'

/** 404 for every demo API route while the demo is switched off (see DEMO_ENABLED). */
export function demoDisabled(): Response | null {
  return DEMO_ENABLED ? null : jsonError(404, 'Not found.')
}

// ---------------------------------------------------------------------------
// JSON errors. Messages are fixed strings: no exception text, stack traces
// or upstream error bodies ever reach the client.
// ---------------------------------------------------------------------------

export function jsonError(
  status: number,
  error: string,
  headers: Record<string, string> = {},
): Response {
  return Response.json(
    { error },
    { status, headers: { 'Cache-Control': 'no-store', ...headers } },
  )
}

// ---------------------------------------------------------------------------
// Logging. Never log request bodies or credentials; redact the gateway key
// and OIDC token if an upstream error happens to echo them.
// ---------------------------------------------------------------------------

export function logError(scope: string, err: unknown): void {
  const name = err instanceof Error ? err.name : typeof err
  let message = err instanceof Error ? err.message : ''
  for (const secret of [process.env.AI_GATEWAY_API_KEY, process.env.VERCEL_OIDC_TOKEN]) {
    if (secret && secret.length >= 8) message = message.split(secret).join('[redacted]')
  }
  message = message.replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[redacted]').slice(0, 300)
  console.error(`[${scope}] ${name}${message ? `: ${message}` : ''}`)
}

// ---------------------------------------------------------------------------
// Client identity
// ---------------------------------------------------------------------------

/**
 * Client IP as seen by the platform. Vercel overwrites x-forwarded-for
 * and sets x-real-ip, so these cannot be spoofed there. Behind other
 * proxies, make sure the proxy does the same.
 */
export function clientIp(request: Request): string {
  const real = request.headers.get('x-real-ip')?.trim()
  if (real) return real.slice(0, 64)
  const fwd = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  if (fwd) return fwd.slice(0, 64)
  return 'unknown'
}

// ---------------------------------------------------------------------------
// Same-origin check for state-changing requests
// ---------------------------------------------------------------------------

function allowedOrigins(request: Request): Set<string> {
  const out = new Set<string>()
  const host =
    request.headers.get('x-forwarded-host')?.split(',')[0]?.trim() ||
    request.headers.get('host')?.trim()
  if (host) {
    out.add(`https://${host}`.toLowerCase())
    out.add(`http://${host}`.toLowerCase())
  }
  for (const o of (process.env.AMP_DEMO_ALLOWED_ORIGINS ?? '').split(',')) {
    const t = o.trim().replace(/\/+$/, '').toLowerCase()
    if (t) out.add(t)
  }
  return out
}

/**
 * Browsers send Origin on every POST. Reject requests whose Origin is not
 * this site (or one listed in AMP_DEMO_ALLOWED_ORIGINS), and requests
 * without Origin that a browser marked as cross-site. This blocks other
 * websites from driving the demo with their visitors' browsers. It does
 * not stop scripted clients, which is what the rate limits are for.
 */
export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin')
  if (!origin) {
    const site = request.headers.get('sec-fetch-site')
    return site === 'same-origin' || site === 'none'
  }
  if (origin === 'null') return false
  return allowedOrigins(request).has(origin.replace(/\/+$/, '').toLowerCase())
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

type Bucket = { tokens: number; updated: number }

const MAX_TRACKED_IPS = 10_000
const buckets = new Map<string, Bucket>()
let globalWindowStart = Date.now()
let globalUsed = 0
let inFlight = 0

function takeIpTokens(ip: string, cost: number, now: number): number | null {
  const capacity = LIMITS.ratePerIpBurst
  const perMs = LIMITS.ratePerIpPerMinute / 60_000
  let b = buckets.get(ip)
  if (b) {
    b.tokens = Math.min(capacity, b.tokens + (now - b.updated) * perMs)
    b.updated = now
    // Refresh LRU position.
    buckets.delete(ip)
    buckets.set(ip, b)
  } else {
    if (buckets.size >= MAX_TRACKED_IPS) {
      // Evict the least recently used entry. Full buckets carry no state
      // worth keeping, so this only forgets idle clients.
      const oldest = buckets.keys().next().value
      if (oldest !== undefined) buckets.delete(oldest)
    }
    b = { tokens: capacity, updated: now }
    buckets.set(ip, b)
  }
  if (b.tokens >= cost) {
    b.tokens -= cost
    return null
  }
  return Math.ceil((cost - b.tokens) / perMs / 1000)
}

export type GuardOptions = {
  /** Tokens this request costs. Scale with how many model calls it can make. */
  cost: number
}

export type Guard = { release: () => void }

/**
 * Run all pre-flight checks for a model-spending POST. Returns either an
 * error Response to send as-is, or a guard whose `release()` must be
 * called when the request (including any stream) finishes.
 */
export function guardRequest(request: Request, opts: GuardOptions): Response | Guard {
  const disabled = demoDisabled()
  if (disabled) return disabled
  if (!isSameOrigin(request)) return jsonError(403, 'Cross-site requests are not allowed')

  const now = Date.now()
  if (now - globalWindowStart >= 3_600_000) {
    globalWindowStart = now
    globalUsed = 0
  }
  if (globalUsed + opts.cost > LIMITS.globalPerHour) {
    const retry = Math.ceil((globalWindowStart + 3_600_000 - now) / 1000)
    return jsonError(429, 'The demo is busy right now. Please try again later.', {
      'Retry-After': String(Math.max(1, retry)),
    })
  }
  if (inFlight >= LIMITS.maxConcurrent) {
    return jsonError(429, 'The demo is busy right now. Please try again shortly.', {
      'Retry-After': '5',
    })
  }
  const retryAfter = takeIpTokens(clientIp(request), opts.cost, now)
  if (retryAfter !== null) {
    return jsonError(429, 'Too many requests. Please slow down.', {
      'Retry-After': String(Math.max(1, retryAfter)),
    })
  }

  globalUsed += opts.cost
  inFlight++
  let released = false
  return {
    release() {
      if (released) return
      released = true
      inFlight = Math.max(0, inFlight - 1)
    },
  }
}

// ---------------------------------------------------------------------------
// Size-capped body reading
// ---------------------------------------------------------------------------

export class BodyTooLarge extends Error {
  constructor() {
    super('Request body too large')
    this.name = 'BodyTooLarge'
  }
}

/** Read the request body, failing fast once it exceeds `maxBytes`. */
export async function readBodyLimited(
  request: Request,
  maxBytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const declared = Number(request.headers.get('content-length') ?? '')
  if (Number.isFinite(declared) && declared > maxBytes) throw new BodyTooLarge()
  if (!request.body) return new Uint8Array(new ArrayBuffer(0))
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => {})
      throw new BodyTooLarge()
    }
    chunks.push(value)
  }
  const out = new Uint8Array(new ArrayBuffer(total))
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.byteLength
  }
  return out
}

/** Parse a size-capped JSON body. Returns `undefined` for invalid JSON. */
export async function readJsonLimited(request: Request, maxBytes: number): Promise<unknown> {
  const ct = request.headers.get('content-type') ?? ''
  if (!/^application\/json\b/i.test(ct)) return undefined
  const bytes = await readBodyLimited(request, maxBytes)
  try {
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return undefined
  }
}

/** Headers for an SSE response that must never be cached. */
export const SSE_HEADERS = {
  'Content-Type': 'text/event-stream; charset=utf-8',
  'Cache-Control': 'no-store, no-transform',
  'X-Accel-Buffering': 'no',
} as const
