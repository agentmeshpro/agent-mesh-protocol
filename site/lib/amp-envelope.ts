/**
 * Builds the AMP envelopes the demo streams to the browser.
 *
 * Shape follows the 0.4.0 wire format (docs/WIRE-BINDING.md §5.1.1 and
 * `ampro.core.envelope.AgentMessage`): `sender`, `recipient`, `id`
 * (UUID v4), `body_type`, `headers` (string values only) and `body`.
 * Bodies of protocol-defined task types carry the fields their schemas
 * require (`ampro.core.body_schemas`): `task_id` everywhere, `expires_at`
 * on task.quote, `reason` + `prompt` on task.input_required, `result` on
 * task.complete. Demo-only body types are reverse-domain (§18.1).
 *
 * The signature is the demo's simplified scheme (see
 * demo/trust/envelope-crypto.ts), NOT the RFC 9421 profile of §12.15.
 */

import { PROTOCOL_VERSION } from '@/demo/body-types'
import { signEnvelopeHeaders } from '@/demo/trust/keystore'
import { requestTaskIds } from './request-context'

export type AMPEnvelope = {
  sender: string
  recipient: string
  id: string
  body_type: string
  headers: Record<string, string>
  body: Record<string, unknown>
}

function hex(bytes: number): string {
  const b = new Uint8Array(bytes)
  crypto.getRandomValues(b)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

/** Message id: UUID v4, as WIRE-BINDING §5.1.3 recommends. */
export function makeMessageId(): string {
  return crypto.randomUUID()
}

/** Demo-local identifiers (task ids, decision ids). */
export function makeId(prefix = 'id'): string {
  return `${prefix}-${hex(8)}`
}

/** W3C trace-context sized ids, as in the WIRE-BINDING examples. */
export function makeTraceId(): string {
  return hex(16)
}

export function makeSpanId(): string {
  return hex(8)
}

export function makeNonce(): string {
  return `n-${hex(8)}`
}

const TASK_TYPES_NEEDING_ID = new Set([
  'task.acknowledge',
  'task.progress',
  'task.quote',
  'task.input_required',
  'task.complete',
  'task.response',
])

function pairKey(a: string, b: string): string {
  return a < b ? `${a}|${b}` : `${b}|${a}`
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

/**
 * Fill the fields the 0.4.0 body schemas require, without overwriting
 * anything the caller set. One task id is shared by all envelopes
 * between the same two agents within a request.
 */
function conformBody(
  sender: string,
  recipient: string,
  bodyType: string,
  body: Record<string, unknown>,
): Record<string, unknown> {
  if (!bodyType.startsWith('task.')) return body
  const out: Record<string, unknown> = { ...body }
  const tasks = requestTaskIds()
  const key = pairKey(sender, recipient)

  if (bodyType === 'task.create') {
    const id = str(out.task_id) ?? makeId('task')
    out.task_id = id
    tasks.set(key, id)
    if (!str(out.description)) out.description = 'Demo task'
    if (typeof out.description === 'string' && out.description.length > 8192) {
      out.description = out.description.slice(0, 8192)
    }
    return out
  }

  if (TASK_TYPES_NEEDING_ID.has(bodyType) && !str(out.task_id)) {
    let id = tasks.get(key)
    if (!id) {
      id = makeId('task')
      tasks.set(key, id)
    }
    out.task_id = id
  }

  const text = str(out.message) ?? ''
  if (bodyType === 'task.quote' && !str(out.expires_at)) {
    out.expires_at = new Date(Date.now() + 15 * 60_000).toISOString()
  }
  if (bodyType === 'task.input_required') {
    if (!str(out.prompt)) out.prompt = text
    if (!str(out.reason)) out.reason = 'A choice from the customer is needed to continue'
  }
  if (bodyType === 'task.complete' && out.result === undefined) {
    out.result = text
  }
  if (bodyType === 'task.response' && !str(out.text)) {
    out.text = text
  }
  if (bodyType === 'task.error' && !str(out.reason)) {
    out.reason = 'error'
  }
  return out
}

/**
 * Build and sign one envelope. `headers` may add standard headers such
 * as Trace-Id, Trust-Tier (internal | owner | verified | external) or
 * In-Reply-To; they are merged after the protocol and signature headers.
 */
export async function makeEnvelope(
  sender: string,
  recipient: string,
  bodyType: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<AMPEnvelope> {
  const id = makeMessageId()
  const nonce = makeNonce()
  const signed_at = new Date().toISOString()
  const finalBody = conformBody(sender, recipient, bodyType, body)

  const sigHeaders = await signEnvelopeHeaders({
    sender,
    recipient,
    id,
    body_type: bodyType,
    body: finalBody,
    signed_at,
    nonce,
  })

  return {
    sender,
    recipient,
    id,
    body_type: bodyType,
    headers: {
      'Protocol-Version': PROTOCOL_VERSION,
      Nonce: nonce,
      ...headers,
      ...sigHeaders,
    },
    body: finalBody,
  }
}
