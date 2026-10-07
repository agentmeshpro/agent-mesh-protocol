/**
 * POST /api/amp-demo/voice
 *
 * Speech-to-text leg of the AMP voice demo. The browser POSTs a single
 * audio blob (webm/opus from MediaRecorder) and gets back a transcript
 * plus a signed `voice.utterance` envelope describing the user→agent hop.
 *
 * The transcript then re-enters the regular AMP demo flow via the
 * existing /api/amp-demo POST, so STT is decoupled from the agent loop.
 */

import { transcribe } from 'ai'
import {
  ensureDemoKeys,
  signEnvelopeHeaders,
} from '@/demo/trust/keystore'
import { transcriptionModel } from '@/lib/models'

export const maxDuration = 30

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'

function makeId(prefix = 'msg'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

function makeNonce(): string {
  return `nonce-${crypto.randomUUID().slice(0, 12)}`
}

export async function POST(request: Request): Promise<Response> {
  let form: FormData
  try {
    form = await request.formData()
  } catch {
    return Response.json({ error: 'Expected multipart/form-data' }, { status: 400 })
  }

  const audio = form.get('audio')
  const targetAgent = (form.get('targetAgent') as string) === 'porter' ? 'porter' : 'bakery'

  if (!(audio instanceof Blob) || audio.size === 0) {
    return Response.json({ error: 'Missing audio blob' }, { status: 400 })
  }

  if (audio.size > 25 * 1024 * 1024) {
    return Response.json({ error: 'Audio too large (>25MB)' }, { status: 400 })
  }

  let transcript: string
  try {
    const result = await transcribe({
      model: transcriptionModel(),
      audio: new Uint8Array(await audio.arrayBuffer()),
      providerOptions: {
        openai: {
          language: 'en',
        },
      },
    })
    transcript = result.text.trim()
  } catch (err) {
    console.error('[amp-demo/voice] STT failed', err)
    return Response.json(
      { error: 'Transcription failed', details: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }

  if (!transcript) {
    return Response.json({ error: 'Empty transcript' }, { status: 422 })
  }

  // Build the signed voice.utterance envelope for the user→agent hop.
  // The audio itself isn't echoed back — the browser already has it —
  // but the envelope captures the transcript + a signed claim that it
  // came from the user-agent in this session.
  await ensureDemoKeys([YOUR_AGENT, SUNNY_BAKERY, PORTER_DELIVERY])

  const recipient = targetAgent === 'porter' ? PORTER_DELIVERY : SUNNY_BAKERY
  const id = makeId()
  const nonce = makeNonce()
  const signedAt = new Date().toISOString()

  const body = {
    transcript,
    mime: audio.type || 'audio/webm',
    duration_ms: null, // browser doesn't tell us; not worth a probe
    speaker: 'user',
  }

  const sigHeaders = await signEnvelopeHeaders({
    sender: YOUR_AGENT,
    recipient,
    id,
    body_type: 'voice.utterance',
    body,
    signed_at: signedAt,
    nonce,
  })

  const envelope = {
    sender: YOUR_AGENT,
    recipient,
    id,
    body_type: 'voice.utterance',
    headers: {
      'Protocol-Version': '0.3.0',
      Nonce: nonce,
      ...sigHeaders,
    },
    body,
  }

  return Response.json({ transcript, envelope })
}
