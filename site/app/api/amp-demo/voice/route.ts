/**
 * POST /api/amp-demo/voice
 *
 * Speech-to-text leg of the AMP voice demo. The browser POSTs a single
 * audio blob (webm/opus from MediaRecorder) and gets back a transcript
 * plus a signed voice-utterance envelope describing the user→agent hop.
 *
 * The transcript then re-enters the regular AMP demo flow via the
 * existing /api/amp-demo POST, so STT is decoupled from the agent loop.
 *
 * Limits: the upload is capped at AMP_DEMO_MAX_AUDIO_BYTES before it is
 * parsed, only audio MIME types are accepted, and transcripts longer than
 * AMP_DEMO_MAX_AUDIO_SECONDS (when the provider reports a duration) or
 * AMP_DEMO_MAX_MESSAGE_CHARS are rejected. The byte cap is what bounds
 * cost up front; the browser also stops recording after a fixed time.
 */

import { transcribe } from 'ai'
import { z } from 'zod'
import { ensureDemoKeys } from '@/demo/trust/keystore'
import { VOICE_UTTERANCE } from '@/demo/body-types'
import { missingModelConfig, transcriptionModel } from '@/lib/models'
import { makeEnvelope } from '@/lib/amp-envelope'
import {
  BodyTooLarge,
  guardRequest,
  jsonError,
  logError,
  readBodyLimited,
} from '@/lib/api-guard'
import { LIMITS } from '@/lib/limits'
import { modelSignal, requestSignal, withRequestContext } from '@/lib/request-context'

export const maxDuration = 30

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'

const ALLOWED_AUDIO = /^audio\/(webm|ogg|mp4|mpeg|wav|x-wav|aac)(;.*)?$/i
// Multipart framing around the audio part.
const MULTIPART_OVERHEAD = 16 * 1024

const VoiceForm = z.object({
  targetAgent: z.enum(['bakery', 'porter']).default('bakery'),
})

export async function POST(request: Request): Promise<Response> {
  const guard = guardRequest(request, { cost: 1 })
  if (guard instanceof Response) return guard
  try {
    if (missingModelConfig('transcription')) {
      return jsonError(503, 'The demo is not configured on this deployment.')
    }

    const contentType = request.headers.get('content-type') ?? ''
    if (!/^multipart\/form-data\b/i.test(contentType)) {
      return jsonError(415, 'Expected multipart/form-data')
    }

    let form: FormData
    try {
      const bytes = await readBodyLimited(request, LIMITS.maxAudioBytes + MULTIPART_OVERHEAD)
      form = await new Response(bytes, { headers: { 'content-type': contentType } }).formData()
    } catch (err) {
      if (err instanceof BodyTooLarge) return jsonError(413, 'Recording is too long')
      return jsonError(400, 'Invalid form data')
    }

    const audio = form.get('audio')
    const target = form.get('targetAgent')
    const fields = VoiceForm.safeParse({
      targetAgent: typeof target === 'string' ? target : undefined,
    })
    if (!fields.success) return jsonError(400, 'Invalid request')
    if (!(audio instanceof Blob) || audio.size === 0) {
      return jsonError(400, 'Missing audio')
    }
    if (audio.size > LIMITS.maxAudioBytes) return jsonError(413, 'Recording is too long')
    const mime = audio.type || 'audio/webm'
    if (!ALLOWED_AUDIO.test(mime)) return jsonError(415, 'Unsupported audio format')

    const signal = requestSignal(request, Math.min(LIMITS.requestTimeoutMs, 28_000))
    return await withRequestContext(signal, async () => {
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
          abortSignal: modelSignal(),
        })
        if (
          typeof result.durationInSeconds === 'number' &&
          result.durationInSeconds > LIMITS.maxAudioSeconds
        ) {
          return jsonError(413, 'Recording is too long')
        }
        transcript = result.text.trim()
      } catch (err) {
        logError('amp-demo/voice', err)
        return jsonError(502, 'Transcription failed. Please try again.')
      }

      if (!transcript) return jsonError(422, 'Empty transcript')
      if (transcript.length > LIMITS.maxMessageChars) {
        return jsonError(413, 'Recording is too long')
      }

      // Signed voice-utterance envelope for the user→agent hop. The audio
      // itself isn't echoed back (the browser already has it); the
      // envelope carries the transcript and a signed claim that it came
      // from the user's agent.
      await ensureDemoKeys([YOUR_AGENT, SUNNY_BAKERY, PORTER_DELIVERY])
      const recipient = fields.data.targetAgent === 'porter' ? PORTER_DELIVERY : SUNNY_BAKERY
      const envelope = await makeEnvelope(YOUR_AGENT, recipient, VOICE_UTTERANCE, {
        transcript,
        mime,
        speaker: 'user',
      })

      return Response.json(
        { transcript, envelope },
        { headers: { 'Cache-Control': 'no-store' } },
      )
    })
  } catch (err) {
    logError('amp-demo/voice', err)
    return jsonError(500, 'Something went wrong. Please try again.')
  } finally {
    guard.release()
  }
}
