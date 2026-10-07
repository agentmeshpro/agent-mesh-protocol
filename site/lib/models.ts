import { gateway } from 'ai'
import type {
  GatewayModelId,
  GatewaySpeechModelId,
  GatewayTranscriptionModelId,
} from '@ai-sdk/gateway'

/**
 * Model access for the demo routes.
 *
 * Model ids come ONLY from server environment variables. Nothing in a
 * request body can choose or override a model. Environment variables are
 * read at request time, never at build time, so `next build` works with
 * no secrets; a request made while configuration is missing gets a 503
 * (see `missingModelConfig`).
 */

const ENV = {
  key: 'AI_GATEWAY_API_KEY',
  language: 'AMP_DEMO_LANGUAGE_MODEL',
  speech: 'AMP_DEMO_SPEECH_MODEL',
  transcription: 'AMP_DEMO_TRANSCRIPTION_MODEL',
} as const

export type ModelKind = 'language' | 'speech' | 'transcription'

function env(name: string): string | undefined {
  const value = process.env[name]?.trim()
  return value ? value : undefined
}

function required(name: string): string {
  const value = env(name)
  if (!value) throw new Error(`${name} is not configured`)
  return value
}

/**
 * True when any variable needed for the given model kinds is missing.
 * Routes call this before doing any work and answer 503 when it is true.
 */
export function missingModelConfig(...kinds: ModelKind[]): boolean {
  if (!env(ENV.key)) return true
  return kinds.some((k) => !env(ENV[k]))
}

/** Configured language model id, for logging and usage accounting. */
export function languageModelId(): string {
  return env(ENV.language) ?? 'unconfigured'
}

/** Language model from the Vercel AI Gateway. */
export function languageModel() {
  required(ENV.key)
  return gateway.languageModel(required(ENV.language) as GatewayModelId)
}

/** Speech model from the Vercel AI Gateway. */
export function speechModel() {
  required(ENV.key)
  return gateway.speechModel(required(ENV.speech) as GatewaySpeechModelId)
}

/** Transcription model from the Vercel AI Gateway. */
export function transcriptionModel() {
  required(ENV.key)
  return gateway.transcriptionModel(
    required(ENV.transcription) as GatewayTranscriptionModelId,
  )
}
