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
 *
 * Gateway credentials: `AI_GATEWAY_API_KEY` if set, otherwise the Vercel
 * OIDC token. The AI SDK reads the OIDC token itself, from the
 * `x-vercel-oidc-token` request header on Vercel or `VERCEL_OIDC_TOKEN`
 * locally (`vercel env pull`), so no key is needed on a Vercel deployment.
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

/**
 * True when the gateway has something to authenticate with: an API key,
 * a local OIDC token, or a Vercel runtime, which sends the OIDC token as a
 * request header.
 */
function hasGatewayAuth(): boolean {
  return Boolean(env(ENV.key) || env('VERCEL_OIDC_TOKEN') || env('VERCEL'))
}

function requireGatewayAuth(): void {
  if (!hasGatewayAuth()) {
    throw new Error(`${ENV.key} or a Vercel OIDC token is not configured`)
  }
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
  if (!hasGatewayAuth()) return true
  return kinds.some((k) => !env(ENV[k]))
}

/** Configured language model id, for logging and usage accounting. */
export function languageModelId(): string {
  return env(ENV.language) ?? 'unconfigured'
}

/** Language model from the Vercel AI Gateway. */
export function languageModel() {
  requireGatewayAuth()
  return gateway.languageModel(required(ENV.language) as GatewayModelId)
}

/** Speech model from the Vercel AI Gateway. */
export function speechModel() {
  requireGatewayAuth()
  return gateway.speechModel(required(ENV.speech) as GatewaySpeechModelId)
}

/** Transcription model from the Vercel AI Gateway. */
export function transcriptionModel() {
  requireGatewayAuth()
  return gateway.transcriptionModel(
    required(ENV.transcription) as GatewayTranscriptionModelId,
  )
}
