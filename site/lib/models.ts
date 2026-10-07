import { gateway } from 'ai'
import type {
  GatewayModelId,
  GatewaySpeechModelId,
  GatewayTranscriptionModelId,
} from '@ai-sdk/gateway'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) {
    throw new Error(`${name} is required`)
  }
  return value
}

function requireGateway(): void {
  required('AI_GATEWAY_API_KEY')
}

/** Language model from the Vercel AI Gateway. */
export function languageModel() {
  requireGateway()
  return gateway.languageModel(required('AMP_DEMO_LANGUAGE_MODEL') as GatewayModelId)
}

/** Speech model from the Vercel AI Gateway. */
export function speechModel() {
  requireGateway()
  return gateway.speechModel(required('AMP_DEMO_SPEECH_MODEL') as GatewaySpeechModelId)
}

/** Transcription model from the Vercel AI Gateway. */
export function transcriptionModel() {
  requireGateway()
  return gateway.transcriptionModel(
    required('AMP_DEMO_TRANSCRIPTION_MODEL') as GatewayTranscriptionModelId,
  )
}
