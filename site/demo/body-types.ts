/**
 * Demo-specific AMP body types.
 *
 * WIRE-BINDING §18.1: custom body types use reverse-domain notation and
 * must not reuse the protocol's own dot-namespaces. The demo's agents
 * live under example.com, so its extension types do too. Real discovery
 * in AMP uses `GET /.well-known/agent.json` and the registry; these
 * directory messages are an illustration of that step.
 */
export const VOICE_UTTERANCE = 'com.example.demo.voice_utterance'
export const DIRECTORY_QUERY = 'com.example.demo.directory_query'
export const DIRECTORY_RESPONSE = 'com.example.demo.directory_response'

/** Protocol version the demo envelopes declare (WIRE-BINDING, 1.0.0). */
export const PROTOCOL_VERSION = '1.0.0'
