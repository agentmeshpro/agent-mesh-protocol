/**
 * Abuse limits for the public demo API routes.
 *
 * Every route spends the site owner's AI Gateway credit, so every limit
 * has a conservative default and can be tuned with an environment
 * variable. Values are read once per server instance. Invalid or
 * non-positive values fall back to the default.
 */

function intEnv(name: string, fallback: number, min = 1, max = Number.MAX_SAFE_INTEGER): number {
  const raw = process.env[name]?.trim()
  if (!raw) return fallback
  const n = Number(raw)
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < min || n > max) return fallback
  return n
}

export const LIMITS = {
  /** Token-bucket capacity per client IP (burst size). */
  ratePerIpBurst: intEnv('AMP_DEMO_RATE_BURST', 8),
  /** Tokens added back per minute per client IP. */
  ratePerIpPerMinute: intEnv('AMP_DEMO_RATE_PER_MINUTE', 4),
  /** Tokens per hour across all clients on one server instance. */
  globalPerHour: intEnv('AMP_DEMO_GLOBAL_PER_HOUR', 400),
  /** Model-spending requests running at once on one server instance. */
  maxConcurrent: intEnv('AMP_DEMO_MAX_CONCURRENT', 16),

  /** Characters in one user message (chat text, transcript, answer, brief). */
  maxMessageChars: intEnv('AMP_DEMO_MAX_MESSAGE_CHARS', 1000, 1, 8192),
  /** Entries accepted in a history array. Larger arrays are rejected. */
  maxHistoryEntries: intEnv('AMP_DEMO_MAX_HISTORY_ENTRIES', 40, 1, 200),
  /** Characters in one history entry. */
  maxHistoryEntryChars: intEnv('AMP_DEMO_MAX_HISTORY_ENTRY_CHARS', 4000, 1, 20000),
  /** History entries actually forwarded to the model (the most recent ones). */
  historyTurnsForModel: intEnv('AMP_DEMO_HISTORY_TURNS_FOR_MODEL', 16, 1, 200),
  /** JSON request body size in bytes. */
  maxJsonBodyBytes: intEnv('AMP_DEMO_MAX_JSON_BYTES', 256 * 1024, 1024, 4 * 1024 * 1024),

  /** Audio upload size for /voice in bytes (roughly 60 s of browser opus). */
  maxAudioBytes: intEnv('AMP_DEMO_MAX_AUDIO_BYTES', 1024 * 1024, 1024, 25 * 1024 * 1024),
  /** Longest transcribed audio accepted, in seconds. */
  maxAudioSeconds: intEnv('AMP_DEMO_MAX_AUDIO_SECONDS', 60, 1, 600),

  /** Hard ceiling on output tokens for any single model call. */
  maxOutputTokens: intEnv('AMP_DEMO_MAX_OUTPUT_TOKENS', 500, 8, 4000),
  /** Characters sent to text-to-speech per clip. */
  maxSpeechChars: intEnv('AMP_DEMO_MAX_SPEECH_CHARS', 600, 50, 4096),
  /** Wall-clock budget for one model call, in milliseconds. */
  modelCallTimeoutMs: intEnv('AMP_DEMO_MODEL_TIMEOUT_MS', 25_000, 1000, 120_000),
  /** Wall-clock budget for a whole request, in milliseconds. */
  requestTimeoutMs: intEnv('AMP_DEMO_REQUEST_TIMEOUT_MS', 55_000, 1000, 300_000),
} as const

/** Clamp a per-call output-token request to the global ceiling. */
export function capTokens(requested: number): number {
  return Math.min(requested, LIMITS.maxOutputTokens)
}
