# AMP site

Landing page and interactive demo for the Agent Mesh Protocol (release 0.4.0).

This directory is a standalone Next.js app. The Python package at the repository root is not part of it. Model calls go through the [Vercel AI Gateway](https://vercel.com/docs/ai-gateway) using AI SDK 7 (`gateway` from `ai`); there is no separate provider client.

## Run

Requires Node 20+ (CI uses Node 22).

```bash
cd site
cp .env.example .env.local   # fill AI_GATEWAY_API_KEY and the three AMP_DEMO_* model ids
npm ci
npm run dev                  # http://localhost:3000
```

Checks:

```bash
npm run type-check
npm run build                # needs no environment variables
```

`npm run build` works with no secrets. Configuration is read at request time. Until it is set, the API routes answer `503 {"error": "The demo is not configured on this deployment."}` and the landing page still works.

## Environment variables

Required at request time:

| Variable | Purpose |
|---|---|
| `AI_GATEWAY_API_KEY` | Vercel AI Gateway credential |
| `AMP_DEMO_LANGUAGE_MODEL` | Gateway id of the language model, e.g. `openai/gpt-4o-mini` |
| `AMP_DEMO_SPEECH_MODEL` | Gateway id of an OpenAI text-to-speech model (`openai/tts-1` or `openai/tts-1-hd`). The demo uses the `nova`, `shimmer` and `onyx` voices. |
| `AMP_DEMO_TRANSCRIPTION_MODEL` | Gateway id of the transcription model, e.g. `openai/gpt-4o-mini-transcribe` |

Only these model ids are used. Nothing a client sends can choose a model.

Optional:

| Variable | Default | Purpose |
|---|---|---|
| `AMP_DEMO_SIGNING_SEED` | unset | Derives the demo agents' Ed25519 keys from this secret, so every server instance signs with the same keys. Recommended on Vercel; without it each instance makes its own keys and the browser may briefly see a key mismatch. |
| `AMP_DEMO_ALLOWED_ORIGINS` | unset | Extra comma-separated origins allowed to POST. The site's own origin is always allowed. |
| `AMP_DEMO_RATE_BURST` | `8` | Token-bucket size per client IP |
| `AMP_DEMO_RATE_PER_MINUTE` | `4` | Tokens refilled per minute per client IP |
| `AMP_DEMO_GLOBAL_PER_HOUR` | `400` | Tokens per hour across all clients |
| `AMP_DEMO_MAX_CONCURRENT` | `16` | Model-spending requests running at once |
| `AMP_DEMO_MAX_MESSAGE_CHARS` | `1000` | Length of a chat message, answer, brief or transcript |
| `AMP_DEMO_MAX_HISTORY_ENTRIES` | `40` | Entries accepted in a history array |
| `AMP_DEMO_MAX_HISTORY_ENTRY_CHARS` | `4000` | Length of one history entry |
| `AMP_DEMO_HISTORY_TURNS_FOR_MODEL` | `16` | Most recent history entries forwarded to the model |
| `AMP_DEMO_MAX_JSON_BYTES` | `262144` | JSON request body size |
| `AMP_DEMO_MAX_AUDIO_BYTES` | `1048576` | Voice upload size (about a minute of browser opus) |
| `AMP_DEMO_MAX_AUDIO_SECONDS` | `60` | Longest transcribed audio, when the provider reports a duration |
| `AMP_DEMO_MAX_OUTPUT_TOKENS` | `500` | Ceiling on output tokens for any single model call |
| `AMP_DEMO_MAX_SPEECH_CHARS` | `600` | Characters sent to text-to-speech per clip |
| `AMP_DEMO_MODEL_TIMEOUT_MS` | `25000` | Timeout for one model call |
| `AMP_DEMO_REQUEST_TIMEOUT_MS` | `55000` | Timeout for a whole request (the routes' `maxDuration` is 60 s, 30 s for voice) |

Costs per request, in rate-limit tokens: a chat turn or a voice upload costs 1, an autonomous voice call costs 3, and resuming one costs 3. The key directory (`GET /api/amp-demo/keys`) is free.

## Deploy to Vercel

1. Create a Vercel project from this repository and set **Root Directory** to `site`. The framework preset is Next.js and the default build command (`npm run build`) is fine.
2. Add the four required variables, plus `AMP_DEMO_SIGNING_SEED`, under Project → Settings → Environment Variables.
3. Set a spend limit on the AI Gateway key. The in-app limits are best-effort (see below), so the gateway limit is the real backstop.

## How the API is protected

The API routes spend the owner's AI Gateway credit, so each one:

- accepts POSTs only from the site's own origin (Origin check; `Sec-Fetch-Site` when Origin is absent);
- is rate limited per client IP (token bucket), with a global hourly budget and a concurrency cap;
- validates the body with a strict zod schema (unknown fields rejected) and size caps, and reads at most the configured number of bytes before parsing;
- caps output tokens, speech length and history forwarded to the model;
- aborts model calls on a per-call timeout, on the request timeout, and when the client disconnects;
- returns fixed error messages only (no exception text or stack traces) and logs errors without request bodies or credentials.

**The limits are best-effort.** They are kept in memory. Vercel runs several function instances and recycles them, so each instance counts on its own and the effective limit is roughly the configured limit times the number of live instances. For hard limits, put a shared store (Redis, Vercel KV) or a WAF rule in front.

Security headers (CSP with `frame-ancestors 'none'`, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, HSTS in production) are set in `next.config.ts`. The CSP allows images only from the site and `images.unsplash.com`, which the bakery agent uses for cake photos.

## What the demo simplifies

- **Agents are simulated.** Your Agent, Sunny Bakery and Porter are played by one language model with different prompts. There is no real network hop between agents and no `ampro` server behind the page.
- **Signatures are a simplified scheme.** Envelopes are signed with Ed25519 on the server and verified in the browser against a public-key directory. The demo signs a canonical JSON form of the envelope and carries the signature in custom `X-Signature*` headers. Real AMP peers sign each HTTP request with the RFC 9421 profile in [WIRE-BINDING §12.15](../docs/WIRE-BINDING.md) (`@method`, `@target-uri`, `@authority`, `content-digest`; `alg="ed25519"`; required `created`, `keyid` and `nonce`). The UI labels the signature as a simplified demo scheme.
- **Envelope shape follows 0.4.0.** `sender`, `recipient`, `id` (UUID v4), `body_type`, string-valued `headers` (`Protocol-Version: 1.0.0`, lowercase `Trust-Tier`), and bodies with the fields the task body schemas require (`task_id`, `expires_at`, `reason`/`prompt`, `result`). Trust tiers, budgets and delegation headers are illustrative: no trust resolution, delegation-chain signing or session handshake runs.
- **Demo-only body types** use reverse-domain names as WIRE-BINDING §18.1 requires: `com.example.demo.voice_utterance`, `com.example.demo.directory_query` and `com.example.demo.directory_response`. Real discovery uses `GET /.well-known/agent.json` and the registry.
- **Private keys never leave the server.** `GET /api/amp-demo/keys` returns public keys only. Private keys live in server memory, are never persisted or logged, and the API never accepts keys from a client.
