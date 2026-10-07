# AMP site

Landing page and interactive demo for the Agent Mesh Protocol.

The page is this Next.js app. The demo signs AMP envelopes in the browser and on the server. Model calls go through the [Vercel AI Gateway](https://vercel.com/docs/ai-gateway) using AI SDK 7 (`gateway` from `ai`). There is no separate provider client.

## Run

```bash
cd site
cp .env.example .env.local
# fill AI_GATEWAY_API_KEY and the three AMP_DEMO_* model ids
npm install
npm run dev
```

Open http://localhost:3000.

`AMP_DEMO_SPEECH_MODEL` should be an OpenAI text-to-speech model on the gateway (`openai/tts-1` or `openai/tts-1-hd`). The demo asks for the `nova`, `shimmer`, and `onyx` voices.

## Deploy

Create a Vercel project with the root directory set to `site`. Set the same environment variables there. The Python package at the repository root is not part of this app.
