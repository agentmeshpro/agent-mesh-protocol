/**
 * POST /api/amp-demo/resume
 *
 * The autonomous loop paused with awaiting_user_card or awaiting_user_text.
 * The user picked a chip or typed an answer. We continue the loop here:
 * Your Agent voices the answer to Sunny, Sunny replies, classifier runs,
 * loop continues until done / next handoff / cap.
 *
 * Returns the SAME SSE event stream as /api/amp-demo so the client can
 * just append events to its existing handlers — no new transport.
 */

// Re-use the autonomous loop module-scope helper by re-importing the
// main route file would create a cycle; instead, the loop lives in a
// shared helper. For now, replicate the minimum needed and call into
// the same building blocks.
//
// Cleanest: factor runAutonomousLoop out of route.ts into a shared
// module. But we don't want to touch the existing autonomous turn-0
// scaffolding. So here we run a "continuation" loop that starts at
// turn 1 with history already in place.

import { generateSpeech, streamText, generateText } from 'ai'
import { generatePrompt } from '@openuidev/lang-core'
import { z } from 'zod'
import { ensureDemoKeys } from '@/demo/trust/keystore'
import { VOICE_UTTERANCE } from '@/demo/body-types'
import { languageModel, languageModelId, missingModelConfig, speechModel } from '@/lib/models'
import { makeEnvelope, makeId, makeTraceId } from '@/lib/amp-envelope'
import {
  BodyTooLarge,
  guardRequest,
  jsonError,
  logError,
  readJsonLimited,
  SSE_HEADERS,
} from '@/lib/api-guard'
import { capTokens, LIMITS } from '@/lib/limits'
import {
  modelSignal,
  requestAborted,
  requestSignal,
  withRequestContext,
} from '@/lib/request-context'

export const maxDuration = 60

type AppRouteUsageContext = undefined

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'
const TURN_CAP = 8

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error
}

function recordAmpDemoResumeUsage(
  _usageContext: AppRouteUsageContext | undefined,
  _input: {
    errorType?: string
    finishReason?: string
    messageCount?: number
    modelId: string
    operation: string
    partner?: 'bakery' | 'your-agent'
    success: boolean
    usage?: unknown
  },
): void {
  void _usageContext
  void _input
}


// ---- duplicated minimal helpers (would normally live in a shared module) ----

function langToProse(lang: string): string {
  const stripped = lang.replace(/```[a-z-]*\s*|\s*```/g, ' ').trim()
  const messages = [...stripped.matchAll(/(?:Bakery|Porter)Message\("((?:[^"\\]|\\.)*)"\)/g)]
    .map((m) => (m[1] ?? '').replace(/\\"/g, '"').replace(/\\n/g, ' '))
    .join(' ')
  if (messages.trim()) return messages.trim()
  const confirmed = stripped.match(
    /OrderConfirmed\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/,
  )
  if (confirmed) {
    const [, orderNo, summary, total, pickup] = confirmed
    return `Order ${orderNo} confirmed — ${summary}, total ${total}, ready ${pickup}.`
  }
  return stripped
    .replace(/[A-Z][a-zA-Z]*\(/g, '')
    .replace(/[)\[\]]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 600)
}

function extractBakeryOptions(lang: string): string[] {
  const opts: string[] = []
  const stripped = lang.replace(/```[a-z-]*\s*|\s*```/g, ' ')
  for (const m of stripped.matchAll(/CakeOption\(\s*"([^"]*)"\s*,\s*"[^"]*"\s*,\s*"([^"]*)"/g)) {
    const [, name, price] = m
    opts.push(price ? `${name} (${price})` : (name ?? ''))
  }
  for (const m of stripped.matchAll(/SizeOption\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/g)) {
    const [, size, serves, price] = m
    opts.push([size, serves, price].filter((s) => s && s.length > 0).join(' · '))
  }
  for (const m of stripped.matchAll(/DecorationOption\(\s*"([^"]*)"/g)) {
    if (m[1]) opts.push(m[1])
  }
  for (const m of stripped.matchAll(/DeliverySlot\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/g)) {
    const [, window, , vehicle, fee] = m
    opts.push([window, vehicle, fee].filter((s) => s && s.length > 0).join(' · '))
  }
  const seen = new Set<string>()
  return opts.filter((o) => {
    if (seen.has(o)) return false
    seen.add(o)
    return true
  })
}

async function synthesizeSpeech(
  text: string,
  voice: 'shimmer' | 'onyx' | 'nova',
): Promise<{ audioB64: string; mime: string } | null> {
  try {
    const result = await generateSpeech({
      model: speechModel(),
      voice,
      text: text.slice(0, LIMITS.maxSpeechChars),
      outputFormat: 'mp3',
      abortSignal: modelSignal(),
    })
    return {
      audioB64: result.audio.base64,
      mime: result.audio.mediaType || 'audio/mpeg',
    }
  } catch (err) {
    logError('amp-demo/resume/tts', err)
    return null
  }
}

async function classifyBakeryReply(args: {
  brief: string
  history: Array<{ role: string; content: string }>
  latestBakeryReply: string
  usageContext?: AppRouteUsageContext
}): Promise<{ kind: 'done' | 'ask_user' | 'answer' }> {
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: `You are the decision module of "Your Agent" — a personal assistant placing an order with Sunny Bakery on behalf of a user. Output EXACTLY one of: done, ask_user, answer. No punctuation, just the word.`,
      prompt: `User's brief:\n${args.brief}\n\nConversation:\n${args.history
        .map((h, i) => `${i + 1}. ${h.role === 'user' ? 'YA' : 'Sunny'}: ${h.content}`)
        .join('\n')}\n\nBakery's latest reply:\n${args.latestBakeryReply}`,
      maxOutputTokens: capTokens(8),
      abortSignal: modelSignal(),
    })
    recordAmpDemoResumeUsage(args.usageContext, {
      messageCount: args.history.length,
      modelId: languageModelId(),
      operation: 'classify_bakery_reply',
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    const label = result.text.trim().toLowerCase()
    if (label === 'done' || label === 'ask_user' || label === 'answer') return { kind: label }
    return { kind: 'answer' }
  } catch (error) {
    recordAmpDemoResumeUsage(args.usageContext, {
      errorType: errorName(error),
      messageCount: args.history.length,
      modelId: languageModelId(),
      operation: 'classify_bakery_reply',
      partner: 'your-agent',
      success: false,
    })
    return { kind: 'answer' }
  }
}

async function generateAgentToBakeryReply(args: {
  brief: string
  bakeryReply: string
  history: Array<{ role: string; content: string }>
  usageContext?: AppRouteUsageContext
}): Promise<string> {
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: `You are "Your Agent" — a personal assistant ordering on behalf of a user. Speak ONE short sentence (max ~22 words) addressed to Sunny. First-person, natural, decisive.`,
      prompt: `User's brief:\n${args.brief}\n\nConversation:\n${args.history
        .map((h) => `${h.role === 'user' ? 'YA' : 'Sunny'}: ${h.content}`)
        .join('\n')}\n\nSunny just said:\n${args.bakeryReply}\n\nYour single-sentence reply to Sunny:`,
      maxOutputTokens: capTokens(80),
      abortSignal: modelSignal(),
    })
    recordAmpDemoResumeUsage(args.usageContext, {
      messageCount: args.history.length,
      modelId: languageModelId(),
      operation: 'agent_to_bakery_reply',
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    return result.text.trim().replace(/^["']|["']$/g, '')
  } catch (error) {
    recordAmpDemoResumeUsage(args.usageContext, {
      errorType: errorName(error),
      messageCount: args.history.length,
      modelId: languageModelId(),
      operation: 'agent_to_bakery_reply',
      partner: 'your-agent',
      success: false,
    })
    return "Got it — let's keep going."
  }
}

async function generateAgentLine(
  kind: 'brief' | 'relay',
  context: { partner: 'Sunny Bakery' | 'Porter'; userMessage?: string; partnerText?: string },
  usageContext?: AppRouteUsageContext,
): Promise<string> {
  const systemBrief = `You are "Your Agent" — the user's personal assistant. Speak ONE short sentence (max ~14 words) addressed to ${context.partner} previewing what you're sending. Natural, conversational, first-person.`
  const systemRelay = `You are "Your Agent" — the user's personal assistant. ${context.partner} just replied. Speak ONE short sentence (max ~18 words) addressed to the user, paraphrasing what ${context.partner} said.`
  const prompt =
    kind === 'brief'
      ? `User asked:\n${context.userMessage ?? ''}`
      : `${context.partner}'s reply:\n${context.partnerText ?? ''}`
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: kind === 'brief' ? systemBrief : systemRelay,
      prompt,
      maxOutputTokens: capTokens(80),
      abortSignal: modelSignal(),
    })
    recordAmpDemoResumeUsage(usageContext, {
      modelId: languageModelId(),
      operation: `agent_line_${kind}`,
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    return result.text.trim().replace(/^["']|["']$/g, '')
  } catch (error) {
    recordAmpDemoResumeUsage(usageContext, {
      errorType: errorName(error),
      modelId: languageModelId(),
      operation: `agent_line_${kind}`,
      partner: 'your-agent',
      success: false,
    })
    return kind === 'brief' ? `Forwarding your request to ${context.partner}.` : `${context.partner} responded.`
  }
}

const BAKERY_SYSTEM_PROMPT = generatePrompt({
  root: 'Stack',
  components: {
    BakeryMessage: { signature: 'BakeryMessage(text: string)', description: 'A friendly text message from Sunny Bakery' },
    CakeOption: { signature: 'CakeOption(name: string, description: string, price: string, image?: string, emoji?: string)', description: 'Cake option card' },
    OptionGrid: { signature: 'OptionGrid(children: node[])', description: 'Grid layout' },
    SizeOption: { signature: 'SizeOption(size: string, serves: string, price: string)', description: 'Size option' },
    PriceQuote: { signature: 'PriceQuote(summary: string, total: string, readyBy: string)', description: 'Order summary' },
    OrderConfirmed: { signature: 'OrderConfirmed(orderNumber: string, summary: string, total: string, pickupTime: string)', description: 'Confirmation card' },
    DecorationOption: { signature: 'DecorationOption(label: string, emoji?: string)', description: 'Decoration option' },
    Stack: { signature: 'Stack(children: node[])', description: 'Vertical stack' },
  },
  preamble:
    'You are Sunny, the owner of Sunny Bakery. You take custom cake orders. Be warm and friendly. You operate out of Linking Rd, Bandra West, Mumbai. In-store pickup ONLY — no delivery.',
  additionalRules: [
    'Always wrap your response in a Stack',
    'Use ₹ (Indian rupees) for prices',
    'Keep messages SHORT (1-2 sentences)',
  ],
})

// ---- main handler ----

const HistoryEntry = z
  .object({
    role: z.enum(['user', 'assistant']),
    content: z.string().max(LIMITS.maxHistoryEntryChars),
  })
  .strict()

const ResumeRequest = z
  .object({
    answer: z.string().trim().min(1).max(LIMITS.maxMessageChars),
    brief: z.string().trim().min(1).max(LIMITS.maxMessageChars),
    history: z.array(HistoryEntry).max(LIMITS.maxHistoryEntries).default([]),
  })
  .strict()

export async function POST(request: Request): Promise<Response> {
  // A resume re-enters the autonomous loop, which can make many model and
  // speech calls, so it costs as much as starting one.
  const guard = guardRequest(request, { cost: 3 })
  if (guard instanceof Response) return guard
  let streaming = false
  try {
    if (missingModelConfig('language', 'speech')) {
      return jsonError(503, 'The demo is not configured on this deployment.')
    }
    let raw: unknown
    try {
      raw = await readJsonLimited(request, LIMITS.maxJsonBodyBytes)
    } catch (err) {
      if (err instanceof BodyTooLarge) return jsonError(413, 'Request body too large')
      return jsonError(400, 'Invalid request body')
    }
    const parsed = ResumeRequest.safeParse(raw)
    if (!parsed.success) return jsonError(400, 'Invalid request')

    await ensureDemoKeys([YOUR_AGENT, SUNNY_BAKERY, PORTER_DELIVERY])

    const signal = requestSignal(request)
    streaming = true
    return withRequestContext(signal, () =>
      resumeStream({
        payload: parsed.data,
        // Only the most recent turns are forwarded to the model.
        incomingHistory: parsed.data.history.slice(-LIMITS.historyTurnsForModel),
        signal,
        release: guard.release,
      }),
    )
  } catch (err) {
    logError('amp-demo/resume', err)
    return jsonError(500, 'Something went wrong. Please try again.')
  } finally {
    if (!streaming) guard.release()
  }
}

function resumeStream(args: {
  payload: z.infer<typeof ResumeRequest>
  incomingHistory: Array<{ role: 'user' | 'assistant'; content: string }>
  signal: AbortSignal
  release: () => void
}): Response {
  const { payload, incomingHistory } = args
  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      const usageContext = undefined
      const traceId = makeTraceId()
      let closed = false
      const send = (type: string, data: unknown) => {
        if (closed) return
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type, data })}\n\n`))
        } catch {
          closed = true
        }
      }

      const speak = async (
        sender: string,
        recipient: string,
        speaker: 'your-agent' | 'bakery',
        text: string,
        voice: 'nova' | 'shimmer',
      ): Promise<void> => {
        if (!text.trim()) return
        const audio = await synthesizeSpeech(text, voice)
        if (!audio) return
        const env = await makeEnvelope(
          sender,
          recipient,
          VOICE_UTTERANCE,
          { transcript: text, audio_b64: audio.audioB64, mime: audio.mime, speaker },
          {
            'Trace-Id': traceId,
            'Trust-Tier':
              sender === YOUR_AGENT && recipient === 'user://you' ? 'owner' : 'verified',
          },
        )
        send('envelope', env)
        send('voice', {
          speaker,
          audio_b64: audio.audioB64,
          mime: audio.mime,
          transcript: text,
        })
      }

      const bakeryTurn = async (
        convo: Array<{ role: 'user' | 'assistant'; content: string }>,
      ): Promise<string> => {
        const result = streamText({
          model: languageModel(),
          instructions: BAKERY_SYSTEM_PROMPT,
          messages: convo,
          maxOutputTokens: capTokens(500),
          abortSignal: modelSignal(),
          onEnd: ({ usage, finishReason }) => {
            recordAmpDemoResumeUsage(usageContext, {
              finishReason,
              messageCount: convo.length,
              modelId: languageModelId(),
              operation: 'bakery_turn',
              partner: 'bakery',
              success: true,
              usage,
            })
          },
          onError({ error }) {
            recordAmpDemoResumeUsage(usageContext, {
              errorType: errorName(error),
              messageCount: convo.length,
              modelId: languageModelId(),
              operation: 'bakery_turn',
              partner: 'bakery',
              success: false,
            })
          },
        })
        let acc = ''
        for await (const chunk of result.textStream) acc += chunk
        return acc.trim()
      }

      try {
        // Rebuild bakery's message history from prose-history (lossy but
        // sufficient — bakery LLM is happy with prose context).
        const bakeryConvo: Array<{ role: 'user' | 'assistant'; content: string }> = [
          { role: 'user', content: payload.brief },
        ]
        for (const h of incomingHistory) {
          bakeryConvo.push({
            role: h.role === 'user' ? 'user' : 'assistant',
            content: h.content,
          })
        }
        const proseHistory = [...incomingHistory]

        // Step 1: YA voices the user's answer to Sunny. This is the
        // moment the user's chip-tap (or text reply) re-enters the call.
        const yaLine = await generateAgentToBakeryReply({
          brief: payload.brief,
          bakeryReply: incomingHistory[incomingHistory.length - 1]?.content ?? '',
          history: [
            ...proseHistory,
            { role: 'user', content: `(User just answered: ${payload.answer})` },
          ],
          usageContext,
        })
        await speak(YOUR_AGENT, SUNNY_BAKERY, 'your-agent', yaLine, 'nova')
        bakeryConvo.push({ role: 'user', content: yaLine })
        proseHistory.push({ role: 'user', content: yaLine })

        // Step 2: bakery replies.
        let bakeryLang = await bakeryTurn(bakeryConvo)
        let bakeryProse = langToProse(bakeryLang)
        bakeryConvo.push({ role: 'assistant', content: bakeryLang })
        proseHistory.push({ role: 'assistant', content: bakeryProse })
        await speak(SUNNY_BAKERY, YOUR_AGENT, 'bakery', bakeryProse, 'shimmer')

        // Step 3+: keep looping until done, ask_user, or cap.
        for (let turn = 1; turn <= TURN_CAP; turn++) {
          if (requestAborted()) return
          send('loop_turn', { turn, max: TURN_CAP })
          const decision = await classifyBakeryReply({
            brief: payload.brief,
            history: proseHistory,
            latestBakeryReply: bakeryProse,
            usageContext,
          })
          if (decision.kind === 'done') {
            const summary = await generateAgentLine('relay', {
              partner: 'Sunny Bakery',
              partnerText: `Order confirmed. ${bakeryProse}`,
            }, usageContext)
            await speak(YOUR_AGENT, 'user://you', 'your-agent', summary, 'nova')
            send('loop_done', { summary })
            return
          }
          if (decision.kind === 'ask_user') {
            const question = await generateAgentLine('relay', {
              partner: 'Sunny Bakery',
              partnerText: bakeryProse,
            }, usageContext)
            const options = extractBakeryOptions(bakeryLang)
            const decisionId = makeId('decision')
            const evType = options.length > 0 ? 'awaiting_user_card' : 'awaiting_user_text'
            send(evType, {
              decisionId,
              question,
              options: options.length > 0 ? options : undefined,
              lastBakeryReply: bakeryProse,
              history: proseHistory,
              brief: payload.brief,
            })
            return
          }
          // decision === 'answer'
          const yaReply = await generateAgentToBakeryReply({
            brief: payload.brief,
            bakeryReply: bakeryProse,
            history: proseHistory,
            usageContext,
          })
          await speak(YOUR_AGENT, SUNNY_BAKERY, 'your-agent', yaReply, 'nova')
          bakeryConvo.push({ role: 'user', content: yaReply })
          proseHistory.push({ role: 'user', content: yaReply })
          bakeryLang = await bakeryTurn(bakeryConvo)
          bakeryProse = langToProse(bakeryLang)
          bakeryConvo.push({ role: 'assistant', content: bakeryLang })
          proseHistory.push({ role: 'assistant', content: bakeryProse })
          await speak(SUNNY_BAKERY, YOUR_AGENT, 'bakery', bakeryProse, 'shimmer')
        }

        // Cap hit
        send('awaiting_user_text', {
          decisionId: makeId('decision'),
          question: "I couldn't finish this on my own. Can you take it from here?",
          lastBakeryReply: bakeryProse,
          history: proseHistory,
          brief: payload.brief,
        })
      } catch (err) {
        if (!args.signal.aborted) logError('amp-demo/resume', err)
        send('error', {
          message: args.signal.aborted
            ? 'The request took too long and was stopped.'
            : 'Something went wrong. Please try again.',
        })
      } finally {
        args.release()
        closed = true
        try {
          controller.close()
        } catch {
          // already closed or cancelled by the client
        }
      }
    },
    cancel() {
      args.release()
    },
  })

  return new Response(stream, { headers: SSE_HEADERS })
}
