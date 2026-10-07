import { generateSpeech, streamText, generateText } from 'ai'
import { generatePrompt } from '@openuidev/lang-core'
import { z } from 'zod'
import { ensureDemoKeys } from '@/demo/trust/keystore'
import {
  DIRECTORY_QUERY,
  DIRECTORY_RESPONSE,
  VOICE_UTTERANCE,
} from '@/demo/body-types'
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


function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error
}

function recordAmpDemoUsage(
  _usageContext: AppRouteUsageContext | undefined,
  _input: {
    errorType?: string
    finishReason?: string
    messageCount?: number
    mode?: 'turn' | 'autonomous'
    modelId: string
    operation: string
    partner?: 'bakery' | 'porter' | 'your-agent'
    success: boolean
    usage?: unknown
  },
): void {
  void _usageContext
  void _input
}


/**
 * Pull the human-readable lines out of an OpenUI Lang response so we
 * speak them rather than spelling out component syntax. We grab the
 * string literal from any *Message(...) component (BakeryMessage,
 * PorterMessage). If none are present, fall back to a stripped form.
 */
function extractSpokenText(lang: string): string {
  const messageMatches = [...lang.matchAll(/(?:Bakery|Porter)Message\("((?:[^"\\]|\\.)*)"\)/g)]
  if (messageMatches.length > 0) {
    return messageMatches
      .map((m) => (m[1] ?? '').replace(/\\"/g, '"').replace(/\\n/g, ' '))
      .join(' ')
      .trim()
  }
  // Strip any Lang component wrappers
  return lang
    .replace(/[A-Z][a-zA-Z]*\(/g, '')
    .replace(/[)\[\]]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 400)
}

/**
 * Render text → MP3 bytes via the Vercel AI Gateway speech model. Voice differs per
 * agent so Your Agent, bakery and porter all sound distinct. Returns
 * null on failure so the demo degrades to text-only rather than
 * dropping the whole turn.
 *   nova    → Your Agent (neutral, brisk)
 *   shimmer → Sunny Bakery (warm, friendly)
 *   onyx    → Porter (operational, male)
 */
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
    return { audioB64: result.audio.base64, mime: result.audio.mediaType || 'audio/mpeg' }
  } catch (err) {
    logError('amp-demo/tts', err)
    return null
  }
}

/**
 * Generate a single short sentence from Your Agent — either a *brief* it
 * speaks to the remote partner ("Sending Sunny a request for…") or a
 * *paraphrase* of the remote partner's reply that it relays back to the
 * user. Kept terse on purpose so the conversation feels like overhearing
 * a real assistant on a phone call, not a recap.
 */
async function generateAgentLine(
  kind: 'brief' | 'relay',
  context: { partner: 'Sunny Bakery' | 'Porter'; userMessage?: string; partnerText?: string },
  usageContext?: AppRouteUsageContext,
): Promise<string> {
  const systemBrief = `You are "Your Agent" — the user's personal assistant. Right now you are about to forward the user's request to ${context.partner}. Speak ONE short sentence (max ~14 words) addressed to ${context.partner} that previews what you're sending. Be natural, conversational, first-person. No greetings, no apologies, no jargon. Examples: "Sending Sunny a chocolate cake order for ten." / "Asking Porter to schedule a 2pm pickup from Bandra."`
  const systemRelay = `You are "Your Agent" — the user's personal assistant. ${context.partner} just replied to you. Speak ONE short sentence (max ~18 words) addressed to the user, paraphrasing what ${context.partner} said. Be natural, conversational, first-person. No prefix like "They said"; just deliver the news. Examples: "Sunny has three flavors — chocolate fudge, vanilla, or red velvet. Which sounds good?" / "Porter can pick up at 2:45 for ₹80. Want me to confirm?"`
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
    recordAmpDemoUsage(usageContext, {
      modelId: languageModelId(),
      operation: `agent_line_${kind}`,
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    return result.text.trim().replace(/^["']|["']$/g, '')
  } catch (error) {
    recordAmpDemoUsage(usageContext, {
      errorType: errorName(error),
      modelId: languageModelId(),
      operation: `agent_line_${kind}`,
      partner: 'your-agent',
      success: false,
    })
    // Fallback so voice mode never just drops a turn
    if (kind === 'brief') return `Forwarding your request to ${context.partner}.`
    return `${context.partner} responded with options.`
  }
}

/**
 * Strip OpenUI Lang component syntax down to plain prose so the
 * classifier and reply-generator see what the bakery actually said
 * rather than DSL noise like `Stack([BakeryMessage("…"), …])`.
 */
function langToProse(lang: string): string {
  // Strip ```openui-lang … ``` fences if the model emitted them.
  const stripped = lang.replace(/```[a-z-]*\s*|\s*```/g, ' ').trim()
  const messages = [...stripped.matchAll(/(?:Bakery|Porter)Message\("((?:[^"\\]|\\.)*)"\)/g)]
    .map((m) => (m[1] ?? '').replace(/\\"/g, '"').replace(/\\n/g, ' '))
    .join(' ')
  if (messages.trim()) return messages.trim()
  // For OrderConfirmed, surface the key fields so the user gets a useful summary.
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

/**
 * Pull structured choices out of the bakery's lang DSL response.
 * Returns the option labels in declaration order. Empty array means
 * either the bakery is asking an open-ended question or no parseable
 * options were emitted.
 *
 * We harvest from any of the bakery/porter components the prompts
 * recognise: CakeOption / SizeOption / DecorationOption / DeliverySlot.
 */
function extractBakeryOptions(lang: string): string[] {
  const opts: string[] = []
  const stripped = lang.replace(/```[a-z-]*\s*|\s*```/g, ' ')

  // CakeOption(name, description, price, image?, emoji?) → name (price)
  for (const m of stripped.matchAll(
    /CakeOption\(\s*"([^"]*)"\s*,\s*"[^"]*"\s*,\s*"([^"]*)"/g,
  )) {
    const [, name, price] = m
    opts.push(price ? `${name} (${price})` : (name ?? ''))
  }

  // SizeOption(size, serves, price) → "Medium (serves 8–10, ₹1500)"
  for (const m of stripped.matchAll(
    /SizeOption\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/g,
  )) {
    const [, size, serves, price] = m
    const bits = [size, serves, price].filter((s) => s && s.length > 0)
    opts.push(bits.join(' · '))
  }

  // DecorationOption(label, emoji?) → label
  for (const m of stripped.matchAll(
    /DecorationOption\(\s*"([^"]*)"/g,
  )) {
    if (m[1]) opts.push(m[1])
  }

  // DeliverySlot(window, driver, vehicle, fee) → "2:30pm – 2:45pm · Bike · ₹80"
  for (const m of stripped.matchAll(
    /DeliverySlot\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/g,
  )) {
    const [, window, , vehicle, fee] = m
    const bits = [window, vehicle, fee].filter((s) => s && s.length > 0)
    opts.push(bits.join(' · '))
  }

  // De-dupe while preserving order
  const seen = new Set<string>()
  return opts.filter((o) => {
    if (seen.has(o)) return false
    seen.add(o)
    return true
  })
}

type BakeryDecision = { kind: 'done' | 'ask_user' | 'answer' }

/**
 * Decide what Your Agent should do with the bakery's latest reply:
 *  - done:     order is confirmed, exit the loop
 *  - ask_user: bakery wants information ONLY the human user knows
 *              (preferences, names, addresses not in the brief, allergies,
 *              identity, payment). Pause loop and hand control to user.
 *  - answer:   YA can answer this from the original brief + reasonable
 *              defaults. Generate a reply and continue the loop.
 */
async function classifyBakeryReply(args: {
  brief: string
  history: Array<{ role: string; content: string }>
  latestBakeryReply: string
  usageContext?: AppRouteUsageContext
}): Promise<BakeryDecision> {
  const { brief, history, latestBakeryReply, usageContext } = args
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: `You are the decision module of "Your Agent" — a personal assistant placing an order with Sunny Bakery on behalf of a user.

You receive (1) the user's original brief and (2) the bakery's latest reply. You must output EXACTLY one of three labels:

- "done"     — bakery has confirmed the order (e.g. "Order confirmed", "I've booked it", an OrderConfirmed component in the reply). Loop ends.
- "ask_user" — bakery is asking for information that ONLY THE USER can answer. This includes any of:
      • Recipient name (spelling, identity)
      • Allergies, dietary restrictions
      • Specific preferences NOT mentioned in the brief (e.g. "what color frosting?" when brief said nothing about color)
      • Address, phone, payment details, contact preferences NOT in the brief
      • Subjective taste questions ("which sounds better to you?")
      • Pickup or delivery times NOT in the brief
- "answer"   — bakery is offering options or asking something Your Agent can answer from the brief + reasonable defaults. Examples:
      • Bakery shows 3 cake flavor options and the brief said "chocolate" → answer (pick chocolate)
      • Bakery asks size and brief said "for 10 people" → answer (pick the size that serves 10)
      • Bakery shows a price quote and brief said anything affirmative → answer (accept)
      • Bakery asks a yes/no clarification YA can infer from the brief → answer

Output ONLY the label. No explanation, no punctuation, just the single word.`,
      prompt: `User's brief:\n${brief}\n\nConversation so far (most recent last):\n${history
        .map((h, i) => `${i + 1}. ${h.role === 'user' ? 'YA' : 'Sunny'}: ${h.content}`)
        .join('\n') || '(this is the first bakery reply)'}\n\nBakery's latest reply:\n${latestBakeryReply}`,
      maxOutputTokens: capTokens(8),
      abortSignal: modelSignal(),
    })
    recordAmpDemoUsage(usageContext, {
      messageCount: history.length,
      modelId: languageModelId(),
      operation: 'classify_bakery_reply',
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    const label = result.text.trim().toLowerCase()
    if (label === 'done' || label === 'ask_user' || label === 'answer') {
      return { kind: label }
    }
    return { kind: 'answer' }
  } catch (error) {
    recordAmpDemoUsage(usageContext, {
      errorType: errorName(error),
      messageCount: history.length,
      modelId: languageModelId(),
      operation: 'classify_bakery_reply',
      partner: 'your-agent',
      success: false,
    })
    // Default to answer — keep the loop alive rather than bailing to user
    // on transient LLM errors. The turn cap catches runaways.
    return { kind: 'answer' }
  }
}

/**
 * Generate Your Agent's next conversational reply to the bakery. One
 * short sentence (max ~22 words), first-person, decisive. Pulls from
 * the brief + bakery's last message + conversation history.
 */
async function generateAgentToBakeryReply(args: {
  brief: string
  bakeryReply: string
  history: Array<{ role: string; content: string }>
  usageContext?: AppRouteUsageContext
}): Promise<string> {
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: `You are "Your Agent" — a personal assistant ordering on behalf of a user. You are mid-call with Sunny Bakery and need to respond to their last message.

Speak ONE short sentence (max ~22 words) addressed to Sunny. First-person, natural, decisive. Use ONLY information from the user's brief or reasonable defaults that fit the brief. Never invent specifics the user didn't give (no made-up names, allergies, addresses, payment).

If Sunny offered choices and the brief implies one, pick it ("Let's go with the chocolate fudge."). If Sunny offered a quote/total and the brief is affirmative, confirm ("That works — please confirm the order."). If Sunny is just acknowledging, nudge forward ("Great. What's the next step?").`,
      prompt: `User's brief:\n${args.brief}\n\nConversation so far:\n${args.history
        .map((h) => `${h.role === 'user' ? 'YA' : 'Sunny'}: ${h.content}`)
        .join('\n') || '(none yet)'}\n\nSunny just said:\n${args.bakeryReply}\n\nYour single-sentence reply to Sunny:`,
      maxOutputTokens: capTokens(80),
      abortSignal: modelSignal(),
    })
    recordAmpDemoUsage(args.usageContext, {
      messageCount: args.history.length,
      modelId: languageModelId(),
      operation: 'agent_to_bakery_reply',
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    return result.text.trim().replace(/^["']|["']$/g, '')
  } catch (error) {
    recordAmpDemoUsage(args.usageContext, {
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

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'

/**
 * "Intelligent routing" — my Agent uses Claude Haiku to classify the user's
 * message into one of three intents. Falls back to a regex for resilience if
 * the LLM call fails.
 *
 *   order    → conversation belongs with Sunny Bakery (cake specs, flavors…)
 *   delivery → conversation belongs with Porter (addresses, pickup times…)
 *   both     → the message describes both; bakery first, then Porter
 */
async function classifyIntent(
  message: string,
  context: { porterActive: boolean },
  usageContext?: AppRouteUsageContext,
): Promise<'order' | 'delivery' | 'both'> {
  try {
    const result = await generateText({
      model: languageModel(),
      instructions: `You are an intent router for a multi-agent system with two external agents:
- BAKERY: handles cake orders (flavor, size, decoration, message, pickup time).
- DELIVERY: handles logistics (addresses, delivery slots, pickup → drop, driver scheduling).

Classify the user's latest message into exactly one label:
- "order"    — only about the cake / bakery product itself
- "delivery" — only about delivery, address, pickup-by-courier, scheduling
- "both"     — mentions both bakery details AND delivery/address

Output ONLY the single word label, no punctuation, no explanation.`,
      prompt: `Porter is ${context.porterActive ? 'already engaged' : 'not yet engaged'}.\n\nUser message:\n${message}`,
      maxOutputTokens: capTokens(10),
      abortSignal: modelSignal(),
    })
    recordAmpDemoUsage(usageContext, {
      modelId: languageModelId(),
      operation: 'classify_intent',
      partner: 'your-agent',
      success: true,
      usage: await result.usage,
    })
    const label = result.text.trim().toLowerCase()
    if (label === 'delivery' || label === 'both') return label
    return 'order'
  } catch (error) {
    recordAmpDemoUsage(usageContext, {
      errorType: errorName(error),
      modelId: languageModelId(),
      operation: 'classify_intent',
      partner: 'your-agent',
      success: false,
    })
    // Fallback heuristic
    const t = message.toLowerCase()
    const hasDelivery =
      /\b(deliver|pick\s?up|drop|send\s+(it|to)|address|home|ship)\b/i.test(t) ||
      /\bto\s+(bandra|juhu|andheri|powai|worli|colaba|khar|goregaon|dadar|malad)/i.test(t)
    return hasDelivery ? 'both' : 'order'
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// ---------------------------------------------------------------------------
// Build OpenUI Lang system prompt from component specs (no React needed)
// ---------------------------------------------------------------------------

const BAKERY_SYSTEM_PROMPT = generatePrompt({
  root: 'Stack',
  components: {
    BakeryMessage: {
      signature: 'BakeryMessage(text: string)',
      description: 'A friendly text message from Sunny Bakery',
    },
    CakeOption: {
      signature:
        'CakeOption(name: string, description: string, price: string, image?: string, emoji?: string)',
      description:
        'A full-bleed cake option card with photo, name, description, and price. Include a real Unsplash photo URL in the `image` prop whenever possible.',
    },
    OptionGrid: {
      signature: 'OptionGrid(children: node[])',
      description: 'A grid layout for displaying multiple options to choose from',
    },
    SizeOption: {
      signature: 'SizeOption(size: string, serves: string, price: string)',
      description: 'A size selection option with serves count and price',
    },
    PriceQuote: {
      signature: 'PriceQuote(summary: string, total: string, readyBy: string)',
      description: 'An order summary card with price and confirm button',
    },
    OrderConfirmed: {
      signature: 'OrderConfirmed(orderNumber: string, summary: string, total: string, pickupTime: string)',
      description: 'Order confirmation card with order number and details',
    },
    DecorationOption: {
      signature: 'DecorationOption(label: string, emoji?: string)',
      description: 'A decoration or message option for the cake',
    },
    Stack: {
      signature: 'Stack(children: node[])',
      description: 'A vertical stack layout for arranging content',
    },
  },
  preamble:
    'You are Sunny, the owner of Sunny Bakery. You take custom cake and pastry orders. Be warm and friendly. You operate out of Linking Rd, Bandra West, Mumbai.',
  additionalRules: [
    'Always wrap your response in a Stack',
    'Start with a BakeryMessage for your greeting/question text',
    'When offering choices, use OptionGrid with CakeOption or SizeOption or DecorationOption cards',
    'When giving a price quote, use PriceQuote',
    'When confirming an order, use OrderConfirmed',
    'Keep messages SHORT (1-2 sentences)',
    'Ask ONE question at a time',
    'CRITICAL: Sunny Bakery is in-store pickup ONLY. You do NOT deliver. If the customer asks about delivery, home drop, or sending to an address, REFUSE clearly and politely — say "I only offer in-store pickup at Linking Rd, Bandra West. For delivery, your agent can book a logistics partner like Porter on your behalf." Do NOT invent a delivery fee or pretend to offer delivery.',
    'ALWAYS include a real Unsplash photo URL in CakeOption image prop. Pick from:',
    '  Chocolate:  https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=800',
    '  Vanilla:    https://images.unsplash.com/photo-1535141192574-5d4897c12636?w=800',
    '  Red Velvet: https://images.unsplash.com/photo-1586788680434-30d324b2d46f?w=800',
    '  Strawberry: https://images.unsplash.com/photo-1464349095431-e9a21285b5f3?w=800',
    '  Black Forest: https://images.unsplash.com/photo-1606313564200-e75d5e30476c?w=800',
    '  Cheesecake: https://images.unsplash.com/photo-1533134242443-d4fd215305ad?w=800',
    '  Lemon tart: https://images.unsplash.com/photo-1519915028121-7d3463d20b13?w=800',
    '  Carrot:     https://images.unsplash.com/photo-1621303837174-89787a7d4729?w=800',
    'Use ₹ (Indian rupees) for prices, not $',
  ],
  examples: [
    `root = Stack([msg, grid])
msg = BakeryMessage("What flavor would you like?")
grid = OptionGrid([c1, c2, c3])
c1 = CakeOption("Chocolate Fudge", "Rich & moist, dark cocoa", "₹1500", "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=800")
c2 = CakeOption("Vanilla Sponge", "Classic, light & airy", "₹1200", "https://images.unsplash.com/photo-1535141192574-5d4897c12636?w=800")
c3 = CakeOption("Red Velvet", "Cream cheese frosting", "₹1650", "https://images.unsplash.com/photo-1586788680434-30d324b2d46f?w=800")`,

    `root = Stack([msg, quote])
msg = BakeryMessage("Here's your order summary:")
quote = PriceQuote("Medium Chocolate Cake with Happy Birthday", "$35", "10am tomorrow")`,

    `root = Stack([confirmed])
confirmed = OrderConfirmed("SB-4821", "Medium Chocolate Cake with Happy Birthday", "$35", "10am tomorrow")`,
  ],
})

const PORTER_SYSTEM_PROMPT = generatePrompt({
  root: 'Stack',
  components: {
    PorterMessage: {
      signature: 'PorterMessage(text: string)',
      description: 'A short text message from the Porter delivery agent',
    },
    DeliverySlot: {
      signature: 'DeliverySlot(window: string, driver: string, vehicle: string, fee: string)',
      description: 'A selectable delivery time slot with driver info and fee',
    },
    RoutePreview: {
      signature: 'RoutePreview(pickup: string, drop: string, distance: string, eta: string)',
      description: 'A pickup → drop route preview with addresses, distance, and ETA',
    },
    CombinedQuote: {
      signature:
        'CombinedQuote(cakeSummary: string, cakePrice: string, deliveryFee: string, total: string, readyBy: string)',
      description: 'Combined order summary: bakery cost + delivery fee + total, with Confirm button',
    },
    DeliveryConfirmed: {
      signature:
        'DeliveryConfirmed(trackingId: string, driver: string, vehicle: string, eta: string)',
      description: 'Delivery confirmation card with tracking ID and driver details',
    },
    Stack: {
      signature: 'Stack(children: node[])',
      description: 'Vertical stack layout',
    },
    OptionGrid: {
      signature: 'OptionGrid(children: node[])',
      description: 'Vertical stack for DeliverySlot cards',
    },
  },
  preamble:
    'You are Porter, an on-demand delivery platform. You quote and schedule pickups from partner merchants (Sunny Bakery) to customer addresses. Be precise and operational — you are logistics, not hospitality.',
  additionalRules: [
    'Always wrap your response in a Stack',
    'Start with a PorterMessage (1 short sentence)',
    'If you have both pickup and drop addresses, include a RoutePreview',
    'When offering time slots, use OptionGrid with DeliverySlot cards (2–3 options)',
    'When giving the combined quote, use CombinedQuote',
    'When confirming the booking, use DeliveryConfirmed',
    'Use realistic Indian driver names (Rahul S., Priya K., Amit J., Neha R.) and vehicles (Bike, Mini-truck)',
    'Use Indian rupee format (₹80, ₹1500) for all money',
    'Keep messages SHORT',
  ],
  examples: [
    `root = Stack([msg, route, grid])
msg = PorterMessage("Here are available delivery slots:")
route = RoutePreview("Sunny Bakery, Linking Rd", "Bandra West", "6.2 km", "18 min")
grid = OptionGrid([s1, s2, s3])
s1 = DeliverySlot("2:30pm - 2:45pm", "Rahul S.", "Bike", "₹80")
s2 = DeliverySlot("3:00pm - 3:15pm", "Priya K.", "Bike", "₹80")
s3 = DeliverySlot("3:30pm - 3:45pm", "Amit J.", "Mini-truck", "₹120")`,

    `root = Stack([quote])
quote = CombinedQuote("Medium Chocolate Cake with Happy Birthday", "₹1500", "₹80", "₹1580", "2:45pm tomorrow")`,

    `root = Stack([confirmed])
confirmed = DeliveryConfirmed("PTR-9231", "Rahul S.", "Bike MH-02-FG-4821", "2:45pm tomorrow")`,
  ],
})

// ---------------------------------------------------------------------------
// Autonomous loop — Your Agent conducts the whole conversation with the
// bakery on the user's behalf. The user gives ONE brief and listens.
// Loop exits when:
//   • Bakery confirms the order            → loop_done event + YA summary
//   • Bakery needs info only the user has  → awaiting_user event + YA pause line
//   • Turn cap (8) hit                     → awaiting_user event (graceful bail)
// Every YA↔Sunny exchange is a signed voice-utterance envelope, just like
// the existing turn-based path. The SSE stream stays the same shape (events
// flow in real time) so the browser plays clips as they arrive.
// ---------------------------------------------------------------------------

const AUTONOMOUS_TURN_CAP = 8

async function runAutonomousLoop(args: {
  brief: string
  history: Array<{ role: string; content: string }>
  traceId: string
  sendEvent: (type: string, data: unknown) => void
  usageContext?: AppRouteUsageContext
}): Promise<void> {
  const { brief, traceId, sendEvent, usageContext } = args
  const YOUR_AGENT_LOCAL = 'agent://you@example.com'
  const SUNNY_BAKERY_LOCAL = 'agent://sunny-bakery.example.com'

  // Mini helpers — these close over sendEvent + traceId so the loop
  // body stays readable. Each one emits BOTH a signed envelope and a
  // 'voice' SSE frame, mirroring the existing single-shot path.
  async function speak(
    sender: string,
    recipient: string,
    speaker: 'your-agent' | 'bakery',
    text: string,
    voice: 'nova' | 'shimmer',
    inReplyTo?: string,
  ): Promise<string | null> {
    if (!text.trim()) return null
    const audio = await synthesizeSpeech(text, voice)
    if (!audio) return null
    const env = await makeEnvelope(
      sender,
      recipient,
      VOICE_UTTERANCE,
      {
        transcript: text,
        audio_b64: audio.audioB64,
        mime: audio.mime,
        speaker,
      },
      {
        'Trace-Id': traceId,
        'Trust-Tier': sender === YOUR_AGENT_LOCAL && recipient === 'user://you' ? 'owner' : 'verified',
        ...(inReplyTo ? { 'In-Reply-To': inReplyTo } : {}),
      },
    )
    sendEvent('envelope', env)
    sendEvent('voice', {
      speaker,
      audio_b64: audio.audioB64,
      mime: audio.mime,
      transcript: text,
    })
    return env.id
  }

  async function bakeryTurn(
    convo: Array<{ role: 'user' | 'assistant'; content: string }>,
  ): Promise<string> {
    const result = streamText({
      model: languageModel(),
      instructions: BAKERY_SYSTEM_PROMPT,
      messages: convo,
      maxOutputTokens: capTokens(500),
      abortSignal: modelSignal(),
      onEnd: ({ usage, finishReason }) => {
        recordAmpDemoUsage(usageContext, {
          finishReason,
          messageCount: convo.length,
          mode: 'autonomous',
          modelId: languageModelId(),
          operation: 'bakery_turn',
          partner: 'bakery',
          success: true,
          usage,
        })
      },
      onError({ error }) {
        recordAmpDemoUsage(usageContext, {
          errorType: errorName(error),
          messageCount: convo.length,
          mode: 'autonomous',
          modelId: languageModelId(),
          operation: 'bakery_turn',
          partner: 'bakery',
          success: false,
        })
      },
    })
    let acc = ''
    for await (const chunk of result.textStream) {
      acc += chunk
      sendEvent('stream', { type: 'text_delta', text: chunk })
    }
    return acc.trim()
  }

  // ------------------------------------------------------------------
  // Turn 0 — YA speaks the brief to bakery, bakery replies first time.
  // ------------------------------------------------------------------
  const briefLine = await generateAgentLine('brief', {
    partner: 'Sunny Bakery',
    userMessage: brief,
  }, usageContext)
  await speak(YOUR_AGENT_LOCAL, SUNNY_BAKERY_LOCAL, 'your-agent', briefLine, 'nova')

  // Convo state passed into bakery LLM each turn. YA's brief is the
  // first "user" message from bakery's POV.
  const bakeryConvo: Array<{ role: 'user' | 'assistant'; content: string }> = [
    { role: 'user', content: brief },
  ]
  // History the classifier + reply generator see — plain prose, not Lang.
  const proseHistory: Array<{ role: string; content: string }> = []

  let bakeryLang = await bakeryTurn(bakeryConvo)
  let bakeryProse = langToProse(bakeryLang)
  bakeryConvo.push({ role: 'assistant', content: bakeryLang })
  proseHistory.push({ role: 'assistant', content: bakeryProse })
  await speak(SUNNY_BAKERY_LOCAL, YOUR_AGENT_LOCAL, 'bakery', bakeryProse, 'shimmer')

  // ------------------------------------------------------------------
  // The loop.
  // ------------------------------------------------------------------
  for (let turn = 1; turn <= AUTONOMOUS_TURN_CAP; turn++) {
    if (requestAborted()) return
    sendEvent('loop_turn', { turn, max: AUTONOMOUS_TURN_CAP })

    const decision = await classifyBakeryReply({
      brief,
      history: proseHistory,
      latestBakeryReply: bakeryProse,
      usageContext,
    })

    if (decision.kind === 'done') {
      const summary = await generateAgentLine('relay', {
        partner: 'Sunny Bakery',
        partnerText: `Order confirmed. ${bakeryProse}`,
      }, usageContext)
      await speak(YOUR_AGENT_LOCAL, 'user://you', 'your-agent', summary, 'nova')
      sendEvent('loop_done', { summary })
      return
    }

    if (decision.kind === 'ask_user') {
      // YA does NOT speak. The handoff to the user is silent — we surface
      // a chat-card with structured options (if any) or a text-input
      // request. The user answers via tap or typing in any of the three
      // synchronized surfaces (chat / protocol / voice mode), then the
      // /resume endpoint re-enters the loop with their answer.
      const question = await generateAgentLine('relay', {
        partner: 'Sunny Bakery',
        partnerText: bakeryProse,
      }, usageContext)
      const options = extractBakeryOptions(bakeryLang)
      const decisionId = makeId('decision')
      if (options.length > 0) {
        sendEvent('awaiting_user_card', {
          decisionId,
          question,
          options,
          lastBakeryReply: bakeryProse,
          history: proseHistory,
          brief,
        })
      } else {
        sendEvent('awaiting_user_text', {
          decisionId,
          question,
          lastBakeryReply: bakeryProse,
          history: proseHistory,
          brief,
        })
      }
      return
    }

    // decision.kind === 'answer' — YA replies to bakery, loop continues.
    const yaReply = await generateAgentToBakeryReply({
      brief,
      bakeryReply: bakeryProse,
      history: proseHistory,
      usageContext,
    })
    await speak(YOUR_AGENT_LOCAL, SUNNY_BAKERY_LOCAL, 'your-agent', yaReply, 'nova')
    bakeryConvo.push({ role: 'user', content: yaReply })
    proseHistory.push({ role: 'user', content: yaReply })

    bakeryLang = await bakeryTurn(bakeryConvo)
    bakeryProse = langToProse(bakeryLang)
    bakeryConvo.push({ role: 'assistant', content: bakeryLang })
    proseHistory.push({ role: 'assistant', content: bakeryProse })
    await speak(SUNNY_BAKERY_LOCAL, YOUR_AGENT_LOCAL, 'bakery', bakeryProse, 'shimmer')
  }

  // Cap hit. Hand off silently — no voice line.
  sendEvent('awaiting_user_text', {
    decisionId: makeId('decision'),
    question: "I couldn't finish this on my own. Can you take it from here?",
    lastBakeryReply: bakeryProse,
    history: proseHistory,
    brief,
  })
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------

// Request schema. Everything the client can send is listed here with a
// size cap; unknown fields are rejected. The client never chooses a model.
const HistoryEntry = z
  .object({
    role: z.enum(['user', 'assistant', 'bakery', 'porter', 'agent']),
    content: z.string().max(LIMITS.maxHistoryEntryChars),
  })
  .strict()

const DemoRequest = z
  .object({
    message: z.string().trim().min(1).max(LIMITS.maxMessageChars),
    history: z.array(HistoryEntry).max(LIMITS.maxHistoryEntries).default([]),
    isFirstTurn: z.boolean().optional(),
    targetAgent: z.enum(['bakery', 'porter']).default('bakery'),
    porterActive: z.boolean().default(false),
    voiceMode: z.boolean().default(false),
    mode: z.enum(['turn', 'autonomous']).default('turn'),
  })
  .strict()

export async function POST(request: Request) {
  const guard = guardRequest(request, { cost: 1 })
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
    const parsed = DemoRequest.safeParse(raw)
    if (!parsed.success) return jsonError(400, 'Invalid request')
    const input = parsed.data

    const message = input.message
    // Only the most recent turns are forwarded to the model.
    const history = input.history.slice(-LIMITS.historyTurnsForModel)
    const isFirstTurn = input.isFirstTurn ?? input.history.length === 0
    const targetAgent = input.targetAgent
    const porterActive = input.porterActive
    // 'turn'        — single round-trip (chat widget). Default.
    // 'autonomous'  — voice-call mode: server loops YA<->bakery until done,
    //                 user-input needed, or the turn cap. Implies voiceMode.
    const mode = input.mode
    const voiceMode = mode === 'autonomous' ? true : input.voiceMode

    // Autonomous mode can run many model + speech calls in one request,
    // so it costs extra rate-limit tokens on top of the base one.
    if (mode === 'autonomous') {
      const extra = guardRequest(request, { cost: 2 })
      if (extra instanceof Response) return extra
      extra.release()
    }

    // Warm the Ed25519 keystore for all demo agents so every envelope
    // signed downstream uses a key the client can fetch from
    // /api/amp-demo/keys.
    await ensureDemoKeys([
      YOUR_AGENT,
      SUNNY_BAKERY,
      PORTER_DELIVERY,
      'agent://directory.amp.example.com',
    ])

    const signal = requestSignal(request)
    streaming = true
    return withRequestContext(signal, () =>
      demoStream({
        message,
        history,
        isFirstTurn,
        targetAgent,
        porterActive,
        voiceMode,
        mode,
        signal,
        release: guard.release,
      }),
    )
  } catch (err) {
    logError('amp-demo', err)
    return jsonError(500, 'Something went wrong. Please try again.')
  } finally {
    if (!streaming) guard.release()
  }
}

function demoStream(args: {
  message: string
  history: Array<{ role: string; content: string }>
  isFirstTurn: boolean
  targetAgent: 'bakery' | 'porter'
  porterActive: boolean
  voiceMode: boolean
  mode: 'turn' | 'autonomous'
  signal: AbortSignal
  release: () => void
}): Response {
  const { message, history, isFirstTurn, targetAgent, porterActive, voiceMode, mode } = args
  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      const usageContext = undefined
      const traceId = makeTraceId()

      let closed = false
      function sendEvent(type: string, data: unknown) {
        if (closed) return
        const payload = JSON.stringify({ type, data })
        try {
          controller.enqueue(encoder.encode(`data: ${payload}\n\n`))
        } catch {
          closed = true
        }
      }

      try {
        // ===============================================================
        // AUTONOMOUS LOOP: Voice-call mode where the user gives a single
        // brief and YA conducts the whole conversation with Sunny on
        // its own. Returns control to the user only on completion or
        // when something genuinely needs human input.
        //
        // Lives BEFORE the routing block so the existing chat-widget
        // flow is untouched.
        // ===============================================================
        if (mode === 'autonomous') {
          await runAutonomousLoop({
            brief: message,
            history,
            traceId,
            sendEvent,
            usageContext,
          })
          return
        }

        // ===============================================================
        // ROUTING: my Agent asks Claude Haiku to classify the user's intent
        // (order / delivery / both) and routes accordingly.
        //
        // - delivery intent + porter already active  → forward to Porter
        // - delivery intent + porter not yet active  → bakery path (will auto-
        //   spawn porter afterwards if body type becomes task.quote/complete)
        // - order intent                             → bakery path
        // - both                                     → bakery first, porter after
        // ===============================================================
        const intent = await classifyIntent(message, { porterActive }, usageContext)
        sendEvent('status', {
          agent: YOUR_AGENT,
          step: `Intent classified as "${intent}" — routing accordingly`,
        })

        // My Agent's decision:
        // - If user explicitly targeted porter (via awaiting-agent state): Porter
        // - If user's message is delivery-only (regardless of porter state): Porter
        //   (Sunny Bakery doesn't handle delivery, so this would only waste a turn.)
        // - If user's message mentions both and Porter is already engaged: Porter
        // - Otherwise: Bakery
        const routeToPorter =
          !isFirstTurn &&
          (targetAgent === 'porter' ||
            intent === 'delivery' ||
            (porterActive && intent === 'both'))

        if (routeToPorter) {
          // If this is the first time we're talking to Porter, do discovery.
          if (!porterActive) {
            const porterDiscovery = await makeEnvelope(
              YOUR_AGENT,
              'agent://directory.amp.example.com',
              DIRECTORY_QUERY,
              {
                capability: 'logistics.delivery',
                location_hint: 'mumbai',
                filters: { category: 'same_day_delivery' },
              },
              { 'Trace-Id': traceId, 'Trust-Tier': 'verified' },
            )
            sendEvent('envelope', porterDiscovery)
            sendEvent('status', {
              agent: YOUR_AGENT,
              step: 'Sunny Bakery does not deliver — discovering a logistics agent...',
            })
            await delay(300)

            const porterDiscoveryResp = await makeEnvelope(
              'agent://directory.amp.example.com',
              YOUR_AGENT,
              DIRECTORY_RESPONSE,
              {
                results: [
                  {
                    agent_id: PORTER_DELIVERY,
                    name: 'Porter',
                    capabilities: ['logistics.delivery', 'logistics.quote', 'logistics.schedule'],
                    trust_tier: 'verified',
                    rating: 4.7,
                    description: 'On-demand delivery for restaurants and retailers',
                  },
                ],
              },
              {
                'Trace-Id': traceId,
                'In-Reply-To': porterDiscovery.id,
                'Trust-Tier': 'verified',
              },
            )
            sendEvent('envelope', porterDiscoveryResp)
            sendEvent('status', {
              agent: YOUR_AGENT,
              step: 'Found Porter (rated 4.7) — requesting delivery quote...',
            })
            await delay(300)
          }

          // Voice mode: Your Agent speaks the porter brief out loud
          // before forwarding the task.
          if (voiceMode) {
            const briefText = await generateAgentLine('brief', {
              partner: 'Porter',
              userMessage: message,
            }, usageContext)
            const briefAudio = await synthesizeSpeech(briefText, 'nova')
            if (briefAudio) {
              const briefEnv = await makeEnvelope(
                YOUR_AGENT,
                PORTER_DELIVERY,
                VOICE_UTTERANCE,
                {
                  transcript: briefText,
                  audio_b64: briefAudio.audioB64,
                  mime: briefAudio.mime,
                  speaker: 'your-agent',
                  role: 'brief',
                },
                { 'Trace-Id': traceId, 'Trust-Tier': 'verified' },
              )
              sendEvent('envelope', briefEnv)
              sendEvent('voice', {
                speaker: 'your-agent',
                audio_b64: briefAudio.audioB64,
                mime: briefAudio.mime,
                transcript: briefText,
              })
            }
          }

          const porterFollowupTask = await makeEnvelope(
            YOUR_AGENT,
            PORTER_DELIVERY,
            'task.create',
            {
              task_id: makeId('task'),
              description: message,
              intent: porterActive ? 'logistics.followup' : 'logistics.quote',
              pickup_agent: SUNNY_BAKERY,
              customer: { agent_id: YOUR_AGENT, request: message },
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'verified',
              'Chain-Budget': 'remaining=10.00USD;max=50.00USD',
            },
          )
          sendEvent('envelope', porterFollowupTask)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: porterActive
              ? 'Forwarded your reply to Porter'
              : 'Sent pickup request to Porter',
          })
          await delay(300)

          const porterAck = await makeEnvelope(
            PORTER_DELIVERY,
            YOUR_AGENT,
            'task.acknowledge',
            { estimated_duration_seconds: 6, message: 'Processing your reply...' },
            {
              'Trace-Id': traceId,
              'In-Reply-To': porterFollowupTask.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterAck)

          await delay(300)
          sendEvent('status', { agent: PORTER_DELIVERY, step: 'Porter is responding...' })

          const porterMessages: Array<{ role: 'user' | 'assistant'; content: string }> = []
          for (const h of history) {
            porterMessages.push({
              role: h.role === 'user' ? 'user' : 'assistant',
              content: h.content,
            })
          }
          // Frame the message with clear context so Porter knows the pickup
          // is from Sunny Bakery and what bakery conversation preceded this.
          porterMessages.push({
            role: 'user',
            content: `Context: Customer has an order at Sunny Bakery (Linking Rd, Bandra West, Mumbai). Sunny does not deliver. You are arranging the pickup and drop.\n\nCustomer's latest message:\n${message}\n\nIf you don't know the drop address yet, ASK for it in a PorterMessage. Otherwise, show a RoutePreview + 2–3 DeliverySlot options, or a CombinedQuote if everything is ready to confirm.`,
          })

          const porterFollowupResult = streamText({
            model: languageModel(),
            instructions: PORTER_SYSTEM_PROMPT,
            messages: porterMessages,
            maxOutputTokens: capTokens(500),
            abortSignal: modelSignal(),
            onEnd: ({ usage, finishReason }) => {
              recordAmpDemoUsage(usageContext, {
                finishReason,
                messageCount: porterMessages.length,
                mode,
                modelId: languageModelId(),
                operation: 'porter_followup',
                partner: 'porter',
                success: true,
                usage,
              })
            },
            onError({ error }) {
              recordAmpDemoUsage(usageContext, {
                errorType: errorName(error),
                messageCount: porterMessages.length,
                mode,
                modelId: languageModelId(),
                operation: 'porter_followup',
                partner: 'porter',
                success: false,
              })
            },
          })

          let porterText = ''
          for await (const chunk of porterFollowupResult.textStream) {
            porterText += chunk
            sendEvent('stream', { type: 'porter_text_delta', text: chunk })
          }

          const cleanPorterText = porterText.trim()

          let porterBodyType = 'task.progress'
          if (cleanPorterText.includes('DeliveryConfirmed(')) {
            porterBodyType = 'task.complete'
          } else if (cleanPorterText.includes('CombinedQuote(')) {
            porterBodyType = 'task.quote'
          } else if (
            cleanPorterText.includes('DeliverySlot(') ||
            cleanPorterText.includes('OptionGrid(')
          ) {
            porterBodyType = 'task.input_required'
          }

          const porterResp = await makeEnvelope(
            PORTER_DELIVERY,
            YOUR_AGENT,
            porterBodyType,
            {
              message: cleanPorterText,
              ...(porterBodyType === 'task.input_required' && { prompt: cleanPorterText }),
              ...(porterBodyType === 'task.quote' && { quote: cleanPorterText }),
              ...(porterBodyType === 'task.complete' && { result: cleanPorterText }),
            },
            {
              'Trace-Id': traceId,
              'In-Reply-To': porterFollowupTask.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterResp)

          const porterFwd = await makeEnvelope(
            YOUR_AGENT,
            'user://you',
            porterBodyType,
            {
              message: cleanPorterText,
              source_agent: PORTER_DELIVERY,
              ...(porterBodyType === 'task.input_required' && { prompt: cleanPorterText }),
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'owner',
            },
          )
          sendEvent('envelope', porterFwd)

          if (voiceMode) {
            const spoken = extractSpokenText(cleanPorterText)
            if (spoken) {
              // Porter speaks TO YOUR AGENT (not to the user directly).
              const porterAudio = await synthesizeSpeech(spoken, 'onyx')
              if (porterAudio) {
                const porterVoiceEnv = await makeEnvelope(
                  PORTER_DELIVERY,
                  YOUR_AGENT,
                  VOICE_UTTERANCE,
                  {
                    transcript: spoken,
                    audio_b64: porterAudio.audioB64,
                    mime: porterAudio.mime,
                    speaker: 'porter',
                  },
                  {
                    'Trace-Id': traceId,
                    'In-Reply-To': porterFollowupTask.id,
                    'Trust-Tier': 'verified',
                  },
                )
                sendEvent('envelope', porterVoiceEnv)
                sendEvent('voice', {
                  speaker: 'porter',
                  audio_b64: porterAudio.audioB64,
                  mime: porterAudio.mime,
                  transcript: spoken,
                })
              }

              // Your Agent paraphrases Porter's reply for the user.
              const relayText = await generateAgentLine('relay', {
                partner: 'Porter',
                partnerText: spoken,
              }, usageContext)
              const relayAudio = await synthesizeSpeech(relayText, 'nova')
              if (relayAudio) {
                const relayEnv = await makeEnvelope(
                  YOUR_AGENT,
                  'user://you',
                  VOICE_UTTERANCE,
                  {
                    transcript: relayText,
                    audio_b64: relayAudio.audioB64,
                    mime: relayAudio.mime,
                    speaker: 'your-agent',
                    role: 'relay',
                  },
                  { 'Trace-Id': traceId, 'Trust-Tier': 'owner' },
                )
                sendEvent('envelope', relayEnv)
                sendEvent('voice', {
                  speaker: 'your-agent',
                  audio_b64: relayAudio.audioB64,
                  mime: relayAudio.mime,
                  transcript: relayText,
                })
              }
            }
          }

          sendEvent('done', { bakeryResponse: cleanPorterText, bodyType: porterBodyType })
          return
        }

        if (isFirstTurn) {
          // =============================================================
          // FIRST TURN: Full discovery + task.create flow
          // =============================================================

          // Step 1: User -> Your Agent (task.create)
          const taskCreateEnvelope = await makeEnvelope(
            'user://you',
            YOUR_AGENT,
            'task.create',
            {
              task_id: makeId('task'),
              description: message,
              intent: 'order.place',
              metadata: {
                source: 'chat',
                timestamp: new Date().toISOString(),
              },
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'owner',
            },
          )
          sendEvent('envelope', taskCreateEnvelope)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Received your request — looking for a bakery agent...',
          })

          await delay(400)

          // Step 2: Discovery query
          const discoveryEnvelope = await makeEnvelope(
            YOUR_AGENT,
            'agent://directory.amp.example.com',
            DIRECTORY_QUERY,
            {
              capability: 'bakery.order',
              location_hint: 'local',
              filters: {
                category: 'bakery',
                accepts_custom_orders: true,
              },
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', discoveryEnvelope)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Querying agent directory for bakery services...',
          })

          await delay(300)

          // Discovery response
          const discoveryResponseEnvelope = await makeEnvelope(
            'agent://directory.amp.example.com',
            YOUR_AGENT,
            DIRECTORY_RESPONSE,
            {
              results: [
                {
                  agent_id: SUNNY_BAKERY,
                  name: 'Sunny Bakery',
                  capabilities: ['bakery.order', 'bakery.quote', 'bakery.custom'],
                  trust_tier: 'verified',
                  rating: 4.8,
                  description: 'Artisan bakery specializing in custom cakes and pastries',
                },
              ],
            },
            {
              'Trace-Id': traceId,
              'In-Reply-To': discoveryEnvelope.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', discoveryResponseEnvelope)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Found Sunny Bakery (rated 4.8) — sending order request...',
          })

          await delay(400)
        }

        // =============================================================
        // EVERY TURN: task.create from Your Agent -> Bakery + response
        // =============================================================

        // In voice mode, Your Agent speaks a brief out loud BEFORE forwarding
        // to the bakery, so the user can hear what's being sent on their behalf.
        if (voiceMode) {
          const briefText = await generateAgentLine('brief', {
            partner: 'Sunny Bakery',
            userMessage: message,
          }, usageContext)
          const briefAudio = await synthesizeSpeech(briefText, 'nova')
          if (briefAudio) {
            const briefEnv = await makeEnvelope(
              YOUR_AGENT,
              SUNNY_BAKERY,
              VOICE_UTTERANCE,
              {
                transcript: briefText,
                audio_b64: briefAudio.audioB64,
                mime: briefAudio.mime,
                speaker: 'your-agent',
                role: 'brief',
              },
              { 'Trace-Id': traceId, 'Trust-Tier': 'verified' },
            )
            sendEvent('envelope', briefEnv)
            sendEvent('voice', {
              speaker: 'your-agent',
              audio_b64: briefAudio.audioB64,
              mime: briefAudio.mime,
              transcript: briefText,
            })
          }
        }

        // Your Agent -> Sunny Bakery (task.create)
        const orderTaskEnvelope = await makeEnvelope(
          YOUR_AGENT,
          SUNNY_BAKERY,
          'task.create',
          {
            task_id: makeId('task'),
            description: message,
            intent: isFirstTurn ? 'bakery.order' : 'bakery.followup',
            customer: {
              agent_id: YOUR_AGENT,
              preferred_contact: 'amp',
            },
          },
          {
            'Trace-Id': traceId,
            'Trust-Tier': 'verified',
            'Chain-Budget': 'remaining=10.00USD;max=50.00USD',
          },
        )
        sendEvent('envelope', orderTaskEnvelope)
        sendEvent('status', {
          agent: YOUR_AGENT,
          step: isFirstTurn
            ? 'Order request sent to Sunny Bakery'
            : 'Follow-up sent to Sunny Bakery',
        })

        await delay(300)

        // Sunny Bakery acknowledges
        const ackEnvelope = await makeEnvelope(
          SUNNY_BAKERY,
          YOUR_AGENT,
          'task.acknowledge',
          {
            estimated_duration_seconds: 10,
            message: isFirstTurn
              ? 'Got your order! Let me check what we can do.'
              : 'Got it, updating your order...',
          },
          {
            'Trace-Id': traceId,
            'In-Reply-To': orderTaskEnvelope.id,
            'Trust-Tier': 'verified',
          },
        )
        sendEvent('envelope', ackEnvelope)
        sendEvent('status', {
          agent: SUNNY_BAKERY,
          step: isFirstTurn
            ? 'Sunny Bakery acknowledged — checking availability...'
            : 'Processing your follow-up...',
        })

        await delay(400)

        // Bakery thinking
        if (isFirstTurn) {
          sendEvent('stream', { type: 'thinking', text: 'Reading the order details...' })
          await delay(300)
          sendEvent('stream', { type: 'thinking', text: 'Checking ingredient inventory...' })
          await delay(300)
        }

        // =============================================================
        // Stream Sunny's response using Claude with full conversation
        // =============================================================
        sendEvent('status', {
          agent: SUNNY_BAKERY,
          step: 'Sunny is responding...',
        })

        // Build the messages array for Claude: system + conversation history + current message
        const claudeMessages: Array<{ role: 'user' | 'assistant'; content: string }> = []

        // Add conversation history
        for (const h of history) {
          claudeMessages.push({
            role: h.role === 'user' ? 'user' : 'assistant',
            content: h.content,
          })
        }

        // Add the current user message
        claudeMessages.push({ role: 'user', content: message })

        const bakeryResult = streamText({
          model: languageModel(),
          instructions: BAKERY_SYSTEM_PROMPT,
          messages: claudeMessages,
          maxOutputTokens: capTokens(500),
          abortSignal: modelSignal(),
          onEnd: ({ usage, finishReason }) => {
            recordAmpDemoUsage(usageContext, {
              finishReason,
              messageCount: claudeMessages.length,
              mode,
              modelId: languageModelId(),
              operation: 'bakery_turn',
              partner: 'bakery',
              success: true,
              usage,
            })
          },
          onError({ error }) {
            recordAmpDemoUsage(usageContext, {
              errorType: errorName(error),
              messageCount: claudeMessages.length,
              mode,
              modelId: languageModelId(),
              operation: 'bakery_turn',
              partner: 'bakery',
              success: false,
            })
          },
        })

        // Stream OpenUI Lang text line by line as text_delta events
        let fullResponse = ''
        for await (const chunk of bakeryResult.textStream) {
          fullResponse += chunk
          sendEvent('stream', { type: 'text_delta', text: chunk })
        }

        sendEvent('stream', { type: 'done', text: '' })

        const cleanResponse = fullResponse.trim()

        await delay(300)

        // Determine AMP body type from the OpenUI Lang content
        let ampBodyType = 'task.progress'
        let ampStatus = 'in_progress'

        if (cleanResponse.includes('OrderConfirmed(')) {
          ampBodyType = 'task.complete'
          ampStatus = 'completed'
        } else if (cleanResponse.includes('PriceQuote(')) {
          ampBodyType = 'task.quote'
          ampStatus = 'quoted'
        } else if (cleanResponse.includes('OptionGrid(') || cleanResponse.includes('CakeOption(') || cleanResponse.includes('SizeOption(') || cleanResponse.includes('DecorationOption(')) {
          ampBodyType = 'task.input_required'
          ampStatus = 'awaiting_input'
        }

        // Sunny Bakery response envelope with correct AMP body type
        const responseEnvelope = await makeEnvelope(
          SUNNY_BAKERY,
          YOUR_AGENT,
          ampBodyType,
          {
            message: cleanResponse,
            status: ampStatus,
            ...(ampBodyType === 'task.input_required' && {
              required_fields: ['customer_response'],
              prompt: cleanResponse,
            }),
            ...(ampBodyType === 'task.quote' && {
              quote: cleanResponse,
              valid_until: new Date(Date.now() + 3600000).toISOString(),
            }),
            ...(ampBodyType === 'task.complete' && {
              result: cleanResponse,
              cost_receipt: {
                agent_id: SUNNY_BAKERY,
                protocol_fee_usd: 0.02,
                timestamp: new Date().toISOString(),
              },
            }),
          },
          {
            'Trace-Id': traceId,
            'In-Reply-To': orderTaskEnvelope.id,
            'Trust-Tier': 'verified',
          },
        )
        sendEvent('envelope', responseEnvelope)
        sendEvent('status', {
          agent: SUNNY_BAKERY,
          step: ampBodyType === 'task.input_required'
            ? 'Bakery needs more information from you'
            : ampBodyType === 'task.quote'
              ? 'Bakery sent a price quote'
              : ampBodyType === 'task.complete'
                ? 'Order confirmed!'
                : 'Response sent',
        })

        // Your Agent forwards to user with appropriate body type
        const forwardBodyType = ampBodyType === 'task.input_required'
          ? 'task.input_required'
          : ampBodyType === 'task.quote'
            ? 'task.quote'
            : ampBodyType === 'task.complete'
              ? 'task.complete'
              : 'task.progress'

        const forwardEnvelope = await makeEnvelope(
          YOUR_AGENT,
          'user://you',
          forwardBodyType,
          {
            message: cleanResponse,
            source_agent: SUNNY_BAKERY,
            ...(forwardBodyType === 'task.input_required' && {
              prompt: cleanResponse,
              awaiting_your_response: true,
            }),
          },
          {
            'Trace-Id': traceId,
            'Trust-Tier': 'owner',
          },
        )
        sendEvent('envelope', forwardEnvelope)

        if (voiceMode) {
          const spoken = extractSpokenText(cleanResponse)
          if (spoken) {
            // Bakery speaks TO YOUR AGENT (not to the user directly) —
            // this is the whole point of having an intermediary agent.
            const bakeryAudio = await synthesizeSpeech(spoken, 'shimmer')
            if (bakeryAudio) {
              const bakeryVoiceEnv = await makeEnvelope(
                SUNNY_BAKERY,
                YOUR_AGENT,
                VOICE_UTTERANCE,
                {
                  transcript: spoken,
                  audio_b64: bakeryAudio.audioB64,
                  mime: bakeryAudio.mime,
                  speaker: 'bakery',
                },
                {
                  'Trace-Id': traceId,
                  'In-Reply-To': orderTaskEnvelope.id,
                  'Trust-Tier': 'verified',
                },
              )
              sendEvent('envelope', bakeryVoiceEnv)
              sendEvent('voice', {
                speaker: 'bakery',
                audio_b64: bakeryAudio.audioB64,
                mime: bakeryAudio.mime,
                transcript: spoken,
              })
            }

            // Your Agent then paraphrases the bakery's reply to the user.
            const relayText = await generateAgentLine('relay', {
              partner: 'Sunny Bakery',
              partnerText: spoken,
            }, usageContext)
            const relayAudio = await synthesizeSpeech(relayText, 'nova')
            if (relayAudio) {
              const relayEnv = await makeEnvelope(
                YOUR_AGENT,
                'user://you',
                VOICE_UTTERANCE,
                {
                  transcript: relayText,
                  audio_b64: relayAudio.audioB64,
                  mime: relayAudio.mime,
                  speaker: 'your-agent',
                  role: 'relay',
                },
                { 'Trace-Id': traceId, 'Trust-Tier': 'owner' },
              )
              sendEvent('envelope', relayEnv)
              sendEvent('voice', {
                speaker: 'your-agent',
                audio_b64: relayAudio.audioB64,
                mime: relayAudio.mime,
                transcript: relayText,
              })
            }
          }
        }

        if (ampBodyType === 'task.input_required') {
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Sunny Bakery needs your input — please reply below',
          })
        } else if (ampBodyType === 'task.complete') {
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Order confirmed! Thank you.',
          })
        }

        // =============================================================
        // PORTER: spawn delivery agent when the user asked for delivery
        // and the bakery has produced a quote or completion
        // =============================================================
        const shouldSpawnPorter =
          (intent === 'delivery' || intent === 'both') &&
          !porterActive &&
          (ampBodyType === 'task.quote' || ampBodyType === 'task.complete')

        if (shouldSpawnPorter) {
          await delay(300)

          // Your Agent -> Porter discovery
          const porterDiscoveryEnvelope = await makeEnvelope(
            YOUR_AGENT,
            'agent://directory.amp.example.com',
            DIRECTORY_QUERY,
            {
              capability: 'logistics.delivery',
              location_hint: 'mumbai',
              filters: { category: 'same_day_delivery' },
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterDiscoveryEnvelope)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Looking for a delivery agent to complete the order...',
          })

          await delay(300)

          const porterDiscoveryResponse = await makeEnvelope(
            'agent://directory.amp.example.com',
            YOUR_AGENT,
            DIRECTORY_RESPONSE,
            {
              results: [
                {
                  agent_id: PORTER_DELIVERY,
                  name: 'Porter',
                  capabilities: ['logistics.delivery', 'logistics.quote', 'logistics.schedule'],
                  trust_tier: 'verified',
                  rating: 4.7,
                  description: 'On-demand delivery for restaurants and retailers',
                },
              ],
            },
            {
              'Trace-Id': traceId,
              'In-Reply-To': porterDiscoveryEnvelope.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterDiscoveryResponse)
          sendEvent('status', {
            agent: YOUR_AGENT,
            step: 'Found Porter (rated 4.7) — requesting delivery quote...',
          })

          await delay(300)

          // Your Agent -> Porter task.create
          const porterTaskEnvelope = await makeEnvelope(
            YOUR_AGENT,
            PORTER_DELIVERY,
            'task.create',
            {
              task_id: makeId('task'),
              description: `Delivery for bakery order: ${message}`,
              intent: 'logistics.quote',
              pickup_agent: SUNNY_BAKERY,
              order_summary: cleanResponse,
              customer: {
                agent_id: YOUR_AGENT,
                request: message,
              },
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'verified',
              'Chain-Budget': 'remaining=10.00USD;max=50.00USD',
            },
          )
          sendEvent('envelope', porterTaskEnvelope)
          sendEvent('status', {
            agent: PORTER_DELIVERY,
            step: 'Porter received pickup request — checking drivers...',
          })

          await delay(400)

          // Porter acknowledges
          const porterAckEnvelope = await makeEnvelope(
            PORTER_DELIVERY,
            YOUR_AGENT,
            'task.acknowledge',
            {
              estimated_duration_seconds: 8,
              message: 'Checking available drivers near Sunny Bakery...',
            },
            {
              'Trace-Id': traceId,
              'In-Reply-To': porterTaskEnvelope.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterAckEnvelope)

          await delay(300)

          sendEvent('status', {
            agent: PORTER_DELIVERY,
            step: 'Porter is generating delivery quote...',
          })

          // Porter Claude call
          const porterClaudeMessages: Array<{ role: 'user' | 'assistant'; content: string }> = [
            {
              role: 'user',
              content: `Customer order from Sunny Bakery:\n${cleanResponse}\n\nCustomer's original request:\n${message}\n\nQuote a delivery from Sunny Bakery (Linking Rd, Bandra West, Mumbai) to the customer's stated address. If no address was given, ask for it. Include route, 2–3 time slot options, and a CombinedQuote that adds the bakery total + your delivery fee.`,
            },
          ]

          const porterResult = streamText({
            model: languageModel(),
            instructions: PORTER_SYSTEM_PROMPT,
            messages: porterClaudeMessages,
            maxOutputTokens: capTokens(500),
            abortSignal: modelSignal(),
            onEnd: ({ usage, finishReason }) => {
              recordAmpDemoUsage(usageContext, {
                finishReason,
                messageCount: porterClaudeMessages.length,
                mode,
                modelId: languageModelId(),
                operation: 'porter_quote',
                partner: 'porter',
                success: true,
                usage,
              })
            },
            onError({ error }) {
              recordAmpDemoUsage(usageContext, {
                errorType: errorName(error),
                messageCount: porterClaudeMessages.length,
                mode,
                modelId: languageModelId(),
                operation: 'porter_quote',
                partner: 'porter',
                success: false,
              })
            },
          })

          let porterResponse = ''
          for await (const chunk of porterResult.textStream) {
            porterResponse += chunk
            sendEvent('stream', { type: 'porter_text_delta', text: chunk })
          }

          const cleanPorterResponse = porterResponse.trim()

          // Determine Porter's AMP body type
          let porterBodyType = 'task.progress'
          if (cleanPorterResponse.includes('DeliveryConfirmed(')) {
            porterBodyType = 'task.complete'
          } else if (cleanPorterResponse.includes('CombinedQuote(')) {
            porterBodyType = 'task.quote'
          } else if (
            cleanPorterResponse.includes('DeliverySlot(') ||
            cleanPorterResponse.includes('OptionGrid(')
          ) {
            porterBodyType = 'task.input_required'
          }

          const porterResponseEnvelope = await makeEnvelope(
            PORTER_DELIVERY,
            YOUR_AGENT,
            porterBodyType,
            {
              message: cleanPorterResponse,
              ...(porterBodyType === 'task.input_required' && {
                prompt: cleanPorterResponse,
              }),
              ...(porterBodyType === 'task.quote' && {
                quote: cleanPorterResponse,
              }),
              ...(porterBodyType === 'task.complete' && {
                result: cleanPorterResponse,
              }),
            },
            {
              'Trace-Id': traceId,
              'In-Reply-To': porterTaskEnvelope.id,
              'Trust-Tier': 'verified',
            },
          )
          sendEvent('envelope', porterResponseEnvelope)
          sendEvent('status', {
            agent: PORTER_DELIVERY,
            step:
              porterBodyType === 'task.quote'
                ? 'Porter sent delivery quote'
                : porterBodyType === 'task.complete'
                  ? 'Delivery scheduled!'
                  : 'Porter needs more information',
          })

          // Forward to user
          const porterForwardEnvelope = await makeEnvelope(
            YOUR_AGENT,
            'user://you',
            porterBodyType,
            {
              message: cleanPorterResponse,
              source_agent: PORTER_DELIVERY,
              ...(porterBodyType === 'task.input_required' && {
                prompt: cleanPorterResponse,
              }),
            },
            {
              'Trace-Id': traceId,
              'Trust-Tier': 'owner',
            },
          )
          sendEvent('envelope', porterForwardEnvelope)
        }

        sendEvent('done', { bakeryResponse: cleanResponse, bodyType: ampBodyType })
      } catch (err) {
        if (!args.signal.aborted) logError('amp-demo', err)
        sendEvent('error', {
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
