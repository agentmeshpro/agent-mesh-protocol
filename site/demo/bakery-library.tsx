'use client'

/**
 * OpenUI component library for the Sunny Bakery agent.
 *
 * These components define what UI the bakery agent can generate
 * via OpenUI Lang. The LLM outputs syntax like:
 *
 *   root = OptionGrid([c1, c2, c3])
 *   c1 = CakeOption("Chocolate", "Rich & moist", "$25")
 *   c2 = CakeOption("Vanilla", "Classic flavor", "$22")
 *   c3 = CakeOption("Red Velvet", "Cream cheese frosting", "$28")
 *
 * The Renderer parses this and renders real React components.
 */

import { defineComponent, createLibrary, useTriggerAction } from '@openuidev/react-lang'
import { z } from 'zod'

// ---------------------------------------------------------------------------
// Bakery message — simple text from Sunny
// ---------------------------------------------------------------------------

const BakeryMessage = defineComponent({
  name: 'BakeryMessage',
  description: 'A friendly text message from Sunny Bakery',
  props: z.object({
    text: z.string().describe('The message text'),
  }),
  component: ({ props }) => (
    <p
      className="font-sans text-[15px] font-medium leading-[22.5px]"
      style={{ color: '#4A3A31' }}
    >
      {props.text}
    </p>
  ),
})

// ---------------------------------------------------------------------------
// Cake option card — for flavor/type selection
// ---------------------------------------------------------------------------

const CakeOption = defineComponent({
  name: 'CakeOption',
  description: 'A full-bleed cake option card with image, name, description, and price',
  props: z.object({
    name: z.string().describe('Cake name like Chocolate, Vanilla'),
    description: z.string().describe('Short description'),
    price: z.string().describe('Price like ₹1500 or $25'),
    image: z
      .string()
      .optional()
      .describe('Unsplash image URL showing this cake type'),
    emoji: z.string().optional().describe('Fallback emoji if no image'),
  }),
  component: function CakeOptionView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <button
        type="button"
        onClick={() => triggerAction(props.name)}
        className="group flex w-full cursor-pointer flex-col overflow-hidden rounded-[18px] bg-white text-left transition-shadow hover:shadow-[0_6px_20px_rgba(74,58,49,0.10)] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#C86948]"
        style={{ border: '1px solid rgba(231, 229, 228, 0.6)' }}
      >
        <div
          className="relative aspect-[5/4] w-full overflow-hidden"
          style={{ backgroundColor: '#FCE2D8' }}
        >
          {props.image ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={props.image}
              alt={props.name}
              className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-[1.03]"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center text-4xl">
              {props.emoji || '🎂'}
            </div>
          )}
        </div>
        <div className="flex flex-col gap-1 p-[14px]">
          <div className="flex items-baseline justify-between gap-3">
            <p
              className="font-[family-name:var(--font-newsreader)] text-[18px] font-normal leading-[24px]"
              style={{ color: '#4A3A31' }}
            >
              {props.name}
            </p>
            <p
              className="shrink-0 font-sans text-[15px] font-medium leading-[22px]"
              style={{ color: '#C86948' }}
            >
              {props.price}
            </p>
          </div>
          <p
            className="line-clamp-2 font-sans text-[13px] font-normal leading-[19px]"
            style={{ color: '#78716C' }}
          >
            {props.description}
          </p>
        </div>
      </button>
    )
  },
})

// ---------------------------------------------------------------------------
// Option grid — wraps multiple options in a grid
// ---------------------------------------------------------------------------

const OptionGrid = defineComponent({
  name: 'OptionGrid',
  description: 'A grid layout for displaying multiple options to choose from',
  props: z.object({
    children: z.array(z.any()).describe('The option cards to display'),
  }),
  component: ({ props, renderNode }) => (
    <div
      className="cake-carousel -mx-1 flex snap-x snap-mandatory gap-3 overflow-x-auto px-1 pb-2"
      style={{ scrollbarWidth: 'thin', WebkitOverflowScrolling: 'touch' }}
    >
      <style>{`
        .cake-carousel > * {
          flex: 0 0 75%;
          scroll-snap-align: start;
          min-width: 220px;
          max-width: 280px;
        }
        @media (min-width: 768px) {
          .cake-carousel > * { flex: 0 0 48%; }
        }
        @media (min-width: 1280px) {
          .cake-carousel > * { flex: 0 0 32%; }
        }
      `}</style>
      {renderNode(props.children)}
    </div>
  ),
})

// ---------------------------------------------------------------------------
// Size option — for size selection
// ---------------------------------------------------------------------------

const SizeOption = defineComponent({
  name: 'SizeOption',
  description: 'A size selection option with serves count and price',
  props: z.object({
    size: z.string().describe('Size name like Small, Medium, Large'),
    serves: z.string().describe('Serves count like 6-8, 12-15'),
    price: z.string().describe('Price like $25'),
  }),
  component: function SizeOptionView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <button
        type="button"
        onClick={() => triggerAction(props.size)}
        className="flex cursor-pointer flex-col items-center justify-center rounded-[18px] bg-white px-4 py-[14px] text-center transition-shadow hover:shadow-[0_6px_20px_rgba(74,58,49,0.10)] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#C86948]"
        style={{ border: '1px solid rgba(231, 229, 228, 0.6)' }}
      >
        <p
          className="font-[family-name:var(--font-newsreader)] text-[17px] font-normal leading-[22px]"
          style={{ color: '#4A3A31' }}
        >
          {props.size}
        </p>
        <p
          className="mt-[2px] font-sans text-[12px] font-normal leading-[17px]"
          style={{ color: '#78716C' }}
        >
          Serves {props.serves}
        </p>
        <p
          className="mt-1 font-sans text-[14px] font-medium leading-[20px]"
          style={{ color: '#C86948' }}
        >
          {props.price}
        </p>
      </button>
    )
  },
})

// ---------------------------------------------------------------------------
// Price quote — order summary with confirm button
// ---------------------------------------------------------------------------

const PriceQuote = defineComponent({
  name: 'PriceQuote',
  description: 'An order summary card with price and confirm button',
  props: z.object({
    summary: z.string().describe('Order summary text'),
    total: z.string().describe('Total price like $35'),
    readyBy: z.string().describe('When the order will be ready'),
  }),
  component: function PriceQuoteView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <div
        className="rounded-[22px] p-[22px]"
        style={{
          backgroundColor: '#FCE2D8',
          border: '1px solid rgba(231, 229, 228, 0.6)',
        }}
      >
        <p
          className="font-sans text-[15px] font-medium leading-[22.5px]"
          style={{ color: '#4A3A31' }}
        >
          {props.summary}
        </p>
        <div className="mt-4 flex items-center justify-between">
          <div>
            <p
              className="font-[family-name:var(--font-newsreader)] text-[21px] font-normal leading-[27.3px]"
              style={{ color: '#C86948' }}
            >
              {props.total}
            </p>
            <p
              className="font-sans text-[13px] font-normal leading-[19.5px]"
              style={{ color: '#78716C' }}
            >
              Ready by {props.readyBy}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => triggerAction('Change order')}
              className="rounded-full bg-white px-4 py-[10px] font-sans text-[14px] font-medium leading-[20px] transition-colors hover:bg-[#FBF3F0]"
              style={{
                color: '#3C3A36',
                border: '1px solid rgba(231, 229, 228, 0.6)',
              }}
            >
              Change
            </button>
            <button
              type="button"
              onClick={() => triggerAction('Confirm order')}
              className="rounded-full px-4 py-[10px] font-sans text-[14px] font-medium leading-[20px] transition-opacity hover:opacity-90"
              style={{
                backgroundColor: '#C86948',
                color: '#FFFFFF',
              }}
            >
              Confirm Order
            </button>
          </div>
        </div>
      </div>
    )
  },
})

// ---------------------------------------------------------------------------
// Order confirmed — success card
// ---------------------------------------------------------------------------

const OrderConfirmed = defineComponent({
  name: 'OrderConfirmed',
  description: 'Order confirmation card with order number and details',
  props: z.object({
    orderNumber: z.string().describe('Order number like SB-4821'),
    summary: z.string().describe('Order summary'),
    total: z.string().describe('Total price'),
    pickupTime: z.string().describe('Pickup time'),
  }),
  component: ({ props }) => (
    <div
      className="rounded-[22px] p-[22px]"
      style={{
        backgroundColor: '#F2F6F2',
        border: '1px solid rgba(90, 139, 88, 0.3)',
      }}
    >
      <div className="mb-3 flex items-center gap-2">
        <span className="text-xl">✅</span>
        <p
          className="font-sans text-[15px] font-medium leading-[22.5px]"
          style={{ color: '#3F613E' }}
        >
          Order Confirmed
        </p>
      </div>
      <p
        className="font-sans text-[13px] font-normal leading-[19.5px]"
        style={{ color: '#78716C' }}
      >
        Order #{props.orderNumber}
      </p>
      <p
        className="mt-2 font-sans text-[15px] font-medium leading-[22.5px]"
        style={{ color: '#4A3A31' }}
      >
        {props.summary}
      </p>
      <div
        className="mt-4 flex items-center justify-between pt-4"
        style={{ borderTop: '1px solid rgba(90, 139, 88, 0.3)' }}
      >
        <p
          className="font-[family-name:var(--font-newsreader)] text-[21px] font-normal leading-[27.3px]"
          style={{ color: '#C86948' }}
        >
          {props.total}
        </p>
        <p
          className="font-sans text-[13px] font-normal leading-[19.5px]"
          style={{ color: '#78716C' }}
        >
          Pickup: {props.pickupTime}
        </p>
      </div>
    </div>
  ),
})

// ---------------------------------------------------------------------------
// Decoration option
// ---------------------------------------------------------------------------

const DecorationOption = defineComponent({
  name: 'DecorationOption',
  description: 'A decoration or message option for the cake',
  props: z.object({
    label: z.string().describe('Decoration label like Happy Birthday'),
    emoji: z.string().optional().describe('Emoji'),
  }),
  component: function DecorationOptionView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <button
        type="button"
        onClick={() => triggerAction(props.label)}
        className="flex cursor-pointer items-center gap-2 rounded-full bg-white px-4 py-[10px] font-sans text-[14px] font-medium leading-[20px] transition-colors hover:bg-[#FBF3F0] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#C86948]"
        style={{
          color: '#3C3A36',
          border: '1px solid rgba(231, 229, 228, 0.6)',
        }}
      >
        {props.emoji && <span>{props.emoji}</span>}
        <span>{props.label}</span>
      </button>
    )
  },
})

// ---------------------------------------------------------------------------
// Stack layout — vertical stack of elements
// ---------------------------------------------------------------------------

const Stack = defineComponent({
  name: 'Stack',
  description: 'A vertical stack layout for arranging content',
  props: z.object({
    children: z.array(z.any()).describe('Content to stack vertically'),
  }),
  component: ({ props, renderNode }) => (
    <div className="flex flex-col gap-3">
      {renderNode(props.children)}
    </div>
  ),
})

// ---------------------------------------------------------------------------
// Create and export the library
// ---------------------------------------------------------------------------

export const bakeryLibrary = createLibrary({
  components: [
    BakeryMessage,
    CakeOption,
    OptionGrid,
    SizeOption,
    PriceQuote,
    OrderConfirmed,
    DecorationOption,
    Stack,
  ],
  root: 'Stack',
})

export const bakeryPromptAddendum = bakeryLibrary.prompt({
  preamble: 'You are Sunny, the owner of Sunny Bakery. You take custom cake and pastry orders. Be warm and friendly.',
  additionalRules: [
    'Always wrap your response in a Stack',
    'Start with a BakeryMessage for your greeting/question text',
    'When offering choices, use OptionGrid with CakeOption or SizeOption or DecorationOption cards',
    'When giving a price quote, use PriceQuote',
    'When confirming an order, use OrderConfirmed',
    'Keep messages SHORT (1-2 sentences)',
    'Ask ONE question at a time',
  ],
  examples: [
    `root = Stack([msg, grid])
msg = BakeryMessage("What flavor would you like?")
grid = OptionGrid([c1, c2, c3])
c1 = CakeOption("Chocolate", "Rich & moist", "$25", "🍫")
c2 = CakeOption("Vanilla", "Classic flavor", "$22", "🍦")
c3 = CakeOption("Red Velvet", "Cream cheese frosting", "$28", "❤️")`,

    `root = Stack([msg, quote])
msg = BakeryMessage("Here's your order summary:")
quote = PriceQuote("Medium Chocolate Cake with Happy Birthday", "$35", "10am tomorrow")`,

    `root = Stack([confirmed])
confirmed = OrderConfirmed("SB-4821", "Medium Chocolate Cake with Happy Birthday", "$35", "10am tomorrow")`,
  ],
})
