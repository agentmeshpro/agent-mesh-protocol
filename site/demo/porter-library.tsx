'use client'

/**
 * OpenUI component library for the Porter Delivery agent.
 *
 * Porter handles pickup from partner merchants (like Sunny Bakery) and
 * delivery to customer addresses. The LLM outputs OpenUI Lang that
 * renders DeliverySlot cards, a RoutePreview, and CombinedQuote cards.
 */

import { defineComponent, createLibrary, useTriggerAction } from '@openuidev/react-lang'
import { z } from 'zod'

// ---------------------------------------------------------------------------
// PorterMessage — simple text from Porter
// ---------------------------------------------------------------------------

const PorterMessage = defineComponent({
  name: 'PorterMessage',
  description: 'A text message from the Porter delivery agent',
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
// DeliverySlot — selectable time window with driver + fee
// ---------------------------------------------------------------------------

const DeliverySlot = defineComponent({
  name: 'DeliverySlot',
  description: 'A selectable delivery time slot with driver info and fee',
  props: z.object({
    window: z.string().describe('Time window like 2:30pm-2:45pm'),
    driver: z.string().describe('Driver name like Rahul S.'),
    vehicle: z.string().describe('Vehicle type like Bike or Mini-truck'),
    fee: z.string().describe('Delivery fee like ₹80'),
  }),
  component: function DeliverySlotView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <button
        type="button"
        onClick={() => triggerAction(props.window)}
        className="flex w-full cursor-pointer flex-col rounded-[22px] bg-white p-[18px] text-left transition-colors hover:bg-[#FBF3F0] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#C86948]"
        style={{ border: '1px solid rgba(231, 229, 228, 0.6)' }}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <p
              className="font-[family-name:var(--font-newsreader)] text-[21px] font-normal leading-[27.3px]"
              style={{ color: '#4A3A31' }}
            >
              {props.window}
            </p>
            <p
              className="mt-1 font-sans text-[13px] font-normal leading-[19.5px]"
              style={{ color: '#78716C' }}
            >
              {props.driver} • {props.vehicle}
            </p>
          </div>
          <p
            className="font-sans text-[15px] font-medium leading-[22.5px]"
            style={{ color: '#C86948' }}
          >
            {props.fee}
          </p>
        </div>
      </button>
    )
  },
})

// ---------------------------------------------------------------------------
// RoutePreview — pickup → drop route summary
// ---------------------------------------------------------------------------

const RoutePreview = defineComponent({
  name: 'RoutePreview',
  description: 'A pickup → drop route preview with addresses and distance',
  props: z.object({
    pickup: z.string().describe('Pickup address'),
    drop: z.string().describe('Drop address'),
    distance: z.string().describe('Distance like 6.2 km'),
    eta: z.string().describe('ETA like 18 min'),
  }),
  component: ({ props }) => (
    <div
      className="rounded-[22px] p-[18px]"
      style={{
        backgroundColor: '#F2F6F2',
        border: '1px solid rgba(90, 139, 88, 0.25)',
      }}
    >
      <div className="flex items-start gap-3">
        <div className="flex flex-col items-center pt-[6px]">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: '#5A8B58' }}
          />
          <span
            className="my-1 h-6 w-px"
            style={{ backgroundColor: 'rgba(90, 139, 88, 0.4)' }}
          />
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: '#C86948' }}
          />
        </div>
        <div className="flex-1">
          <div>
            <p
              className="font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
              style={{ color: '#A8A29E' }}
            >
              Pickup
            </p>
            <p
              className="font-sans text-[15px] font-medium leading-[22.5px]"
              style={{ color: '#4A3A31' }}
            >
              {props.pickup}
            </p>
          </div>
          <div className="mt-3">
            <p
              className="font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
              style={{ color: '#A8A29E' }}
            >
              Drop
            </p>
            <p
              className="font-sans text-[15px] font-medium leading-[22.5px]"
              style={{ color: '#4A3A31' }}
            >
              {props.drop}
            </p>
          </div>
        </div>
      </div>
      <div
        className="mt-4 flex items-center justify-between pt-3"
        style={{ borderTop: '1px solid rgba(90, 139, 88, 0.25)' }}
      >
        <p
          className="font-sans text-[13px] font-normal leading-[19.5px]"
          style={{ color: '#78716C' }}
        >
          {props.distance}
        </p>
        <p
          className="font-sans text-[13px] font-medium leading-[19.5px]"
          style={{ color: '#3F613E' }}
        >
          ETA {props.eta}
        </p>
      </div>
    </div>
  ),
})

// ---------------------------------------------------------------------------
// CombinedQuote — merged bakery + porter total with Confirm
// ---------------------------------------------------------------------------

const CombinedQuote = defineComponent({
  name: 'CombinedQuote',
  description:
    'A combined order summary showing bakery cost + delivery cost + total with a Confirm button',
  props: z.object({
    cakeSummary: z.string().describe('Cake order summary'),
    cakePrice: z.string().describe('Cake price like ₹1500'),
    deliveryFee: z.string().describe('Delivery fee like ₹80'),
    total: z.string().describe('Combined total like ₹1580'),
    readyBy: z.string().describe('When ready/delivered'),
  }),
  component: function CombinedQuoteView({ props }) {
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
          className="font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
          style={{ color: '#AC5A3E' }}
        >
          Combined Order
        </p>
        <p
          className="mt-2 font-sans text-[15px] font-medium leading-[22.5px]"
          style={{ color: '#4A3A31' }}
        >
          {props.cakeSummary}
        </p>

        <div className="mt-4 space-y-1">
          <div className="flex items-center justify-between">
            <p
              className="font-sans text-[13px] font-normal leading-[19.5px]"
              style={{ color: '#78716C' }}
            >
              Sunny Bakery
            </p>
            <p
              className="font-sans text-[13px] font-medium leading-[19.5px]"
              style={{ color: '#4A3A31' }}
            >
              {props.cakePrice}
            </p>
          </div>
          <div className="flex items-center justify-between">
            <p
              className="font-sans text-[13px] font-normal leading-[19.5px]"
              style={{ color: '#78716C' }}
            >
              Porter delivery
            </p>
            <p
              className="font-sans text-[13px] font-medium leading-[19.5px]"
              style={{ color: '#4A3A31' }}
            >
              {props.deliveryFee}
            </p>
          </div>
        </div>

        <div
          className="mt-4 flex items-center justify-between pt-3"
          style={{ borderTop: '1px solid rgba(172, 90, 62, 0.2)' }}
        >
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
              Arrives {props.readyBy}
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
              onClick={() => triggerAction('Confirm combined order')}
              className="rounded-full px-4 py-[10px] font-sans text-[14px] font-medium leading-[20px] transition-opacity hover:opacity-90"
              style={{ backgroundColor: '#C86948', color: '#FFFFFF' }}
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
// DeliveryConfirmed — success card after Porter confirms pickup
// ---------------------------------------------------------------------------

const DeliveryConfirmed = defineComponent({
  name: 'DeliveryConfirmed',
  description: 'Delivery confirmation card with tracking ID and driver details',
  props: z.object({
    trackingId: z.string().describe('Tracking ID like PTR-9231'),
    driver: z.string().describe('Driver name'),
    vehicle: z.string().describe('Vehicle / plate'),
    eta: z.string().describe('Delivery ETA'),
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
        <span className="text-xl">🛵</span>
        <p
          className="font-sans text-[15px] font-medium leading-[22.5px]"
          style={{ color: '#3F613E' }}
        >
          Delivery Scheduled
        </p>
      </div>
      <p
        className="font-sans text-[13px] font-normal leading-[19.5px]"
        style={{ color: '#78716C' }}
      >
        Tracking #{props.trackingId}
      </p>
      <p
        className="mt-2 font-sans text-[15px] font-medium leading-[22.5px]"
        style={{ color: '#4A3A31' }}
      >
        {props.driver} • {props.vehicle}
      </p>
      <div
        className="mt-4 flex items-center justify-between pt-4"
        style={{ borderTop: '1px solid rgba(90, 139, 88, 0.3)' }}
      >
        <p
          className="font-sans text-[13px] font-normal leading-[19.5px]"
          style={{ color: '#78716C' }}
        >
          Arrives
        </p>
        <p
          className="font-sans text-[15px] font-medium leading-[22.5px]"
          style={{ color: '#3F613E' }}
        >
          {props.eta}
        </p>
      </div>
    </div>
  ),
})

// ---------------------------------------------------------------------------
// Stack layout — vertical stack
// ---------------------------------------------------------------------------

const Stack = defineComponent({
  name: 'Stack',
  description: 'A vertical stack layout',
  props: z.object({
    children: z.array(z.any()).describe('Content to stack vertically'),
  }),
  component: ({ props, renderNode }) => (
    <div className="flex flex-col gap-3">{renderNode(props.children)}</div>
  ),
})

// ---------------------------------------------------------------------------
// OptionGrid — reuse for DeliverySlot grids
// ---------------------------------------------------------------------------

const OptionGrid = defineComponent({
  name: 'OptionGrid',
  description: 'A vertical stack for delivery slot options',
  props: z.object({
    children: z.array(z.any()).describe('Option cards'),
  }),
  component: ({ props, renderNode }) => (
    <div className="flex flex-col gap-2">{renderNode(props.children)}</div>
  ),
})

// ---------------------------------------------------------------------------
// Library export
// ---------------------------------------------------------------------------

export const porterLibrary = createLibrary({
  components: [
    PorterMessage,
    DeliverySlot,
    RoutePreview,
    CombinedQuote,
    DeliveryConfirmed,
    Stack,
    OptionGrid,
  ],
  root: 'Stack',
})

export const porterPromptAddendum = porterLibrary.prompt({
  preamble:
    'You are Porter, an on-demand delivery platform. You quote and schedule pickups from partner merchants (like Sunny Bakery) to customer addresses. Be precise and operational — you are logistics, not hospitality.',
  additionalRules: [
    'Always wrap your response in a Stack',
    'Start with a PorterMessage for your text explanation (1 short sentence)',
    'When showing the route, use RoutePreview with pickup and drop addresses',
    'When offering time slots, use OptionGrid with DeliverySlot cards',
    'When giving the combined bakery + delivery quote, use CombinedQuote',
    'When confirming the delivery booking, use DeliveryConfirmed',
    'Keep messages SHORT',
    'Use realistic driver names (Rahul S., Priya K., Amit J.) and vehicles (Bike, Mini-truck)',
    'Use Indian rupee format (₹80, ₹1500) for fees',
  ],
  examples: [
    `root = Stack([msg, route, grid])
msg = PorterMessage("Here are available delivery slots from Sunny Bakery:")
route = RoutePreview("Sunny Bakery, Linking Rd", "Bandra West", "6.2 km", "18 min")
grid = OptionGrid([s1, s2, s3])
s1 = DeliverySlot("2:30pm - 2:45pm", "Rahul S.", "Bike", "₹80")
s2 = DeliverySlot("3:00pm - 3:15pm", "Priya K.", "Bike", "₹80")
s3 = DeliverySlot("3:30pm - 3:45pm", "Amit J.", "Mini-truck", "₹120")`,

    `root = Stack([quote])
quote = CombinedQuote("Medium Chocolate Cake with Happy Birthday message", "₹1500", "₹80", "₹1580", "2:45pm tomorrow")`,

    `root = Stack([confirmed])
confirmed = DeliveryConfirmed("PTR-9231", "Rahul S.", "Bike MH-02-FG-4821", "2:45pm tomorrow")`,
  ],
})
