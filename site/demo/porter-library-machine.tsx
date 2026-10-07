'use client'

/**
 * Machine-view twin of porter-library.tsx.
 *
 * Same component names and prop shapes — different visual skin
 * (dark Space Mono ticket-stub).
 */

import { defineComponent, createLibrary, useTriggerAction } from '@openuidev/react-lang'
import { z } from 'zod'

const MACHINE_BG_DEEP = '#1A1A1A'
const MACHINE_TEXT = '#E8E4DC'
const MACHINE_MUTED = 'rgba(232, 228, 220, 0.55)'
const MACHINE_FAINT = 'rgba(232, 228, 220, 0.25)'
const MACHINE_BORDER = 'rgba(232, 228, 220, 0.15)'
const ACCENT = '#C86948'

const monoFont = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"
const TEXTURE = 'L'.repeat(120)

function LabelValueGrid({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '80px 18px 1fr',
        rowGap: '6px',
        fontFamily: monoFont,
        fontSize: '11px',
        lineHeight: '1.3',
        letterSpacing: '0.04em',
      }}
    >
      {rows.map(([label, value], i) => (
        <div key={i} style={{ display: 'contents' }}>
          <div
            style={{
              gridColumn: 1,
              color: MACHINE_MUTED,
              textTransform: 'uppercase',
            }}
          >
            {label}
          </div>
          <div style={{ gridColumn: 2, color: MACHINE_FAINT }}>&gt;</div>
          <div
            style={{
              gridColumn: 3,
              color: MACHINE_TEXT,
              textTransform: 'uppercase',
            }}
          >
            {value}
          </div>
        </div>
      ))}
    </div>
  )
}

function TextureDivider() {
  return (
    <div
      style={{
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        lineHeight: 1,
        letterSpacing: '1px',
        opacity: 0.18,
        fontSize: '10px',
        fontFamily: monoFont,
        color: MACHINE_TEXT,
        margin: '10px 0',
      }}
    >
      {TEXTURE}
    </div>
  )
}

// ---------------------------------------------------------------------------

const PorterMessage = defineComponent({
  name: 'PorterMessage',
  description: 'Text from Porter',
  props: z.object({
    text: z.string(),
  }),
  component: ({ props }) => (
    <p
      style={{
        fontFamily: monoFont,
        color: MACHINE_TEXT,
        fontSize: '12px',
        lineHeight: '1.5',
        letterSpacing: '0.02em',
      }}
    >
      <span style={{ opacity: 0.55 }}>&gt;&nbsp;</span>
      {props.text}
    </p>
  ),
})

// ---------------------------------------------------------------------------

const DeliverySlot = defineComponent({
  name: 'DeliverySlot',
  description: 'Selectable slot row',
  props: z.object({
    window: z.string(),
    driver: z.string(),
    vehicle: z.string(),
    fee: z.string(),
  }),
  component: function DeliverySlotView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <button
        type="button"
        onClick={() => triggerAction(props.window)}
        style={{
          display: 'block',
          width: '100%',
          textAlign: 'left',
          padding: '10px 14px',
          backgroundColor: MACHINE_BG_DEEP,
          border: `1px solid ${MACHINE_BORDER}`,
          borderRadius: '4px',
          cursor: 'pointer',
          fontFamily: monoFont,
          color: MACHINE_TEXT,
        }}
      >
        <LabelValueGrid
          rows={[
            ['SLOT', props.window],
            ['DRIVER', props.driver],
            ['VEHICLE', props.vehicle],
            ['FEE', props.fee],
          ]}
        />
      </button>
    )
  },
})

// ---------------------------------------------------------------------------

const RoutePreview = defineComponent({
  name: 'RoutePreview',
  description: 'Route summary ticket',
  props: z.object({
    pickup: z.string(),
    drop: z.string(),
    distance: z.string(),
    eta: z.string(),
  }),
  component: ({ props }) => (
    <div
      style={{
        padding: '12px 14px',
        backgroundColor: MACHINE_BG_DEEP,
        border: `1px solid ${MACHINE_BORDER}`,
        borderRadius: '4px',
        fontFamily: monoFont,
      }}
    >
      <div
        style={{
          fontSize: '10px',
          letterSpacing: '0.18em',
          color: ACCENT,
          textTransform: 'uppercase',
          marginBottom: '8px',
        }}
      >
        ROUTE
      </div>
      <LabelValueGrid
        rows={[
          ['PICKUP', props.pickup],
          ['DROP', props.drop],
          ['DIST', props.distance],
          ['ETA', props.eta],
        ]}
      />
    </div>
  ),
})

// ---------------------------------------------------------------------------

const CombinedQuote = defineComponent({
  name: 'CombinedQuote',
  description: 'Merged bakery+porter quote',
  props: z.object({
    cakeSummary: z.string(),
    cakePrice: z.string(),
    deliveryFee: z.string(),
    total: z.string(),
    readyBy: z.string(),
  }),
  component: function CombinedQuoteView({ props }) {
    const triggerAction = useTriggerAction()
    return (
      <div
        style={{
          padding: '14px',
          backgroundColor: MACHINE_BG_DEEP,
          border: `1px solid ${MACHINE_BORDER}`,
          borderRadius: '4px',
          fontFamily: monoFont,
        }}
      >
        <div
          style={{
            fontSize: '10px',
            letterSpacing: '0.18em',
            color: ACCENT,
            textTransform: 'uppercase',
            marginBottom: '8px',
          }}
        >
          QUOTE&nbsp;//&nbsp;COMBINED
        </div>
        <LabelValueGrid
          rows={[
            ['ORDER', props.cakeSummary],
            ['BAKERY', props.cakePrice],
            ['PORTER', props.deliveryFee],
            ['TOTAL', props.total],
            ['ARRIVE', props.readyBy],
          ]}
        />
        <TextureDivider />
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={() => triggerAction('Change order')}
            style={{
              flex: 1,
              padding: '8px 10px',
              background: 'transparent',
              color: MACHINE_TEXT,
              border: `1px solid ${MACHINE_BORDER}`,
              borderRadius: '3px',
              cursor: 'pointer',
              fontFamily: monoFont,
              fontSize: '10px',
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
            }}
          >
            [ CHANGE ]
          </button>
          <button
            type="button"
            onClick={() => triggerAction('Confirm combined order')}
            style={{
              flex: 1,
              padding: '8px 10px',
              background: ACCENT,
              color: '#121212',
              border: `1px solid ${ACCENT}`,
              borderRadius: '3px',
              cursor: 'pointer',
              fontFamily: monoFont,
              fontSize: '10px',
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              fontWeight: 700,
            }}
          >
            [ CONFIRM ]
          </button>
        </div>
      </div>
    )
  },
})

// ---------------------------------------------------------------------------

const DeliveryConfirmed = defineComponent({
  name: 'DeliveryConfirmed',
  description: 'Confirmation ticket',
  props: z.object({
    trackingId: z.string(),
    driver: z.string(),
    vehicle: z.string(),
    eta: z.string(),
  }),
  component: ({ props }) => (
    <div
      style={{
        padding: '14px',
        backgroundColor: MACHINE_BG_DEEP,
        border: `1px solid ${MACHINE_BORDER}`,
        borderRadius: '4px',
        fontFamily: monoFont,
      }}
    >
      <div
        style={{
          fontSize: '10px',
          letterSpacing: '0.18em',
          color: '#8BB58A',
          textTransform: 'uppercase',
          marginBottom: '8px',
        }}
      >
        STATUS&nbsp;//&nbsp;SCHEDULED
      </div>
      <LabelValueGrid
        rows={[
          ['TRACK#', props.trackingId],
          ['DRIVER', props.driver],
          ['VEHICLE', props.vehicle],
          ['ETA', props.eta],
        ]}
      />
    </div>
  ),
})

// ---------------------------------------------------------------------------

const Stack = defineComponent({
  name: 'Stack',
  description: 'Vertical stack',
  props: z.object({
    children: z.array(z.any()),
  }),
  component: ({ props, renderNode }) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {renderNode(props.children)}
    </div>
  ),
})

const OptionGrid = defineComponent({
  name: 'OptionGrid',
  description: 'Vertical list of rows',
  props: z.object({
    children: z.array(z.any()),
  }),
  component: ({ props, renderNode }) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {renderNode(props.children)}
    </div>
  ),
})

export const porterLibraryMachine = createLibrary({
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
