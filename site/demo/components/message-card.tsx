'use client'

import { useState } from 'react'
import { HugeiconsIcon } from '@hugeicons/react'
import { ArrowDownIcon, ArrowUpIcon } from '@hugeicons/core-free-icons'
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from '@/lib/collapsible'
import type {
  BodyType,
  TrustTier,
  DemoMessage,
  DemoStreamEvent,
  StreamEventType,
} from '../scenarios/types'

// ---------------------------------------------------------------------------
// Color maps
// ---------------------------------------------------------------------------

const BODY_TYPE_COLORS: Record<BodyType, { bg: string; text: string }> = {
  'task.create':      { bg: 'bg-blue-500/20',   text: 'text-blue-400' },
  'task.delegate':    { bg: 'bg-purple-500/20',  text: 'text-purple-400' },
  'task.progress':    { bg: 'bg-amber-500/20',   text: 'text-amber-400' },
  'task.complete':    { bg: 'bg-green-500/20',   text: 'text-green-400' },
  'task.error':       { bg: 'bg-red-500/20',     text: 'text-red-400' },
  'task.acknowledge': { bg: 'bg-cyan-500/20',    text: 'text-cyan-400' },
  'message':          { bg: 'bg-gray-500/20',    text: 'text-gray-400' },
  'session.init':         { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  'session.established':  { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  'com.example.demo.voice_utterance': { bg: 'bg-teal-500/20', text: 'text-teal-400' },
}

const TRUST_TIER_COLORS: Record<TrustTier, { bg: string; text: string }> = {
  internal: { bg: 'bg-green-500/20',  text: 'text-green-400' },
  owner:    { bg: 'bg-blue-500/20',   text: 'text-blue-400' },
  verified: { bg: 'bg-amber-500/20',  text: 'text-amber-400' },
  external: { bg: 'bg-red-500/20',    text: 'text-red-400' },
}

const STREAM_EVENT_COLORS: Record<StreamEventType, { bg: string; text: string }> = {
  thinking:    { bg: 'bg-purple-500/20',  text: 'text-purple-400' },
  tool_call:   { bg: 'bg-blue-500/20',    text: 'text-blue-400' },
  tool_result: { bg: 'bg-cyan-500/20',    text: 'text-cyan-400' },
  text_delta:  { bg: 'bg-gray-500/20',    text: 'text-gray-400' },
  done:        { bg: 'bg-green-500/20',   text: 'text-green-400' },
  heartbeat:   { bg: 'bg-amber-500/20',   text: 'text-amber-400' },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip agent:// prefix and .example.com suffix for display. */
function shortenAgent(agent: string): string {
  return agent
    .replace(/^agent:\/\//, '')
    .replace(/\.example\.com$/, '')
}

/** Format a timestamp (ms) as human-friendly duration. */
function formatTimestamp(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

/** Truncate a string to maxLen characters. */
function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str
  return str.slice(0, maxLen) + '...'
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function Badge({ label, bg, text }: { label: string; bg: string; text: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${bg} ${text}`}
    >
      {label}
    </span>
  )
}

function StreamEventRow({ event }: { event: DemoStreamEvent }) {
  const colors = STREAM_EVENT_COLORS[event.type]
  const preview = truncate(JSON.stringify(event.data), 80)

  return (
    <div className="flex items-start gap-2 py-1">
      <Badge label={event.type} bg={colors.bg} text={colors.text} />
      <span className="flex-1 truncate font-mono text-xs text-white/50">
        {preview}
      </span>
      <span className="shrink-0 font-mono text-xs text-white/30">
        {formatTimestamp(event.timestamp)}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// MessageCard
// ---------------------------------------------------------------------------

export interface MessageCardProps {
  message: DemoMessage
  streamEvents?: DemoStreamEvent[]
  isSelected: boolean
  onSelect: (id: string) => void
}

export function MessageCard({
  message,
  streamEvents,
  isSelected,
  onSelect,
}: MessageCardProps) {
  const [expanded, setExpanded] = useState(false)

  const bodyColors = BODY_TYPE_COLORS[message.bodyType]
  const trustColors = TRUST_TIER_COLORS[message.trustTier]

  const sender = shortenAgent(message.sender)
  const recipient = shortenAgent(message.recipient)

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(message.id)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect(message.id)
        }
      }}
      className={[
        'rounded-lg border p-4 transition-colors',
        'bg-white/[0.02] hover:bg-white/[0.04]',
        isSelected
          ? 'border-blue-500/60 ring-1 ring-blue-500/30'
          : 'border-white/10',
        'cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/50',
      ].join(' ')}
    >
      {/* ── Header row: badges + timestamp ──────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <Badge label={message.bodyType} bg={bodyColors.bg} text={bodyColors.text} />
        <Badge label={message.trustTier} bg={trustColors.bg} text={trustColors.text} />
        <span className="ml-auto shrink-0 font-mono text-xs text-white/40">
          {formatTimestamp(message.timestamp)}
        </span>
      </div>

      {/* ── Sender → Recipient ──────────────────────────────────────── */}
      <p className="mt-2 text-sm text-white/70">
        <span className="font-medium text-white/90">{sender}</span>
        <span className="mx-1 text-white/30">{'\u2192'}</span>
        <span className="font-medium text-white/90">{recipient}</span>
      </p>

      {/* ── Summary ─────────────────────────────────────────────────── */}
      <p className="mt-1 text-sm text-white/50">{message.summary}</p>

      {/* ── Stream events ───────────────────────────────────────────── */}
      {streamEvents && streamEvents.length > 0 && (
        <div className="mt-3 space-y-0.5 border-t border-white/5 pt-2">
          <p className="mb-1 text-xs font-medium uppercase tracking-wider text-white/30">
            Stream Events
          </p>
          {streamEvents.map((evt, idx) => (
            <StreamEventRow key={`${evt.type}-${evt.timestamp}-${idx}`} event={evt} />
          ))}
        </div>
      )}

      {/* ── Expand / Collapse — full JSON envelope ──────────────────── */}
      <Collapsible open={expanded} onOpenChange={setExpanded}>
        <CollapsibleTrigger asChild>
          <button
            type="button"
            onClick={(e) => e.stopPropagation()}
            className={[
              'mt-3 flex w-full items-center gap-1 rounded-md px-2 py-1 text-xs font-medium',
              'text-white/40 hover:bg-white/[0.04] hover:text-white/60',
              'transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/50',
            ].join(' ')}
          >
            <HugeiconsIcon
              icon={expanded ? ArrowUpIcon : ArrowDownIcon}
              size={14}
              strokeWidth={2}
            />
            {expanded ? 'Hide' : 'Show'} JSON Envelope
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-black/40 p-3 font-mono text-xs text-white/60">
            {JSON.stringify(message, null, 2)}
          </pre>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}
