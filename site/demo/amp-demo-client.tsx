'use client'

import type { CSSProperties, Dispatch, RefObject } from 'react'
import { useReducer, useRef, useCallback, useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { HugeiconsIcon } from '@hugeicons/react'
import {
  SentIcon,
  CheckmarkCircleIcon,
  Loading03Icon,
  CircleIcon,
  ArrowDown01Icon,
  ArrowUp01Icon,
  CalendarIcon,
  CheckListIcon,
  MicIcon,
  MicOffIcon,
  CancelIcon,
} from '@hugeicons/core-free-icons'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/lib/collapsible'
import { Renderer } from '@openuidev/react-lang'
import { motion, AnimatePresence } from 'framer-motion'
import { MeshGradient } from '@paper-design/shaders-react'
import { ProtocolEnvelope } from './components/protocol-envelope'
import { DIRECTORY_QUERY, DIRECTORY_RESPONSE } from './body-types'
import { bakeryLibrary } from './bakery-library'
import { porterLibrary } from './porter-library'
import { bakeryLibraryMachine } from './bakery-library-machine'
import { porterLibraryMachine } from './porter-library-machine'
import { useAmpTheme, type AmpTheme } from './theme'
import { TicketVisual } from './components/ticket-visual'
import { cn } from '@/lib/cn'

/** Client-side mirrors of the server limits (see lib/limits.ts). */
const MAX_MESSAGE_CHARS = 1000
const MAX_HISTORY_SENT = 30
const MAX_RECORDING_MS = 30_000

const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"

function bakeryLibFor(theme: AmpTheme) {
  return theme === 'machine' ? bakeryLibraryMachine : bakeryLibrary
}
function porterLibFor(theme: AmpTheme) {
  return theme === 'machine' ? porterLibraryMachine : porterLibrary
}

/**
 * Abbreviate an agent URL for display so the full routable identity
 * doesn't sit on screen for screencasts / shoulder-surfers.
 *   agent://you@example.com -> you@…
 *   agent://sunny-bakery.example -> sunny…
 */
function abbreviateAddress(url: string): string {
  const stripped = url.replace(/^agent:\/\//, '')
  const at = stripped.indexOf('@')
  if (at > 0) return `${stripped.slice(0, at)}@…`
  const head = stripped.split('.')[0] ?? stripped
  return `${head.slice(0, 8)}…`
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AgentId = 'your-agent' | 'bakery' | 'porter'

interface ThinkingStep {
  label: string
  status: 'complete' | 'active' | 'pending'
}

interface AgentEntry {
  id: number
  type: 'chat' | 'thinking' | 'status'
  agent: AgentId
  text: string
  role?: 'user' | 'agent' | 'remote'
  steps?: ThinkingStep[]
  isStreaming?: boolean
  timestamp: number
}

interface Envelope {
  data: Record<string, unknown>
  timestamp: number
}

interface ConversationEntry {
  role: 'user' | 'bakery'
  content: string
}

/**
 * A line spoken aloud during a voice call. Drives the rolling transcript
 * in voice mode AND surfaces in the Chat tab as a "spoken" bubble so
 * all three surfaces (chat / protocol / voice) stay in sync.
 */
interface SpokenLine {
  id: number
  speaker: 'your-agent' | 'bakery' | 'porter'
  text: string
}

/**
 * A pending hand-off from the autonomous loop back to the user. Either
 * a structured option pick (chips) or an open-ended text reply. Only one
 * is pending at a time; tapping a chip or sending a reply clears it.
 */
interface PendingDecision {
  id: string
  question: string
  options?: string[]
  brief: string
  history: Array<{ role: string; content: string }>
}

interface State {
  input: string
  isStreaming: boolean
  yourAgentEntries: AgentEntry[]
  bakeryEntries: AgentEntry[]
  porterEntries: AgentEntry[]
  porterActive: boolean
  /** Which agent is currently awaiting a user reply. Drives message routing. */
  awaitingAgent: 'bakery' | 'porter' | null
  envelopes: Envelope[]
  error: string | null
  conversationHistory: ConversationEntry[]
  turnCount: number
  pendingOptions: string[]
  /** Voice-clip transcript log shared across all three surfaces. */
  spokenLog: SpokenLine[]
  /** Hand-off from voice loop to user; one at a time. */
  pendingDecision: PendingDecision | null
}

type Action =
  | { type: 'SET_INPUT'; value: string }
  | { type: 'START_TURN' }
  | { type: 'ADD_ENTRY'; entry: AgentEntry }
  | { type: 'ADD_THINKING_STEP'; agent: AgentId; label: string; status: ThinkingStep['status'] }
  | { type: 'COMPLETE_THINKING'; agent: AgentId }
  | { type: 'APPEND_STREAM'; agent: AgentId; text: string }
  | { type: 'FINALIZE_STREAM' }
  | { type: 'ADD_ENVELOPE'; data: Record<string, unknown> }
  | { type: 'SET_ERROR'; error: string }
  | { type: 'DONE'; bakeryResponse?: string; userMessage?: string }
  | { type: 'SET_OPTIONS'; options: string[] }
  | { type: 'CLEAR_OPTIONS' }
  | { type: 'ACTIVATE_PORTER' }
  | { type: 'SET_AWAITING_AGENT'; agent: 'bakery' | 'porter' | null }
  | { type: 'APPEND_SPOKEN'; line: SpokenLine }
  | { type: 'SET_PENDING_DECISION'; decision: PendingDecision }
  | { type: 'CLEAR_PENDING_DECISION' }
  | { type: 'CLEAR_SPOKEN_LOG' }
  | { type: 'RESET_ALL' }

const initial: State = {
  input: '',
  isStreaming: false,
  yourAgentEntries: [],
  bakeryEntries: [],
  porterEntries: [],
  porterActive: false,
  awaitingAgent: null,
  envelopes: [],
  error: null,
  conversationHistory: [],
  turnCount: 0,
  pendingOptions: [],
  spokenLog: [],
  pendingDecision: null,
}

let entryId = 0
// Unique ID generator that is safe under React StrictMode double-invoke of
// reducers — uses a timestamp + random suffix so collisions are impossible
// even if the module-level counter is called multiple times per dispatch.
function nextEntryId(): number {
  entryId += 1
  return entryId * 1_000_000 + Math.floor(Math.random() * 1_000_000)
}

function getEntries(s: State, agent: AgentId): AgentEntry[] {
  if (agent === 'your-agent') return s.yourAgentEntries
  if (agent === 'porter') return s.porterEntries
  return s.bakeryEntries
}

function setEntries(s: State, agent: AgentId, entries: AgentEntry[]): State {
  if (agent === 'your-agent') return { ...s, yourAgentEntries: entries }
  if (agent === 'porter') return { ...s, porterEntries: entries }
  return { ...s, bakeryEntries: entries }
}

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case 'SET_INPUT':
      return { ...s, input: a.value }

    case 'START_TURN':
      return { ...s, isStreaming: true, error: null, input: '', pendingOptions: [] }

    case 'ADD_ENTRY': {
      const entries = [...getEntries(s, a.entry.agent), a.entry]
      return setEntries(s, a.entry.agent, entries)
    }

    case 'ADD_THINKING_STEP': {
      const entries = [...getEntries(s, a.agent)]
      // Find or create a thinking entry at the end
      let thinkingEntry = entries.length > 0 ? entries[entries.length - 1] : null
      if (!thinkingEntry || thinkingEntry.type !== 'thinking') {
        // Create a new thinking entry
        thinkingEntry = {
          id: nextEntryId(),
          type: 'thinking',
          agent: a.agent,
          text: a.agent === 'your-agent' ? 'Agent thinking...' : 'Processing...',
          steps: [],
          timestamp: Date.now(),
        }
        entries.push(thinkingEntry)
      }
      // Mark all previous active steps as complete
      const updatedSteps = (thinkingEntry.steps || []).map((step) =>
        step.status === 'active' ? { ...step, status: 'complete' as const } : step,
      )
      updatedSteps.push({ label: a.label, status: a.status })
      entries[entries.length - 1] = { ...thinkingEntry, steps: updatedSteps }
      return setEntries(s, a.agent, entries)
    }

    case 'COMPLETE_THINKING': {
      const entries = getEntries(s, a.agent).map((entry) => {
        if (entry.type === 'thinking' && entry.steps) {
          return {
            ...entry,
            steps: entry.steps.map((step) =>
              step.status === 'active' ? { ...step, status: 'complete' as const } : step,
            ),
          }
        }
        return entry
      })
      return setEntries(s, a.agent, entries)
    }

    case 'APPEND_STREAM': {
      const entries = [...getEntries(s, a.agent)]
      // Find the last streaming entry
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i]
        if (entry && entry.isStreaming && entry.type === 'chat') {
          entries[i] = { ...entry, text: entry.text + a.text }
          return setEntries(s, a.agent, entries)
        }
      }
      // Create a new streaming chat entry
      entries.push({
        id: nextEntryId(),
        type: 'chat',
        agent: a.agent,
        text: a.text,
        role: 'agent',
        isStreaming: true,
        timestamp: Date.now(),
      })
      return setEntries(s, a.agent, entries)
    }

    case 'FINALIZE_STREAM': {
      const finalizeEntries = (entries: AgentEntry[]) =>
        entries.map((e) => (e.isStreaming ? { ...e, isStreaming: false } : e))
      return {
        ...s,
        yourAgentEntries: finalizeEntries(s.yourAgentEntries),
        bakeryEntries: finalizeEntries(s.bakeryEntries),
        porterEntries: finalizeEntries(s.porterEntries),
      }
    }

    case 'ADD_ENVELOPE':
      return {
        ...s,
        envelopes: [...s.envelopes, { data: a.data, timestamp: Date.now() }],
      }

    case 'SET_ERROR':
      return { ...s, error: a.error, isStreaming: false }

    case 'DONE': {
      const newHistory = [...s.conversationHistory]
      if (a.userMessage) {
        newHistory.push({ role: 'user', content: a.userMessage })
      }
      if (a.bakeryResponse) {
        newHistory.push({ role: 'bakery', content: a.bakeryResponse })
      }
      const finalizeEntries = (entries: AgentEntry[]) =>
        entries.map((e) => (e.isStreaming ? { ...e, isStreaming: false } : e))
      return {
        ...s,
        isStreaming: false,
        yourAgentEntries: finalizeEntries(s.yourAgentEntries),
        bakeryEntries: finalizeEntries(s.bakeryEntries),
        porterEntries: finalizeEntries(s.porterEntries),
        conversationHistory: newHistory,
        turnCount: s.turnCount + 1,
      }
    }

    case 'SET_OPTIONS':
      return { ...s, pendingOptions: a.options }

    case 'ACTIVATE_PORTER':
      return { ...s, porterActive: true }

    case 'SET_AWAITING_AGENT':
      return { ...s, awaitingAgent: a.agent }

    case 'CLEAR_OPTIONS':
      return { ...s, pendingOptions: [] }

    case 'APPEND_SPOKEN':
      return { ...s, spokenLog: [...s.spokenLog, a.line].slice(-50) }

    case 'SET_PENDING_DECISION':
      return { ...s, pendingDecision: a.decision }

    case 'CLEAR_PENDING_DECISION':
      return { ...s, pendingDecision: null }

    case 'CLEAR_SPOKEN_LOG':
      return { ...s, spokenLog: [] }

    case 'RESET_ALL':
      return { ...initial }

    default:
      return s
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mkEntry(
  agent: AgentId,
  type: AgentEntry['type'],
  text: string,
  opts?: Partial<AgentEntry>,
): AgentEntry {
  return {
    id: nextEntryId(),
    type,
    agent,
    text,
    timestamp: Date.now(),
    ...opts,
  }
}

// ---------------------------------------------------------------------------
// Thinking Block (Chain of Thought)
// ---------------------------------------------------------------------------

function ThinkingBlock({ entry }: { entry: AgentEntry }) {
  const [isOpen, setIsOpen] = useState(true)
  const { theme } = useAmpTheme()
  const steps = entry.steps || []
  const allComplete = steps.every((s) => s.status === 'complete')

  const sectionLabel =
    entry.agent === 'your-agent'
      ? 'MY AGENT'
      : entry.agent === 'porter'
        ? 'PORTER'
        : 'BAKERY'
  const countLabel = allComplete
    ? `${steps.length} DONE`
    : `${steps.filter((s) => s.status === 'complete').length}/${steps.length}`

  const headerIcon = entry.agent === 'your-agent' ? CheckListIcon : CalendarIcon

  if (theme === 'machine') {
    const borderColor = 'rgba(232, 228, 220, 0.15)'
    const mutedText = 'rgba(232, 228, 220, 0.55)'
    const textColor = '#E8E4DC'
    return (
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <div className="mx-5 my-2" style={{ borderTop: `1px solid ${borderColor}` }} />
        <CollapsibleTrigger
          className="flex w-full items-center gap-2 px-5 py-[10px]"
          style={{ fontFamily: MONO }}
        >
          <span
            style={{
              fontSize: '10px',
              letterSpacing: '0.18em',
              color: mutedText,
              textTransform: 'uppercase',
            }}
          >
            {sectionLabel}&nbsp;//&nbsp;TRACE
          </span>
          <span
            style={{
              fontSize: '10px',
              letterSpacing: '0.12em',
              color: allComplete ? '#8BB58A' : '#C86948',
              padding: '2px 8px',
              border: `1px solid ${allComplete ? 'rgba(139,181,138,0.35)' : 'rgba(200,105,72,0.45)'}`,
              borderRadius: '3px',
              textTransform: 'uppercase',
            }}
          >
            {countLabel}
          </span>
          <span className="flex-1" />
          <span
            style={{
              fontSize: '10px',
              letterSpacing: '0.12em',
              color: '#C86948',
              textTransform: 'uppercase',
            }}
          >
            [ {isOpen ? 'HIDE' : 'SHOW'} ]
          </span>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div
            className="pb-2"
            style={{
              fontFamily: MONO,
              display: 'grid',
              gridTemplateColumns: '28px 70px 18px 1fr',
              rowGap: '4px',
              padding: '0 20px',
            }}
          >
            {steps.map((step, i) => {
              const tag =
                step.status === 'complete'
                  ? 'OK'
                  : step.status === 'active'
                    ? '..'
                    : '--'
              const tagColor =
                step.status === 'complete'
                  ? '#8BB58A'
                  : step.status === 'active'
                    ? '#C86948'
                    : mutedText
              return (
                <div key={i} style={{ display: 'contents' }}>
                  <div
                    style={{
                      gridColumn: 1,
                      fontSize: '10px',
                      letterSpacing: '0.08em',
                      color: mutedText,
                      textTransform: 'uppercase',
                    }}
                  >
                    {String(i + 1).padStart(2, '0')}
                  </div>
                  <div
                    style={{
                      gridColumn: 2,
                      fontSize: '10px',
                      letterSpacing: '0.12em',
                      color: tagColor,
                      textTransform: 'uppercase',
                    }}
                  >
                    [{tag}]
                  </div>
                  <div style={{ gridColumn: 3, color: 'rgba(232,228,220,0.25)' }}>&gt;</div>
                  <div
                    style={{
                      gridColumn: 4,
                      fontSize: '11px',
                      color: step.status === 'pending' ? mutedText : textColor,
                      letterSpacing: '0.02em',
                    }}
                  >
                    {step.label}
                  </div>
                </div>
              )
            })}
          </div>
        </CollapsibleContent>
      </Collapsible>
    )
  }

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div
        className="mx-5 my-2"
        style={{ borderTop: '1px solid rgba(231, 229, 228, 0.6)' }}
      />
      <CollapsibleTrigger className="flex w-full items-center gap-2 px-5 py-[10px] transition-colors">
        <HugeiconsIcon
          icon={headerIcon}
          size={14}
          className="shrink-0"
          style={{ color: '#A8A29E' }}
          strokeWidth={2}
        />
        <span
          className="font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
          style={{ color: '#78716C' }}
        >
          {sectionLabel}
        </span>
        <span
          className="rounded-full px-[10px] py-[2px] font-sans text-[11px] font-semibold uppercase leading-[16px] tracking-[0.04em]"
          style={{
            backgroundColor: allComplete ? '#F2F6F2' : '#FCE2D8',
            color: allComplete ? '#3F613E' : '#AC5A3E',
          }}
        >
          {countLabel}
        </span>
        <span className="flex-1" />
        <span
          className="font-sans text-[13px] font-normal leading-[19.5px]"
          style={{ color: '#C86948' }}
        >
          + Log
        </span>
        <HugeiconsIcon
          icon={isOpen ? ArrowUp01Icon : ArrowDown01Icon}
          size={12}
          className="shrink-0 opacity-40"
        />
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-[2px] pb-2">
          {steps.map((step, i) => {
            const pillLabel =
              step.status === 'complete'
                ? 'Done'
                : step.status === 'active'
                  ? 'Now'
                  : 'Next'
            const pillStyle: CSSProperties =
              step.status === 'complete'
                ? { backgroundColor: '#F2F6F2', color: '#3F613E' }
                : step.status === 'active'
                  ? { backgroundColor: '#FCE2D8', color: '#AC5A3E' }
                  : { backgroundColor: '#F7F7F6', color: '#A8A29E' }
            return (
              <div key={i} className="flex items-center gap-3 px-5 py-2">
                {step.status === 'complete' && (
                  <HugeiconsIcon
                    icon={CheckmarkCircleIcon}
                    size={16}
                    className="shrink-0"
                    style={{ color: '#5A8B58' }}
                  />
                )}
                {step.status === 'active' && (
                  <HugeiconsIcon
                    icon={Loading03Icon}
                    size={16}
                    className="shrink-0 animate-spin"
                    style={{ color: '#C86948' }}
                  />
                )}
                {step.status === 'pending' && (
                  <HugeiconsIcon
                    icon={CircleIcon}
                    size={16}
                    className="shrink-0"
                    style={{ color: '#C7C5C4' }}
                  />
                )}
                <span
                  className={cn(
                    'flex-1 font-sans text-[15px] font-medium leading-[22.5px]',
                    step.status === 'complete' && 'line-through',
                  )}
                  style={{
                    color:
                      step.status === 'complete'
                        ? '#A8A29E'
                        : step.status === 'active'
                          ? '#4A3A31'
                          : '#C7C5C4',
                  }}
                >
                  {step.label}
                </span>
                <span
                  className="rounded-full px-[10px] py-[2px] font-sans text-[11px] font-medium leading-[16px]"
                  style={pillStyle}
                >
                  {pillLabel}
                </span>
              </div>
            )
          })}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

// ---------------------------------------------------------------------------
// Chat Bubble (simple, inline)
// ---------------------------------------------------------------------------

function ChatBubble({
  entry,
  onAction,
}: {
  entry: AgentEntry
  onAction?: (event: { action: string; formName?: string }) => void
}) {
  const { theme } = useAmpTheme()
  const isUser = entry.role === 'user'
  const isRemote = entry.role === 'remote'
  const isAgent = entry.role === 'agent'
  const isBakeryContent = isAgent || isRemote

  // Bakery / remote content
  if (isBakeryContent) {
    const isPorterMsg = entry.agent === 'porter'
    const isPorterForward =
      entry.agent === 'your-agent' &&
      /(?:DeliverySlot|RoutePreview|CombinedQuote|DeliveryConfirmed|PorterMessage)\(/.test(
        entry.text,
      )
    const labelText = isPorterMsg || isPorterForward
      ? 'PORTER'
      : isRemote
        ? 'SUNNY BAKERY'
        : 'MY AGENT'
    const isPorter = isPorterMsg || isPorterForward
    const library = isPorter ? porterLibFor(theme) : bakeryLibFor(theme)

    if (theme === 'machine') {
      return (
        <div className="px-4 py-2">
          <div
            style={{
              backgroundColor: '#2A2A2A',
              border: '1px solid rgba(232, 228, 220, 0.15)',
              borderRadius: '4px',
              padding: '12px 14px',
              fontFamily: MONO,
            }}
          >
            <p
              style={{
                marginBottom: '10px',
                fontSize: '10px',
                letterSpacing: '0.18em',
                color: 'rgba(232,228,220,0.55)',
                textTransform: 'uppercase',
              }}
            >
              RX&nbsp;//&nbsp;{labelText}
            </p>
            <Renderer
              response={entry.text}
              library={library}
              isStreaming={entry.isStreaming || false}
              onAction={(event) => {
                if (onAction) {
                  onAction({
                    action:
                      event.humanFriendlyMessage ||
                      String(event.params?.label ?? event.type ?? ''),
                    formName: event.formName,
                  })
                }
              }}
            />
          </div>
        </div>
      )
    }

    // User theme
    return (
      <div className="px-4 py-2">
        <div
          className="rounded-[22px] p-5"
          style={{
            backgroundColor: '#FCE2D8',
            border: '1px solid rgba(231, 229, 228, 0.6)',
          }}
        >
          <p
            className="mb-3 font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
            style={{ color: '#A8A29E' }}
          >
            {labelText}
          </p>
          <div style={{ color: '#4A3A31' }}>
            <Renderer
              response={entry.text}
              library={library}
              isStreaming={entry.isStreaming || false}
              onAction={(event) => {
                if (onAction) {
                  onAction({
                    action:
                      event.humanFriendlyMessage ||
                      String(event.params?.label ?? event.type ?? ''),
                    formName: event.formName,
                  })
                }
              }}
            />
          </div>
        </div>
      </div>
    )
  }

  // User message
  if (isUser) {
    if (theme === 'machine') {
      return (
        <div className="flex flex-col items-end px-4 py-2">
          <p
            style={{
              marginBottom: '4px',
              fontSize: '10px',
              letterSpacing: '0.18em',
              color: 'rgba(232,228,220,0.55)',
              textTransform: 'uppercase',
              fontFamily: MONO,
            }}
          >
            TX&nbsp;//&nbsp;YOU
          </p>
          <div
            style={{
              maxWidth: '85%',
              backgroundColor: '#C86948',
              color: '#121212',
              padding: '8px 12px',
              borderRadius: '4px',
              fontFamily: MONO,
              fontSize: '12px',
              lineHeight: '1.5',
              whiteSpace: 'pre-wrap',
            }}
          >
            {entry.text}
          </div>
        </div>
      )
    }

    return (
      <div className="flex flex-col items-end px-4 py-2">
        <p
          className="mb-1 font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
          style={{ color: '#A8A29E' }}
        >
          You
        </p>
        <div
          className="max-w-[85%] rounded-[18px] px-4 py-[10px]"
          style={{
            backgroundColor: '#C86948',
            color: '#FFFFFF',
          }}
        >
          <p className="whitespace-pre-wrap font-sans text-[15px] font-medium leading-[22.5px]">
            {entry.text}
          </p>
        </div>
      </div>
    )
  }

  // Fallback plain text
  if (theme === 'machine') {
    return (
      <div className="px-5 py-2">
        <p
          style={{
            fontFamily: MONO,
            color: '#E8E4DC',
            fontSize: '12px',
            lineHeight: '1.5',
            whiteSpace: 'pre-wrap',
          }}
        >
          {entry.text}
          {entry.isStreaming && (
            <span
              className="ml-0.5 inline-block h-3.5 w-0.5 animate-pulse"
              style={{ backgroundColor: '#C86948' }}
            />
          )}
        </p>
      </div>
    )
  }
  return (
    <div className="px-5 py-2">
      <p
        className="whitespace-pre-wrap font-sans text-[15px] font-medium leading-[22.5px]"
        style={{ color: '#4A3A31' }}
      >
        {entry.text}
        {entry.isStreaming && (
          <span
            className="ml-0.5 inline-block h-3.5 w-0.5 animate-pulse"
            style={{ backgroundColor: '#C86948' }}
          />
        )}
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Status Line
// ---------------------------------------------------------------------------

function StatusLine({ entry }: { entry: AgentEntry }) {
  const { theme } = useAmpTheme()
  if (theme === 'machine') {
    return (
      <div
        className="flex items-center gap-2 px-5 py-1"
        style={{ fontFamily: MONO }}
      >
        <span
          style={{
            fontSize: '10px',
            letterSpacing: '0.12em',
            color: '#C86948',
            textTransform: 'uppercase',
          }}
        >
          [..]
        </span>
        <span
          style={{
            fontSize: '11px',
            color: 'rgba(232,228,220,0.55)',
            letterSpacing: '0.02em',
          }}
        >
          {entry.text}
        </span>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-2 px-5 py-1">
      <span
        className="inline-block h-1 w-1 rounded-full"
        style={{ backgroundColor: '#D7937B' }}
      />
      <span
        className="font-sans text-[13px] font-normal italic leading-[19.5px]"
        style={{ color: '#A8A29E' }}
      >
        {entry.text}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Agent Window
// ---------------------------------------------------------------------------

function AgentWindow({
  address,
  entries,
  envelopes,
  agentId,
  onAction,
}: {
  title: string
  address: string
  entries: AgentEntry[]
  envelopes: Envelope[]
  agentId: AgentId
  onAction?: (event: { action: string; formName?: string }) => void
}) {
  const { theme } = useAmpTheme()
  const scrollRef = useRef<HTMLDivElement>(null)

  const relevantEnvelopes = envelopes.filter((env) => {
    const sender = ((env.data.sender as string) || '').toLowerCase()
    const recipient = ((env.data.recipient as string) || '').toLowerCase()
    if (agentId === 'your-agent') {
      return (
        sender.includes('you@example.com') ||
        sender.includes('you@') ||
        recipient.includes('you@example.com') ||
        recipient.includes('you@')
      )
    }
    if (agentId === 'porter') {
      return sender.includes('porter') || recipient.includes('porter')
    }
    return (
      sender.includes('bakery') ||
      sender.includes('sunny') ||
      recipient.includes('bakery') ||
      recipient.includes('sunny')
    )
  })

  const lastEntryText = entries[entries.length - 1]?.text
  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: 'smooth',
    })
  }, [entries.length, lastEntryText, theme])

  const labelText =
    agentId === 'your-agent'
      ? 'MY AGENT'
      : agentId === 'porter'
        ? 'PORTER'
        : 'SUNNY BAKERY'

  const isMachine = theme === 'machine'

  // ---- Shared content renderers ----
  const emptyChatMsg =
    agentId === 'your-agent'
      ? 'Send a message to begin'
      : agentId === 'porter'
        ? 'Waiting for delivery request…'
        : 'Waiting for incoming task…'

  const chatContent =
    entries.length === 0 ? (
      <div className="flex flex-col items-center justify-center px-5 py-16 text-center">
        <p
          style={
            isMachine
              ? {
                  fontFamily: MONO,
                  fontSize: '11px',
                  letterSpacing: '0.08em',
                  color: 'rgba(232,228,220,0.55)',
                  textTransform: 'uppercase',
                }
              : undefined
          }
          className={
            isMachine
              ? ''
              : 'font-sans text-[13px] font-normal leading-[19.5px]'
          }
        >
          {isMachine ? `> ${emptyChatMsg}` : emptyChatMsg}
        </p>
      </div>
    ) : (
      <div className="py-2">
        {entries.map((entry) => {
          if (entry.type === 'thinking')
            return <ThinkingBlock key={entry.id} entry={entry} />
          if (entry.type === 'status')
            return <StatusLine key={entry.id} entry={entry} />
          return <ChatBubble key={entry.id} entry={entry} onAction={onAction} />
        })}
      </div>
    )

  const protocolContent =
    relevantEnvelopes.length === 0 ? (
      <div className="flex flex-col items-center justify-center px-5 py-16 text-center">
        <p
          style={
            isMachine
              ? {
                  fontFamily: MONO,
                  fontSize: '11px',
                  letterSpacing: '0.08em',
                  color: 'rgba(232,228,220,0.55)',
                  textTransform: 'uppercase',
                }
              : undefined
          }
          className={
            isMachine
              ? ''
              : 'font-sans text-[13px] font-normal leading-[19.5px]'
          }
        >
          {isMachine ? '> No envelopes yet' : 'No envelopes yet'}
        </p>
      </div>
    ) : (
      <div className="p-3" style={{ fontFamily: MONO }}>
        {relevantEnvelopes.map((env) => {
          const d = env.data as {
            sender: string
            recipient: string
            id: string
            body_type: string
            headers: Record<string, string>
            body: Record<string, unknown>
          }
          return (
            <ProtocolEnvelope key={d.id} envelope={d} isMachine={isMachine} />
          )
        })}
      </div>
    )

  // ---- Machine variant (Protocol view): always shows envelopes ----
  if (isMachine) {
    return (
      <div
        className="relative flex h-full flex-col overflow-hidden"
        style={{
          backgroundColor: '#2A2A2A',
          border: '1px solid rgba(232, 228, 220, 0.12)',
          borderRadius: '6px',
          fontFamily: MONO,
        }}
      >
        {/* Ambient dot-field header strip */}
        <div
          className="relative shrink-0"
          style={{
            height: '72px',
            borderBottom: '1px solid rgba(232, 228, 220, 0.08)',
            overflow: 'hidden',
          }}
        >
          <div className="absolute inset-0 opacity-60">
            <TicketVisual />
          </div>
          <div
            className="relative flex items-center justify-between px-5"
            style={{ height: '100%' }}
          >
            <div>
              <div
                style={{
                  fontSize: '10px',
                  letterSpacing: '0.22em',
                  color: 'rgba(232,228,220,0.7)',
                  textTransform: 'uppercase',
                }}
              >
                {labelText}
              </div>
              <div
                style={{
                  marginTop: '4px',
                  fontSize: '11px',
                  color: 'rgba(232,228,220,0.85)',
                  letterSpacing: '0.02em',
                }}
              >
                {abbreviateAddress(address)}
              </div>
            </div>
            <div
              style={{
                fontSize: '10px',
                letterSpacing: '0.14em',
                color: 'rgba(232,228,220,0.5)',
                textTransform: 'uppercase',
              }}
            >
              {relevantEnvelopes.length > 0 ? `${relevantEnvelopes.length} ENV` : 'AMP v0.2'}
            </div>
          </div>
        </div>

        <div ref={scrollRef} className="flex-1 overflow-y-auto scrollbar-thin">
          {protocolContent}
        </div>
      </div>
    )
  }

  // ---- User variant (Chat view): always shows the conversation ----
  return (
    <div
      className="flex h-full flex-col overflow-hidden rounded-[28px]"
      style={{
        backgroundColor: '#F7F7F6',
        border: '1px solid rgba(231, 229, 228, 0.6)',
      }}
    >
      <div className="shrink-0 px-6 pt-5 pb-4">
        <div className="flex items-center justify-between">
          <span
            className="font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.1em]"
            style={{ color: '#A8A29E' }}
          >
            {labelText}
          </span>
          <span
            className="truncate font-mono text-[11px] font-normal leading-[16px]"
            style={{ color: '#C7C5C4' }}
          >
            {abbreviateAddress(address)}
          </span>
        </div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto scrollbar-thin">
        {chatContent}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// useMicCapture — hold-to-talk MediaRecorder hook. Single source of truth
// for mic state so both ChatbotWidget and VoiceCallOverlay can share it.
// ---------------------------------------------------------------------------

function useMicCapture({
  isStreaming,
  awaitingAgent,
  sendMessage,
  onError,
  onListeningStart,
  onListeningEnd,
}: {
  isStreaming: boolean
  awaitingAgent: 'bakery' | 'porter' | null
  sendMessage: (
    text: string,
    opts?: { voiceMode?: boolean; mode?: 'turn' | 'autonomous' },
  ) => Promise<void>
  onError: (msg: string) => void
  onListeningStart?: () => void
  onListeningEnd?: () => void
}) {
  const [isRecording, setIsRecording] = useState(false)
  const [isTranscribing, setIsTranscribing] = useState(false)
  const mediaRecorderRef = useRef<MediaRecorder | null>(null)
  const audioChunksRef = useRef<Blob[]>([])
  const recordingStreamRef = useRef<MediaStream | null>(null)

  const stopRecording = useCallback(() => {
    const rec = mediaRecorderRef.current
    if (!rec || rec.state === 'inactive') return
    // Force a final dataavailable flush before stop so very short
    // recordings still produce at least one chunk.
    try { rec.requestData() } catch { /* not all browsers */ }
    rec.stop()
  }, [])

  const startRecording = useCallback(async (opts?: { mode?: 'turn' | 'autonomous' }) => {
    if (isRecording || isTranscribing || isStreaming) return
    const mode = opts?.mode ?? 'turn'
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      recordingStreamRef.current = stream
      audioChunksRef.current = []
      const rec = new MediaRecorder(stream, { mimeType: 'audio/webm;codecs=opus' })
      mediaRecorderRef.current = rec
      rec.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) audioChunksRef.current.push(e.data)
      }
      rec.onstop = async () => {
        setIsRecording(false)
        recordingStreamRef.current?.getTracks().forEach((t) => t.stop())
        recordingStreamRef.current = null
        onListeningEnd?.()
        const blob = new Blob(audioChunksRef.current, { type: 'audio/webm' })
        if (blob.size < 1500) {
          onError('Tap the mic, speak at least 1 second, then tap again to send.')
          return
        }
        setIsTranscribing(true)
        try {
          const form = new FormData()
          form.append('audio', blob, 'utterance.webm')
          form.append('targetAgent', awaitingAgent ?? 'bakery')
          const res = await fetch('/api/amp-demo/voice', { method: 'POST', body: form })
          if (!res.ok) {
            const err = (await res.json().catch(() => ({}))) as { error?: string }
            onError(
              res.status === 422
                ? "Couldn't hear anything. Speak louder, closer to the mic."
                : err.error || `Voice failed (${res.status})`,
            )
            return
          }
          const { transcript } = (await res.json()) as { transcript: string }
          const cleaned = transcript?.trim() ?? ''
          if (!cleaned) {
            onError("Couldn't hear anything. Speak louder, closer to the mic.")
            return
          }
          await sendMessage(cleaned, { voiceMode: true, mode })
        } catch (err) {
          onError(err instanceof Error ? err.message : 'Voice request failed')
        } finally {
          setIsTranscribing(false)
        }
      }
      rec.start(250)
      // Keep uploads small: the server rejects long recordings anyway.
      setTimeout(() => {
        if (rec.state !== 'inactive') {
          try { rec.requestData() } catch { /* not all browsers */ }
          rec.stop()
        }
      }, MAX_RECORDING_MS)
      setIsRecording(true)
      onListeningStart?.()
    } catch (err) {
      onError(err instanceof Error ? `Mic blocked: ${err.message}` : 'Mic access denied')
    }
  }, [isRecording, isTranscribing, isStreaming, awaitingAgent, sendMessage, onError, onListeningStart, onListeningEnd])

  return { isRecording, isTranscribing, startRecording, stopRecording }
}

// ---------------------------------------------------------------------------
// Animated Orb — gradient sphere that pulses when the speaker is active.
// Color is identity (which agent), motion is liveness (talking now).
// ---------------------------------------------------------------------------

type Speaker = 'your-agent' | 'bakery' | 'porter'

function AnimatedOrb({
  speaker,
  label,
  sublabel,
  active,
  size = 140,
}: {
  speaker: Speaker
  label: string
  sublabel: string
  active: boolean
  size?: number
}) {
  // Each speaker gets a distinct color palette so the orb's identity
  // is unmistakable even when motion blurs the gradient. Paper-shaders'
  // MeshGradient accepts up to 10 colors as hex strings.
  const colors =
    speaker === 'your-agent'
      ? ['#B8C5D6', '#6E89B0', '#2E4870', '#1A2D4A']
      : speaker === 'bakery'
        ? ['#FAD9C5', '#E6A685', '#C86948', '#8A3A22']
        : ['#D6D0C8', '#A09487', '#5A4D40', '#2B231D']

  // Speed encodes liveness: slow drift at rest, brisk swirl while
  // this speaker is producing audio. Saturation/opacity also dim
  // when inactive so the talker reads as the focal orb.
  const speed = active ? 2.5 : 0.4

  return (
    <div className="flex flex-col items-center gap-3">
      <motion.div
        aria-hidden
        animate={{
          opacity: active ? 1 : 0.55,
          scale: active ? 1 : 0.96,
        }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        style={{
          width: size,
          height: size,
          borderRadius: '9999px',
          overflow: 'hidden',
          filter: active ? 'none' : 'saturate(0.7)',
          boxShadow: active
            ? '0 0 80px 8px rgba(200,105,72,0.25), 0 20px 50px rgba(0,0,0,0.25)'
            : '0 20px 50px rgba(0,0,0,0.18)',
        }}
      >
        <MeshGradient
          colors={colors}
          speed={speed}
          distortion={0.85}
          swirl={active ? 0.9 : 0.4}
          grainMixer={0.15}
          grainOverlay={0}
          style={{ width: '100%', height: '100%' }}
        />
      </motion.div>
      {(label || sublabel) && (
        <div className="flex flex-col items-center gap-1">
          {label && (
            <span className="text-base font-semibold" style={{ color: '#3C3A36' }}>
              {label}
            </span>
          )}
          {sublabel && (
            <span className="text-sm" style={{ color: '#78716C' }}>
              {sublabel}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Voice Call Overlay — replaces the chatbot widget when voice mode is on.
// Centered orbs, transcript caption, mic button, exit pill.
// ---------------------------------------------------------------------------

type CallStateValue = 'idle' | 'listening' | 'conversing' | 'waiting_for_user' | 'done'

function speakerDisplayName(s: Speaker): string {
  return s === 'your-agent' ? 'Your Agent' : s === 'bakery' ? 'Sunny' : 'Porter'
}

function speakerColor(s: Speaker): string {
  return s === 'your-agent' ? '#2E4870' : s === 'bakery' ? '#C86948' : '#5A4D40'
}

function orbStateLabel(s: Speaker, active: boolean, callState: CallStateValue): string {
  if (active) return 'speaking'
  if (callState === 'listening' && s === 'your-agent') return 'listening to you'
  if (callState === 'conversing') return 'waiting'
  if (callState === 'idle') return 'ready'
  return '—'
}

// ---------------------------------------------------------------------------
// Voice call: header strip. "AMP voice call · live · turn 3/8" on the
// left, inline theme switch + close button on the right. Replaces the
// page-level FloatingThemeToggle while the call is open.
// ---------------------------------------------------------------------------

function VoiceCallHeader({
  loopProgress,
  onExit,
}: {
  loopProgress: { turn: number; max: number } | null
  onExit: () => void
}) {
  const { theme, setTheme } = useAmpTheme()
  const isMachine = theme === 'machine'
  return (
    <div
      className="flex w-full items-center justify-between px-6 pt-6"
      style={{ minHeight: 56 }}
    >
      <div className="flex items-center gap-2">
        <motion.span
          aria-hidden
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            width: 8,
            height: 8,
            borderRadius: '9999px',
            backgroundColor: '#C86948',
          }}
        />
        <span
          className="text-xs font-medium uppercase"
          style={{
            color: '#78716C',
            letterSpacing: '0.16em',
            fontFamily: isMachine ? MONO : undefined,
          }}
        >
          AMP voice call · live
          {loopProgress ? ` · turn ${loopProgress.turn}/${loopProgress.max}` : ''}
        </span>
      </div>

      <div className="flex items-center gap-3">
        {/* Inline theme switch */}
        <div
          className="flex overflow-hidden rounded-full"
          style={{
            border: '1px solid rgba(231, 229, 228, 0.7)',
            backgroundColor: 'rgba(255,255,255,0.7)',
            backdropFilter: 'blur(8px)',
            WebkitBackdropFilter: 'blur(8px)',
          }}
        >
          {(['user', 'machine'] as AmpTheme[]).map((t) => {
            const active = theme === t
            return (
              <button
                key={t}
                type="button"
                onClick={() => setTheme(t)}
                className="px-3 py-1 text-xs font-medium transition-opacity"
                style={{
                  backgroundColor: active ? '#C86948' : 'transparent',
                  color: active ? '#FFFFFF' : '#78716C',
                  fontFamily: isMachine && !active ? MONO : undefined,
                  letterSpacing: isMachine && !active ? '0.16em' : undefined,
                  textTransform: isMachine && !active ? 'uppercase' : 'none',
                }}
              >
                {t === 'user' ? 'Chat' : 'Protocol'}
              </button>
            )
          })}
        </div>

        <button
          type="button"
          onClick={onExit}
          aria-label="End call"
          className="flex items-center justify-center rounded-full transition-opacity hover:opacity-70"
          style={{
            width: 32,
            height: 32,
            border: '1px solid rgba(231, 229, 228, 0.7)',
            backgroundColor: 'rgba(255,255,255,0.7)',
            color: '#4A3A31',
          }}
        >
          <HugeiconsIcon icon={CancelIcon} size={14} strokeWidth={2} />
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Voice call: orb stage. Two orbs with live state labels.
// ---------------------------------------------------------------------------

function OrbStage({
  activeSpeaker,
  callState,
  remoteSpeaker,
  remoteLabel,
  remoteSub,
}: {
  activeSpeaker: Speaker | null
  callState: CallStateValue
  remoteSpeaker: Speaker
  remoteLabel: string
  remoteSub: string
}) {
  return (
    <div className="flex w-full items-center justify-center gap-16 py-6">
      <OrbWithState
        speaker="your-agent"
        label="Your Agent"
        sublabel="you@example.com"
        active={activeSpeaker === 'your-agent'}
        callState={callState}
      />
      <OrbWithState
        speaker={remoteSpeaker}
        label={remoteLabel}
        sublabel={remoteSub}
        active={activeSpeaker === remoteSpeaker}
        callState={callState}
      />
    </div>
  )
}

function OrbWithState({
  speaker,
  label,
  sublabel,
  active,
  callState,
}: {
  speaker: Speaker
  label: string
  sublabel: string
  active: boolean
  callState: CallStateValue
}) {
  const state = orbStateLabel(speaker, active, callState)
  return (
    <div className="flex flex-col items-center gap-3">
      <AnimatedOrb speaker={speaker} label="" sublabel="" active={active} />
      <div className="flex flex-col items-center gap-1">
        <span className="text-base font-semibold" style={{ color: '#3C3A36' }}>
          {label}
        </span>
        <span className="text-xs" style={{ color: '#A8A29E' }}>
          {sublabel}
        </span>
        <div className="mt-1 flex items-center gap-1.5">
          {active && (
            <motion.span
              aria-hidden
              animate={{ opacity: [0.4, 1, 0.4] }}
              transition={{ duration: 1, repeat: Infinity, ease: 'easeInOut' }}
              style={{
                width: 6,
                height: 6,
                borderRadius: '9999px',
                backgroundColor: speakerColor(speaker),
              }}
            />
          )}
          <span
            className="text-xs font-medium"
            style={{ color: active ? speakerColor(speaker) : '#A8A29E' }}
          >
            {state}
          </span>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Voice call: rolling transcript log. Shows the last 5 spoken lines in
// chronological order; auto-scrolls so the newest is always visible.
// ---------------------------------------------------------------------------

function TranscriptScroll({
  log,
}: {
  log: Array<{ speaker: Speaker; text: string; id: number }>
}) {
  const recent = log.slice(-5)
  const scrollerRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (scrollerRef.current) {
      scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight
    }
  }, [log.length])

  if (recent.length === 0) {
    return (
      <div
        className="mx-auto flex w-full max-w-2xl items-center justify-center"
        style={{ minHeight: 120, color: '#A8A29E', fontSize: 13 }}
      >
        Conversation will appear here.
      </div>
    )
  }

  return (
    <div
      ref={scrollerRef}
      className="mx-auto flex w-full max-w-2xl flex-col gap-2 overflow-y-auto px-4"
      style={{ height: 140 }}
    >
      {recent.map((entry, i) => {
        const isLatest = i === recent.length - 1
        return (
          <motion.div
            key={entry.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: isLatest ? 1 : 0.55, y: 0 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="text-left"
          >
            <span
              className="mr-2 text-xs font-semibold uppercase"
              style={{
                color: speakerColor(entry.speaker),
                letterSpacing: '0.08em',
              }}
            >
              {speakerDisplayName(entry.speaker)}
            </span>
            <span
              className="text-sm"
              style={{
                color: isLatest ? '#3C3A36' : '#78716C',
                lineHeight: '1.5',
              }}
            >
              {entry.text}
            </span>
          </motion.div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Voice call: approval card slot. Renders the pending hand-off from
// the autonomous loop — a question with structured option chips, or
// just a question (free-text reply expected). Tapping a chip calls
// onAnswer with that label; voice resumes between YA and Sunny.
// ---------------------------------------------------------------------------

function ApprovalCardSlot({
  pending,
  onAnswer,
}: {
  pending: PendingDecision | null
  onAnswer: (answer: string) => void
}) {
  if (!pending) return null
  const hasChips = pending.options && pending.options.length > 0
  return (
    <motion.div
      key={pending.id}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
      className="mx-auto w-full max-w-2xl"
      style={{
        marginTop: 8,
        padding: '14px 18px',
        borderRadius: '1rem',
        background: 'rgba(255, 255, 255, 0.9)',
        border: '1px solid rgba(231, 229, 228, 0.7)',
        boxShadow: '0 8px 20px rgba(74, 58, 49, 0.08)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
    >
      <p
        className="mb-3 text-sm"
        style={{ color: '#3C3A36', fontWeight: 500 }}
      >
        {pending.question}
      </p>
      {hasChips ? (
        <div className="flex flex-wrap gap-2">
          {pending.options!.map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => onAnswer(opt)}
              className="rounded-[var(--radius-control,0.75rem)] px-3 py-2 text-sm font-medium transition-all hover:opacity-90 active:scale-[0.98]"
              style={{
                backgroundColor: '#C86948',
                color: '#FFFFFF',
                border: 'none',
              }}
            >
              {opt}
            </button>
          ))}
        </div>
      ) : (
        <p className="text-xs" style={{ color: '#A8A29E' }}>
          Reply in chat to continue the call.
        </p>
      )}
    </motion.div>
  )
}

// ---------------------------------------------------------------------------
// Voice call: single bottom control. Mic button + status hint line.
// ---------------------------------------------------------------------------

function MicControl({
  callState,
  isRecording,
  isTranscribing,
  isStreaming,
  loopProgress,
  remoteLabel,
  finalSummary,
  onMicDown,
  onMicUp,
  onRestart,
}: {
  callState: CallStateValue
  isRecording: boolean
  isTranscribing: boolean
  isStreaming: boolean
  loopProgress: { turn: number; max: number } | null
  remoteLabel: string
  finalSummary: string | null
  onMicDown: () => void
  onMicUp: () => void
  onRestart: () => void
}) {
  const micEnabled =
    callState === 'idle' ||
    callState === 'waiting_for_user' ||
    callState === 'listening'

  const hint = (() => {
    if (callState === 'idle') return 'Tap to brief your agent'
    if (callState === 'listening') return 'Tap again to send'
    if (callState === 'conversing') {
      const t = loopProgress ? ` (turn ${loopProgress.turn}/${loopProgress.max})` : ''
      return `Your Agent is on a call with ${remoteLabel}${t}`
    }
    if (callState === 'waiting_for_user') return 'Tap to reply'
    if (callState === 'done') return finalSummary || 'Done'
    return ''
  })()

  if (callState === 'done') {
    return (
      <div className="flex flex-col items-center gap-3">
        <p
          className="max-w-xl text-center text-sm"
          style={{ color: '#3C3A36' }}
        >
          {hint}
        </p>
        <button
          type="button"
          onClick={onRestart}
          className="rounded-full px-6 py-2.5 text-sm font-medium transition-opacity hover:opacity-90"
          style={{
            backgroundColor: '#C86948',
            color: '#FFFFFF',
            boxShadow: '0 8px 20px rgba(200,105,72,0.3)',
          }}
        >
          Start new call
        </button>
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center gap-3">
      {micEnabled ? (
        <motion.button
          type="button"
          onClick={(e) => {
            e.preventDefault()
            if (isRecording) {
              onMicUp()
            } else if (micEnabled) {
              onMicDown()
            }
          }}
          disabled={isStreaming || isTranscribing}
          aria-pressed={isRecording}
          aria-label={isRecording ? 'Tap to stop recording' : 'Tap to speak'}
          className="flex items-center justify-center disabled:cursor-not-allowed disabled:opacity-40"
          animate={{
            backgroundColor: isRecording ? '#9A3A1F' : '#C86948',
            scale: isRecording ? 1.08 : 1,
          }}
          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
          style={{
            height: 60,
            width: 60,
            borderRadius: '9999px',
            color: '#FFFFFF',
            boxShadow: '0 10px 24px rgba(200,105,72,0.32)',
          }}
        >
          {isTranscribing ? (
            <HugeiconsIcon icon={Loading03Icon} size={22} strokeWidth={2} className="animate-spin" />
          ) : (
            <HugeiconsIcon
              icon={isRecording ? MicOffIcon : MicIcon}
              size={22}
              strokeWidth={2}
            />
          )}
        </motion.button>
      ) : (
        // Conversing — agents are talking. Show a soft pulse so the user
        // knows the call is alive without offering an input control.
        <motion.div
          aria-hidden
          animate={{ opacity: [0.4, 1, 0.4], scale: [1, 1.15, 1] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            width: 14,
            height: 14,
            borderRadius: '9999px',
            backgroundColor: '#C86948',
            margin: '23px 0',
          }}
        />
      )}
      <p className="text-sm font-medium" style={{ color: '#78716C' }}>
        {hint}
      </p>
    </div>
  )
}

function VoiceCallOverlay({
  activeSpeaker,
  isRecording,
  isTranscribing,
  isStreaming,
  porterActive,
  transcriptLog,
  pendingDecision,
  callState,
  loopProgress,
  finalSummary,
  onMicDown,
  onMicUp,
  onAnswerDecision,
  onExit,
  onRestart,
}: {
  activeSpeaker: Speaker | null
  isRecording: boolean
  isTranscribing: boolean
  isStreaming: boolean
  porterActive: boolean
  lastTranscript: { speaker: Speaker; text: string } | null
  transcriptLog: Array<{ speaker: Speaker; text: string; id: number }>
  pendingDecision: PendingDecision | null
  callState: CallStateValue
  loopProgress: { turn: number; max: number } | null
  finalSummary: string | null
  onMicDown: () => void
  onMicUp: () => void
  onAnswerDecision: (answer: string) => void
  onExit: () => void
  onRestart: () => void
}) {
  const remoteSpeaker: Speaker = porterActive ? 'porter' : 'bakery'
  const remoteLabel = porterActive ? 'Porter' : 'Sunny Bakery'
  const remoteSub = porterActive ? 'Logistics' : 'Bakery'

  return createPortal(
    <motion.div
      className="fixed inset-0 z-40 flex flex-col"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3 }}
      style={{
        background:
          'radial-gradient(ellipse at center, rgba(251,251,251,0.96) 0%, rgba(245,241,237,0.98) 60%, rgba(245,241,237,1) 100%)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
    >
      <VoiceCallHeader loopProgress={loopProgress} onExit={onExit} />

      <div className="flex flex-1 flex-col items-center justify-center gap-5 px-6">
        <OrbStage
          activeSpeaker={activeSpeaker}
          callState={callState}
          remoteSpeaker={remoteSpeaker}
          remoteLabel={remoteLabel}
          remoteSub={remoteSub}
        />

        <TranscriptScroll log={transcriptLog} />

        <ApprovalCardSlot pending={pendingDecision} onAnswer={onAnswerDecision} />
      </div>

      <div className="flex w-full justify-center px-6 pb-10">
        <MicControl
          callState={callState}
          isRecording={isRecording}
          isTranscribing={isTranscribing}
          isStreaming={isStreaming}
          loopProgress={loopProgress}
          remoteLabel={remoteLabel}
          finalSummary={finalSummary}
          onMicDown={onMicDown}
          onMicUp={onMicUp}
          onRestart={onRestart}
        />
      </div>
    </motion.div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Floating Chatbot Widget — bottom-right, transparent, shadow halo
// ---------------------------------------------------------------------------

function ChatbotWidget({
  state,
  dispatch,
  sendMessage,
  handleSend,
  handleOptionClick,
  inputRef,
  mic,
  onEnterVoiceMode,
  onAnswerDecision,
}: {
  state: State
  dispatch: Dispatch<Action>
  sendMessage: (explicitText?: string, opts?: { voiceMode?: boolean }) => Promise<void>
  handleSend: () => void
  handleOptionClick: (opt: string) => void
  inputRef: RefObject<HTMLTextAreaElement | null>
  mic: {
    isRecording: boolean
    isTranscribing: boolean
    startRecording: (opts?: { mode?: 'turn' | 'autonomous' }) => Promise<void>
    stopRecording: () => void
  }
  onEnterVoiceMode: () => void
  onAnswerDecision: (answer: string) => void
}) {
  const { theme } = useAmpTheme()
  const isMachine = theme === 'machine'
  const { isRecording, isTranscribing, startRecording, stopRecording } = mic

  // Show the full user/bakery chat history in the widget (chronological)
  const history = state.yourAgentEntries.filter(
    (e) => e.type === 'chat' && (e.role === 'user' || e.role === 'remote'),
  )
  const latestRemote = [...history].reverse().find((e) => e.role === 'remote')

  const threadRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    threadRef.current?.scrollTo({
      top: threadRef.current.scrollHeight,
      behavior: 'smooth',
    })
  }, [history.length, latestRemote?.text])

  const starterSuggestions = [
    // One-shot with delivery (spawns Porter)
    "Medium chocolate fudge cake (serves 12–15), 'Happy Birthday Maya' in white frosting, deliver tomorrow 2pm to Bandra West.",
    // Pickup only (no Porter)
    "Small red velvet cake (serves 6–8), 'Congrats Priya' message, pickup Friday at 6pm.",
    // Delivery but vague, bakery asks questions first
    "Birthday cake for 20 people this Saturday, deliver to Juhu.",
    // Fully vague
    "I want to order a cake for my friend.",
  ]

  const [mounted, setMounted] = useState(false)
  // eslint-disable-next-line react-hooks/set-state-in-effect -- client-after-hydration flag
  useEffect(() => setMounted(true), [])
  if (!mounted) return null

  return createPortal(
    <div className="pointer-events-none fixed bottom-4 left-4 right-4 z-50 sm:bottom-6 sm:left-auto sm:right-6 sm:w-[380px]">
      {/* Ambient shadow halo behind widget — layered for depth */}
      <div
        aria-hidden
        className="absolute -inset-32 -z-10"
        style={{
          background: isMachine
            ? 'radial-gradient(ellipse at bottom right, rgba(0,0,0,0.55) 0%, rgba(0,0,0,0.25) 30%, rgba(0,0,0,0) 75%)'
            : 'radial-gradient(ellipse at bottom right, rgba(74, 58, 49, 0.28) 0%, rgba(74, 58, 49, 0.16) 25%, rgba(74, 58, 49, 0.06) 55%, rgba(74, 58, 49, 0) 80%)',
          filter: 'blur(40px)',
        }}
      />
      <div
        aria-hidden
        className="absolute -inset-20 -z-10"
        style={{
          background: isMachine
            ? 'radial-gradient(ellipse at bottom right, rgba(200, 105, 72, 0.22) 0%, rgba(200, 105, 72, 0.08) 40%, rgba(200, 105, 72, 0) 75%)'
            : 'radial-gradient(ellipse at bottom right, rgba(200, 105, 72, 0.18) 0%, rgba(200, 105, 72, 0.08) 35%, rgba(200, 105, 72, 0) 70%)',
          filter: 'blur(28px)',
        }}
      />
      <div
        aria-hidden
        className="absolute -inset-12 -z-10"
        style={{
          background: isMachine
            ? 'radial-gradient(ellipse at bottom right, rgba(0,0,0,0.5) 0%, rgba(0,0,0,0.2) 40%, rgba(0,0,0,0) 75%)'
            : 'radial-gradient(ellipse at bottom right, rgba(74, 58, 49, 0.22) 0%, rgba(74, 58, 49, 0.10) 40%, rgba(74, 58, 49, 0) 75%)',
          filter: 'blur(18px)',
        }}
      />

      <div className="pointer-events-auto flex flex-col gap-3">
        {/* Scrollable chat thread */}
        {history.length > 0 && (
          <div
            ref={threadRef}
            className="flex max-h-[50vh] flex-col gap-3 overflow-y-auto pr-1 scrollbar-thin"
          >
            {history.map((entry) =>
              entry.role === 'user' ? (
                <div key={entry.id} className="flex justify-end">
                  <div
                    className="max-w-[80%]"
                    style={
                      isMachine
                        ? {
                            backgroundColor: '#C86948',
                            color: '#121212',
                            padding: '8px 12px',
                            borderRadius: '4px',
                            fontFamily: MONO,
                            fontSize: '12px',
                            lineHeight: '1.5',
                            whiteSpace: 'pre-wrap',
                          }
                        : {
                            backgroundColor: '#C86948',
                            color: '#FFFFFF',
                            padding: '10px 16px',
                            borderRadius: '18px',
                          }
                    }
                  >
                    {isMachine ? (
                      entry.text
                    ) : (
                      <p className="whitespace-pre-wrap font-sans text-[14px] font-medium leading-[20px]">
                        {entry.text}
                      </p>
                    )}
                  </div>
                </div>
              ) : (
                (() => {
                  const isPorterForward =
                    /(?:DeliverySlot|RoutePreview|CombinedQuote|DeliveryConfirmed|PorterMessage)\(/.test(
                      entry.text,
                    )
                  const viaLabel = isPorterForward
                    ? 'via Porter'
                    : 'via Sunny Bakery'
                  const lib = isPorterForward
                    ? porterLibFor(theme)
                    : bakeryLibFor(theme)
                  return (
                    <div key={entry.id}>
                      {isMachine ? (
                        <p
                          style={{
                            marginBottom: '8px',
                            fontFamily: MONO,
                            fontSize: '10px',
                            letterSpacing: '0.18em',
                            color: 'rgba(232,228,220,0.55)',
                            textTransform: 'uppercase',
                          }}
                        >
                          RX&nbsp;//&nbsp;MY AGENT
                          <span style={{ color: 'rgba(232,228,220,0.35)' }}>
                            &nbsp;·&nbsp;{viaLabel}
                          </span>
                        </p>
                      ) : (
                        <p
                          className="mb-2 font-sans text-[11px] font-medium uppercase leading-[16px] tracking-[0.08em]"
                          style={{ color: '#A8A29E' }}
                        >
                          My Agent{' '}
                          <span style={{ color: '#C7C5C4' }}>· {viaLabel}</span>
                        </p>
                      )}
                      <Renderer
                        response={entry.text}
                        library={lib}
                        isStreaming={entry.isStreaming || false}
                        onAction={(event) => {
                          if (!state.isStreaming) {
                            const action =
                              event.humanFriendlyMessage ||
                              String(event.params?.label ?? event.type ?? '')
                            if (action) sendMessage(action)
                          }
                        }}
                      />
                    </div>
                  )
                })()
              ),
            )}
          </div>
        )}

        {/* Starter suggestions (only before the first turn) */}
        <AnimatePresence>
        {state.turnCount === 0 && !state.isStreaming && (
          <motion.div
            key="starters"
            // Phones: one horizontally scrollable row so the fixed dock does
            // not stack over the page. Wider screens: wrap as before.
            className="-mx-1 flex flex-nowrap gap-2 overflow-x-auto px-1 pb-1 sm:mx-0 sm:flex-wrap sm:overflow-visible sm:px-0 sm:pb-0"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.3 }}
          >
            {starterSuggestions.map((suggestion, idx) => (
              <motion.button
                key={suggestion}
                type="button"
                onClick={() => handleOptionClick(suggestion)}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{
                  duration: 0.25,
                  delay: 0.04 * idx,
                  ease: [0.22, 1, 0.36, 1],
                }}
                style={
                  isMachine
                    ? {
                        padding: '6px 10px',
                        background: '#2A2A2A',
                        color: '#E8E4DC',
                        border: '1px solid rgba(232,228,220,0.15)',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontFamily: MONO,
                        fontSize: '10px',
                        letterSpacing: '0.06em',
                        textAlign: 'left',
                      }
                    : {
                        color: '#3C3A36',
                        border: '1px solid rgba(231, 229, 228, 0.6)',
                        boxShadow: '0 2px 6px rgba(74, 58, 49, 0.06)',
                      }
                }
                className={
                  isMachine
                    ? ''
                    : 'shrink-0 whitespace-nowrap rounded-full bg-white px-3 py-[8px] font-sans text-[13px] font-medium leading-[19.5px] transition-colors hover:bg-[#FBF3F0] sm:shrink sm:whitespace-normal'
                }
              >
                {isMachine ? `> ${suggestion}` : suggestion}
              </motion.button>
            ))}
          </motion.div>
        )}
        </AnimatePresence>

        {/* Pending server-side options */}
        <AnimatePresence>
        {state.pendingOptions.length > 0 && !state.isStreaming && (
          <motion.div
            key="pending-options"
            className="flex flex-wrap gap-2"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.25 }}
          >
            {state.pendingOptions.map((opt, i) => (
              <motion.button
                key={i}
                type="button"
                onClick={() => handleOptionClick(opt)}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                style={
                  isMachine
                    ? {
                        padding: '6px 12px',
                        background: '#2A2A2A',
                        color: '#E8E4DC',
                        border: '1px solid rgba(232,228,220,0.15)',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontFamily: MONO,
                        fontSize: '10px',
                        letterSpacing: '0.12em',
                        textTransform: 'uppercase',
                      }
                    : {
                        color: '#3C3A36',
                        border: '1px solid rgba(231, 229, 228, 0.6)',
                        boxShadow: '0 2px 6px rgba(74, 58, 49, 0.06)',
                      }
                }
                className={
                  isMachine
                    ? ''
                    : 'rounded-full bg-white px-3 py-[8px] font-sans text-[13px] font-medium leading-[19.5px] transition-colors hover:bg-[#FBF3F0] active:scale-[0.98]'
                }
              >
                {isMachine ? `[ ${opt} ]` : opt}
              </motion.button>
            ))}
          </motion.div>
        )}
        </AnimatePresence>

        {/* Pending decision from the voice-mode autonomous loop. The
            same data renders in the orb overlay's ApprovalCardSlot; we
            mirror it here so the chat tab can answer too. Tapping a chip
            (or sending a typed reply) calls onAnswerDecision which POSTs
            to /api/amp-demo/resume and the call continues. */}
        <AnimatePresence>
          {state.pendingDecision && (
            <motion.div
              key={state.pendingDecision.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="flex flex-col gap-2"
              style={{
                padding: '12px 14px',
                borderRadius: '1rem',
                background: isMachine ? 'rgba(42,42,42,0.85)' : 'rgba(255,255,255,0.95)',
                border: isMachine
                  ? '1px solid rgba(232,228,220,0.2)'
                  : '1px solid rgba(231,229,228,0.6)',
                boxShadow: isMachine
                  ? '0 8px 24px rgba(0,0,0,0.4)'
                  : '0 8px 20px rgba(74,58,49,0.08)',
              }}
            >
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 500,
                  color: isMachine ? '#E8E4DC' : '#3C3A36',
                }}
              >
                {state.pendingDecision.question}
              </p>
              {state.pendingDecision.options && state.pendingDecision.options.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {state.pendingDecision.options.map((opt) => (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => onAnswerDecision(opt)}
                      className="transition-opacity hover:opacity-90 active:scale-[0.98]"
                      style={
                        isMachine
                          ? {
                              padding: '6px 12px',
                              backgroundColor: '#C86948',
                              color: '#121212',
                              border: 'none',
                              borderRadius: '3px',
                              fontFamily: MONO,
                              fontSize: 10,
                              letterSpacing: '0.12em',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                            }
                          : {
                              padding: '8px 14px',
                              backgroundColor: '#C86948',
                              color: '#FFFFFF',
                              border: 'none',
                              borderRadius: '9999px',
                              fontSize: 13,
                              fontWeight: 500,
                            }
                      }
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              ) : (
                <p
                  style={{
                    fontSize: 11,
                    color: isMachine ? 'rgba(232,228,220,0.5)' : '#A8A29E',
                  }}
                >
                  Type your reply below.
                </p>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Voice mode entry pill — switches the widget for the orb overlay. */}
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onEnterVoiceMode}
            className="flex items-center gap-1.5 transition-opacity hover:opacity-80"
            style={
              isMachine
                ? {
                    padding: '4px 10px',
                    backgroundColor: 'rgba(232,228,220,0.08)',
                    border: '1px solid rgba(232,228,220,0.2)',
                    borderRadius: '3px',
                    color: 'rgba(232,228,220,0.75)',
                    fontFamily: MONO,
                    fontSize: '10px',
                    letterSpacing: '0.16em',
                    textTransform: 'uppercase',
                    fontWeight: 700,
                  }
                : {
                    padding: '6px 12px',
                    backgroundColor: 'rgba(255,255,255,0.7)',
                    border: '1px solid rgba(231, 229, 228, 0.6)',
                    borderRadius: '9999px',
                    color: '#4A3A31',
                    fontSize: '12px',
                    fontWeight: 500,
                  }
            }
          >
            <HugeiconsIcon icon={MicIcon} size={isMachine ? 10 : 12} strokeWidth={2} />
            {isMachine ? 'VOICE CALL' : 'Talk to agents'}
          </button>
        </div>

        {/* Input row */}
        <motion.div
          className={cn(
            'flex items-end gap-2',
            state.isStreaming && 'opacity-60',
          )}
          animate={
            isMachine
              ? {
                  backgroundColor: '#2A2A2A',
                  borderColor: 'rgba(232,228,220,0.18)',
                  borderRadius: '4px',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                }
              : {
                  backgroundColor: '#FFFFFF',
                  borderColor: 'rgba(231, 229, 228, 0.6)',
                  borderRadius: '9999px',
                  boxShadow: '0 8px 24px rgba(74, 58, 49, 0.12)',
                }
          }
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          style={{
            padding: isMachine ? '8px 12px' : '8px 16px',
            borderStyle: 'solid',
            borderWidth: '1px',
          }}
        >
          <textarea
            ref={inputRef}
            maxLength={MAX_MESSAGE_CHARS}
            value={state.input}
            onChange={(e) => dispatch({ type: 'SET_INPUT', value: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                handleSend()
              }
            }}
            placeholder={
              isMachine
                ? state.turnCount === 0
                  ? '> TX READY…'
                  : '> REPLY…'
                : state.turnCount === 0
                  ? 'Ask your agent anything…'
                  : 'Reply to your agent…'
            }
            disabled={state.isStreaming}
            rows={1}
            className="max-h-32 flex-1 resize-none bg-transparent focus:outline-hidden disabled:opacity-50"
            style={
              isMachine
                ? {
                    color: '#E8E4DC',
                    fontFamily: MONO,
                    fontSize: '12px',
                    lineHeight: '1.5',
                    letterSpacing: '0.02em',
                  }
                : {
                    color: '#4A3A31',
                    fontFamily: 'inherit',
                    fontSize: '14px',
                    fontWeight: 500,
                    lineHeight: '20px',
                  }
            }
          />
          <motion.button
            type="button"
            onClick={(e) => {
              e.preventDefault()
              if (isRecording) {
                stopRecording()
              } else {
                startRecording()
              }
            }}
            disabled={state.isStreaming || isTranscribing}
            aria-pressed={isRecording}
            aria-label={isRecording ? 'Tap to stop recording' : 'Tap to speak'}
            className="flex shrink-0 items-center justify-center disabled:cursor-not-allowed disabled:opacity-30"
            animate={{
              backgroundColor: isRecording
                ? '#9A3A1F'
                : isMachine
                  ? '#1E1E1E'
                  : '#F5F1ED',
              color: isRecording
                ? '#FFFFFF'
                : isMachine
                  ? '#E8E4DC'
                  : '#4A3A31',
            }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            style={
              isMachine
                ? {
                    padding: '6px 10px',
                    border: '1px solid rgba(232,228,220,0.2)',
                    borderRadius: '3px',
                  }
                : {
                    height: '32px',
                    width: '32px',
                    borderRadius: '9999px',
                    border: '1px solid rgba(231, 229, 228, 0.6)',
                  }
            }
          >
            {isTranscribing ? (
              <HugeiconsIcon icon={Loading03Icon} size={13} strokeWidth={2} className="animate-spin" />
            ) : (
              <HugeiconsIcon
                icon={isRecording ? MicOffIcon : MicIcon}
                size={isMachine ? 12 : 14}
                strokeWidth={2}
              />
            )}
          </motion.button>
          <motion.button
            type="button"
            onClick={handleSend}
            disabled={state.isStreaming || !state.input.trim()}
            className="flex shrink-0 items-center justify-center disabled:cursor-not-allowed disabled:opacity-30"
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            style={
              isMachine
                ? {
                    padding: '6px 10px',
                    backgroundColor: '#C86948',
                    color: '#121212',
                    border: 'none',
                    borderRadius: '3px',
                    fontFamily: MONO,
                    fontSize: '10px',
                    letterSpacing: '0.16em',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                  }
                : {
                    height: '32px',
                    width: '32px',
                    borderRadius: '9999px',
                    backgroundColor: '#C86948',
                    color: '#FFFFFF',
                  }
            }
          >
            {isMachine ? 'TX' : (
              <HugeiconsIcon icon={SentIcon} size={13} strokeWidth={2} />
            )}
          </motion.button>
        </motion.div>

        <AnimatePresence>
          {state.error && (
            <motion.p
              key="err"
              className="text-center"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              style={
                isMachine
                  ? {
                      fontFamily: MONO,
                      fontSize: '10px',
                      letterSpacing: '0.12em',
                      color: '#C86948',
                      textTransform: 'uppercase',
                    }
                  : {
                      fontFamily: 'inherit',
                      fontSize: '13px',
                      fontWeight: 400,
                      lineHeight: '19.5px',
                      color: '#C86948',
                    }
              }
            >
              {isMachine ? `ERR > ${state.error}` : state.error}
            </motion.p>
          )}
        </AnimatePresence>
      </div>
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function AmpDemoClient() {
  const { theme, setVoiceCallActive, surface, setSurface } = useAmpTheme()
  const isMachine = theme === 'machine'
  const [state, dispatch] = useReducer(reducer, initial)
  const bakeryResponseRef = useRef('')
  const porterResponseRef = useRef('')
  const currentUserMsgRef = useRef('')
  const inputRef = useRef<HTMLTextAreaElement>(null)
  /**
   * Whether the user has opted into the voice-call UI (two orbs instead
   * of the chat thread). Default off so the visual demo stays the same
   * for keyboard users.
   */
  const [voiceUIMode, setVoiceUIMode] = useState(false)
  // Mirror voiceUIMode into the AMP theme context so the page-level
  // FloatingThemeToggle can hide itself while the call is open.
  useEffect(() => {
    setVoiceCallActive(voiceUIMode)
    return () => setVoiceCallActive(false)
  }, [voiceUIMode, setVoiceCallActive])

  // Single-direction sync: surface drives voiceUIMode. Closing the
  // overlay (via End-Call button) calls setSurface('chat') directly in
  // the onExit handler below — no effect-loop hazard.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- single-direction sync from source (surface)
    setVoiceUIMode(surface === 'voice')
  }, [surface])
  /**
   * Which speaker (if any) is producing audio right now. Drives the
   * orb pulse animation. Reset to null when the playback queue drains.
   */
  const [activeSpeaker, setActiveSpeaker] = useState<
    'your-agent' | 'bakery' | 'porter' | null
  >(null)
  /**
   * Latest voice-utterance transcript shown as a caption under the orbs.
   * Local because it's purely visual (the overlay caption). The shared
   * rolling log lives in state.spokenLog and is consumed by every
   * surface (chat thread, protocol timeline, voice overlay).
   */
  const [lastTranscript, setLastTranscript] = useState<{
    speaker: Speaker
    text: string
  } | null>(null)
  const transcriptIdRef = useRef(0)
  /**
   * Overlay state machine — drives what the orb screen shows and whether
   * the mic is hot.
   *   idle              → Ready for the user's brief. Mic visible & hot.
   *   listening         → User is holding the mic right now.
   *   conversing        → Agents are talking among themselves. Mic hidden.
   *   waiting_for_user  → Agent paused, needs user input. Mic visible & hot.
   *   done              → Loop finished. Restart button visible.
   */
  type CallState = 'idle' | 'listening' | 'conversing' | 'waiting_for_user' | 'done'
  const [callState, setCallState] = useState<CallState>('idle')
  const [loopProgress, setLoopProgress] = useState<{ turn: number; max: number } | null>(null)
  const [finalSummary, setFinalSummary] = useState<string | null>(null)
  /**
   * Web Audio playback. Decode each clip's base64 MP3 into an
   * AudioBuffer and play through an AudioBufferSourceNode. This works
   * around browser autoplay policy: once the AudioContext is resumed
   * under a user gesture (the mic-tap on entering voice mode), every
   * subsequent decode+play inherits authorization for the page lifetime.
   * <audio> element playback cannot achieve this without a fresh
   * synchronous gesture per clip — which an SSE callback can't provide.
   */
  const audioCtxRef = useRef<AudioContext | null>(null)
  type QueuedClip = {
    speaker: 'your-agent' | 'bakery' | 'porter'
    transcript: string
    buffer: AudioBuffer
  }
  const voiceQueueRef = useRef<QueuedClip[]>([])
  const voicePlayingRef = useRef(false)

  // Called on the mic-tap gesture. Lazily creates the AudioContext and
  // resumes it. Safe to call repeatedly.
  const unlockAudio = useCallback(() => {
    if (audioCtxRef.current) {
      if (audioCtxRef.current.state === 'suspended') {
        void audioCtxRef.current.resume()
      }
      return
    }
    const AC =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext })
        .webkitAudioContext
    if (!AC) {
      console.warn('[amp-demo] Web Audio API unsupported in this browser')
      return
    }
    audioCtxRef.current = new AC()
    void audioCtxRef.current.resume()
  }, [])

  // Holds the latest `playNextVoiceClip` so the BufferSource `onended`
  // chain can recurse without referencing the callback before it is declared.
  const playNextVoiceClipRef = useRef<(() => void) | null>(null)
  const playNextVoiceClip = useCallback(() => {
    if (voicePlayingRef.current) return
    const ctx = audioCtxRef.current
    if (!ctx) {
      // No context yet — the user hasn't tapped the mic. Drop clips
      // silently rather than building up an unplayable backlog.
      voiceQueueRef.current = []
      setActiveSpeaker(null)
      return
    }
    const next = voiceQueueRef.current.shift()
    if (!next) {
      setActiveSpeaker(null)
      return
    }
    voicePlayingRef.current = true
    setActiveSpeaker(next.speaker)
    if (next.transcript) {
      setLastTranscript({ speaker: next.speaker, text: next.transcript })
      transcriptIdRef.current += 1
      dispatch({
        type: 'APPEND_SPOKEN',
        line: {
          id: transcriptIdRef.current,
          speaker: next.speaker,
          text: next.transcript,
        },
      })
    }
    const src = ctx.createBufferSource()
    src.buffer = next.buffer
    src.connect(ctx.destination)
    src.onended = () => {
      voicePlayingRef.current = false
      playNextVoiceClipRef.current?.()
    }
    try {
      src.start()
    } catch (err) {
      console.warn('[amp-demo] BufferSource.start failed', err)
      voicePlayingRef.current = false
      playNextVoiceClipRef.current?.()
    }
  }, [])
  // Keep the latest callback in the ref so the async `onended` chain
  // always recurses into the current closure. Written in an effect (not
  // during render) to satisfy react-hooks/refs.
  useEffect(() => {
    playNextVoiceClipRef.current = playNextVoiceClip
  }, [playNextVoiceClip])

  // Decode + enqueue a single voice clip. Decoding is async; we
  // serialize via a chain so the order matches the SSE arrival order.
  const decodeChainRef = useRef<Promise<void>>(Promise.resolve())
  const enqueueVoiceClip = useCallback(
    (clip: { speaker: 'your-agent' | 'bakery' | 'porter'; transcript: string; audioB64: string }) => {
      decodeChainRef.current = decodeChainRef.current.then(async () => {
        const ctx = audioCtxRef.current
        if (!ctx) return
        try {
          const binary = atob(clip.audioB64)
          const bytes = new Uint8Array(binary.length)
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
          const buffer = await ctx.decodeAudioData(bytes.buffer)
          voiceQueueRef.current.push({
            speaker: clip.speaker,
            transcript: clip.transcript,
            buffer,
          })
          playNextVoiceClip()
        } catch (err) {
          console.warn('[amp-demo] decodeAudioData failed for clip', err)
        }
      })
    },
    [playNextVoiceClip],
  )

  // Auto-resize textarea
  const adjustTextareaHeight = useCallback(() => {
    const textarea = inputRef.current
    if (textarea) {
      textarea.style.height = 'auto'
      textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`
    }
  }, [])

  useEffect(() => {
    adjustTextareaHeight()
  }, [state.input, adjustTextareaHeight])

  const sendMessage = useCallback(async (
    explicitText?: string,
    opts?: { voiceMode?: boolean; mode?: 'turn' | 'autonomous' },
  ) => {
    const text = (explicitText ?? state.input).trim()
    if (!text || state.isStreaming) return

    const isFirstTurn = state.turnCount === 0
    currentUserMsgRef.current = text
    bakeryResponseRef.current = ''
    porterResponseRef.current = ''

    dispatch({ type: 'START_TURN' })

    // Add user message to Your Agent window
    dispatch({
      type: 'ADD_ENTRY',
      entry: mkEntry('your-agent', 'chat', text, { role: 'user' }),
    })

    try {
      const res = await fetch('/api/amp-demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          // The server accepts a bounded history; send the recent part.
          history: state.conversationHistory.slice(-MAX_HISTORY_SENT),
          isFirstTurn,
          targetAgent: state.awaitingAgent ?? 'bakery',
          porterActive: state.porterActive,
          voiceMode: Boolean(opts?.voiceMode),
          mode: opts?.mode ?? 'turn',
        }),
      })

      if (!res.ok) {
        const err = (await res.json().catch(() => ({}))) as { error?: string }
        dispatch({ type: 'SET_ERROR', error: err.error || `Request failed (${res.status})` })
        return
      }

      const reader = res.body?.getReader()
      if (!reader) {
        dispatch({ type: 'SET_ERROR', error: 'No stream available' })
        return
      }

      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const raw = line.slice(6).trim()
          if (!raw || raw === '[DONE]') continue

          try {
            const p = JSON.parse(raw) as {
              type: string
              data: Record<string, unknown>
            }

            if (p.type === 'envelope') {
              dispatch({ type: 'ADD_ENVELOPE', data: p.data })
              const bt = (p.data.body_type as string) || ''
              const sender = ((p.data.sender as string) || '').replace('agent://', '').toLowerCase()
              const recipient = ((p.data.recipient as string) || '').replace('agent://', '').toLowerCase()

              if (bt === DIRECTORY_QUERY) {
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'your-agent',
                  label: 'Discovering bakery agents in the mesh...',
                  status: 'active',
                })
              } else if (bt === DIRECTORY_RESPONSE) {
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'your-agent',
                  label: 'Found Sunny Bakery (rated 4.8)',
                  status: 'complete',
                })
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'your-agent',
                  label: 'Task handed to Sunny Bakery (signed envelope)',
                  status: 'complete',
                })
              } else if (bt === 'task.create') {
                if (sender.includes('you@example.com') || sender.includes('you@')) {
                  const toPorter = recipient.includes('porter')
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'your-agent',
                    label: toPorter
                      ? 'Sent task.create to Porter'
                      : isFirstTurn
                        ? 'Sent task.create to Sunny Bakery'
                        : 'Forwarded your reply to Sunny Bakery',
                    status: 'complete',
                  })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'your-agent' })

                  if (toPorter) {
                    dispatch({ type: 'ACTIVATE_PORTER' })
                    dispatch({
                      type: 'ADD_THINKING_STEP',
                      agent: 'porter',
                      label: `Received task from ${sender}`,
                      status: 'active',
                    })
                  } else {
                    dispatch({
                      type: 'ADD_THINKING_STEP',
                      agent: 'bakery',
                      label: `Received task from ${sender}`,
                      status: 'active',
                    })
                  }
                }
              } else if (bt === 'task.acknowledge') {
                if (sender.includes('bakery') || sender.includes('sunny')) {
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'bakery',
                    label: 'Trust verified: VERIFIED',
                    status: 'complete',
                  })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'bakery',
                    label: 'Task acknowledged',
                    status: 'active',
                  })
                } else if (sender.includes('porter')) {
                  dispatch({ type: 'ACTIVATE_PORTER' })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'porter',
                    label: 'Trust verified: VERIFIED',
                    status: 'complete',
                  })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'porter',
                    label: 'Checking drivers nearby',
                    status: 'active',
                  })
                }
              } else if (bt === 'task.quote') {
                const body = p.data.body as Record<string, unknown> | undefined
                const price = body?.price || body?.amount || ''
                const sourceAgent = ((body?.source_agent as string) || '').toLowerCase()

                if (sender.includes('bakery') || sender.includes('sunny')) {
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'bakery',
                    label: `Quote prepared${price ? ` — ${price}` : ''}`,
                    status: 'complete',
                  })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                } else if (sender.includes('porter')) {
                  dispatch({ type: 'ACTIVATE_PORTER' })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'porter',
                    label: `Delivery quote prepared${price ? ` — ${price}` : ''}`,
                    status: 'complete',
                  })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'porter' })
                  // Render the CombinedQuote lang inside Porter window
                  const quoteLang =
                    (body?.quote as string) ||
                    (body?.message as string) ||
                    porterResponseRef.current
                  if (quoteLang && quoteLang.trim()) {
                    dispatch({
                      type: 'ADD_ENTRY',
                      entry: mkEntry('porter', 'chat', quoteLang, { role: 'agent' }),
                    })
                  }
                } else if (sender.includes('you@example.com') || sender.includes('you@')) {
                  const quoteLang =
                    (body?.quote as string) ||
                    (body?.message as string) ||
                    (sourceAgent.includes('porter')
                      ? porterResponseRef.current
                      : bakeryResponseRef.current)
                  if (quoteLang && quoteLang.trim()) {
                    dispatch({ type: 'COMPLETE_THINKING', agent: 'your-agent' })
                    dispatch({
                      type: 'ADD_ENTRY',
                      entry: mkEntry('your-agent', 'chat', quoteLang, { role: 'remote' }),
                    })
                  }
                  // After a quote, either agent can still receive replies
                  // (Change / Confirm go back to whichever quoted).
                  dispatch({
                    type: 'SET_AWAITING_AGENT',
                    agent: sourceAgent.includes('porter') ? 'porter' : 'bakery',
                  })
                }
              } else if (bt === 'task.input_required') {
                const body = p.data.body as Record<string, unknown> | undefined
                const prompt =
                  (body?.prompt as string) || (body?.message as string) || ''

                if (sender.includes('bakery') || sender.includes('sunny')) {
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'bakery',
                    label: 'Sent task.input_required',
                    status: 'complete',
                  })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                } else if (sender.includes('porter')) {
                  dispatch({ type: 'ACTIVATE_PORTER' })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'porter' })
                  dispatch({
                    type: 'ADD_THINKING_STEP',
                    agent: 'porter',
                    label: 'Sent task.input_required',
                    status: 'complete',
                  })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'porter' })
                  const lang = prompt || porterResponseRef.current
                  if (lang && lang.trim()) {
                    dispatch({
                      type: 'ADD_ENTRY',
                      entry: mkEntry('porter', 'chat', lang, { role: 'agent' }),
                    })
                  }
                } else if (sender.includes('you@example.com') || sender.includes('you@')) {
                  if (prompt) {
                    dispatch({ type: 'COMPLETE_THINKING', agent: 'your-agent' })
                    dispatch({
                      type: 'ADD_ENTRY',
                      entry: mkEntry('your-agent', 'chat', prompt, { role: 'remote' }),
                    })
                  }
                  // Mark which agent the next user message should route to.
                  const src = ((body?.source_agent as string) || '').toLowerCase()
                  dispatch({
                    type: 'SET_AWAITING_AGENT',
                    agent: src.includes('porter') ? 'porter' : 'bakery',
                  })
                }
              } else if (bt === 'task.progress' || bt === 'task.update') {
                const msg =
                  ((p.data.body as Record<string, unknown>)?.message as string) || ''
                if (sender.includes('bakery') || sender.includes('sunny')) {
                  if (msg) {
                    dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                    dispatch({
                      type: 'ADD_ENTRY',
                      entry: mkEntry('bakery', 'chat', msg, { role: 'agent' }),
                    })
                  }
                }
              } else if (bt === 'task.complete') {
                const body = p.data.body as Record<string, unknown> | undefined
                const result =
                  (body?.result as string) || (body?.message as string) || ''
                if (sender.includes('bakery') || sender.includes('sunny')) {
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                  dispatch({
                    type: 'ADD_ENTRY',
                    entry: mkEntry('bakery', 'chat', result || 'Order confirmed!', {
                      role: 'agent',
                    }),
                  })
                } else if (sender.includes('porter')) {
                  dispatch({ type: 'ACTIVATE_PORTER' })
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'porter' })
                  dispatch({
                    type: 'ADD_ENTRY',
                    entry: mkEntry('porter', 'chat', result || 'Delivery scheduled!', {
                      role: 'agent',
                    }),
                  })
                } else if (sender.includes('you@example.com') || sender.includes('you@')) {
                  dispatch({ type: 'COMPLETE_THINKING', agent: 'your-agent' })
                  dispatch({
                    type: 'ADD_ENTRY',
                    entry: mkEntry('your-agent', 'chat', result || 'Order confirmed!', {
                      role: 'remote',
                    }),
                  })
                  dispatch({ type: 'SET_AWAITING_AGENT', agent: null })
                }
              }
            } else if (p.type === 'status') {
              const step = (p.data as { step?: string }).step ?? ''
              const agent = (p.data as { agent?: string }).agent ?? ''

              if (agent.includes('you@example.com') || agent.includes('you')) {
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'your-agent',
                  label: step,
                  status: 'active',
                })
              } else if (agent.includes('bakery') || agent.includes('sunny')) {
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'bakery',
                  label: step,
                  status: 'active',
                })
              } else if (agent.includes('porter')) {
                dispatch({ type: 'ACTIVATE_PORTER' })
                dispatch({
                  type: 'ADD_THINKING_STEP',
                  agent: 'porter',
                  label: step,
                  status: 'active',
                })
              }
            } else if (p.type === 'stream') {
              const streamType = (p.data as { type?: string }).type
              if (streamType === 'text_delta') {
                const chunk = (p.data as { text?: string }).text ?? ''
                bakeryResponseRef.current += chunk
                dispatch({ type: 'COMPLETE_THINKING', agent: 'bakery' })
                dispatch({ type: 'APPEND_STREAM', agent: 'bakery', text: chunk })
              } else if (streamType === 'porter_text_delta') {
                const chunk = (p.data as { text?: string }).text ?? ''
                porterResponseRef.current += chunk
                dispatch({ type: 'ACTIVATE_PORTER' })
                dispatch({ type: 'COMPLETE_THINKING', agent: 'porter' })
                dispatch({ type: 'APPEND_STREAM', agent: 'porter', text: chunk })
              }
            } else if (p.type === 'options') {
              const opts = (p.data as { options?: string[] }).options ?? []
              dispatch({ type: 'SET_OPTIONS', options: opts })
            } else if (p.type === 'voice') {
              const d = p.data as {
                audio_b64?: string
                mime?: string
                speaker?: Speaker
                transcript?: string
              }
              if (d.audio_b64 && d.speaker) {
                enqueueVoiceClip({
                  speaker: d.speaker,
                  transcript: d.transcript ?? '',
                  audioB64: d.audio_b64,
                })
              }
            } else if (p.type === 'loop_turn') {
              const d = p.data as { turn?: number; max?: number }
              if (typeof d.turn === 'number' && typeof d.max === 'number') {
                setLoopProgress({ turn: d.turn, max: d.max })
              }
            } else if (p.type === 'awaiting_user_card' || p.type === 'awaiting_user_text') {
              // Autonomous loop paused — needs the user. The hand-off is
              // SILENT: YA did not speak. We surface the question (with
              // chips if structured, free text input otherwise) in chat
              // AND in the voice overlay. Either surface can answer; the
              // /api/amp-demo/resume endpoint re-enters the loop.
              const d = p.data as {
                decisionId?: string
                question?: string
                options?: string[]
                brief?: string
                history?: Array<{ role: string; content: string }>
              }
              if (d.decisionId && d.question && d.brief && d.history) {
                dispatch({
                  type: 'SET_PENDING_DECISION',
                  decision: {
                    id: d.decisionId,
                    question: d.question,
                    options: p.type === 'awaiting_user_card' ? d.options ?? [] : undefined,
                    brief: d.brief,
                    history: d.history,
                  },
                })
                setCallState('waiting_for_user')
              }
            } else if (p.type === 'loop_done') {
              const d = p.data as { summary?: string }
              setFinalSummary(d.summary ?? null)
              setCallState('done')
            } else if (p.type === 'done') {
              const doneData = p.data as { bakeryResponse?: string }
              const finalResponse = doneData.bakeryResponse || bakeryResponseRef.current
              dispatch({ type: 'FINALIZE_STREAM' })
              dispatch({
                type: 'DONE',
                bakeryResponse: finalResponse,
                userMessage: currentUserMsgRef.current,
              })
            }
          } catch {
            /* skip malformed */
          }
        }
      }
      reader.releaseLock()

      // If we never got a 'done' event, finalize anyway
      if (state.isStreaming) {
        dispatch({ type: 'FINALIZE_STREAM' })
        dispatch({
          type: 'DONE',
          bakeryResponse: bakeryResponseRef.current,
          userMessage: currentUserMsgRef.current,
        })
      }
    } catch (err) {
      dispatch({
        type: 'SET_ERROR',
        error: err instanceof Error ? err.message : 'Connection failed',
      })
    }
  }, [
    state.input,
    state.isStreaming,
    state.conversationHistory,
    state.turnCount,
    state.awaitingAgent,
    state.porterActive,
    enqueueVoiceClip,
  ])

  const handleSend = useCallback(() => {
    sendMessage()
  }, [sendMessage])

  const handleOptionClick = useCallback((opt: string) => {
    dispatch({ type: 'CLEAR_OPTIONS' })
    sendMessage(opt)
  }, [sendMessage])

  const handleRendererAction = useCallback((event: { action: string; formName?: string }) => {
    if (event.action && !state.isStreaming) {
      sendMessage(event.action)
    }
  }, [sendMessage, state.isStreaming])

  const handleMicError = useCallback(
    (msg: string) => dispatch({ type: 'SET_ERROR', error: msg }),
    [],
  )
  // In voice-call mode, the call-state machine transitions as the mic
  // is used. Listening starts → state goes 'listening'; mic release →
  // we flip to 'conversing' optimistically and wait for SSE events
  // (loop_done, awaiting_user) to push us out.
  const handleListeningStart = useCallback(() => {
    // Unlock the AudioContext under the user's mic-tap gesture. Once
    // unlocked, it stays unlocked for the page lifetime — every voice
    // clip from SSE plays without further gesture priming.
    unlockAudio()
    if (voiceUIMode) setCallState('listening')
  }, [voiceUIMode, unlockAudio])
  const handleListeningEnd = useCallback(() => {
    if (voiceUIMode) setCallState('conversing')
  }, [voiceUIMode])
  const mic = useMicCapture({
    isStreaming: state.isStreaming,
    awaitingAgent: state.awaitingAgent,
    sendMessage,
    onError: handleMicError,
    onListeningStart: handleListeningStart,
    onListeningEnd: handleListeningEnd,
  })

  /**
   * The user just answered a pendingDecision (chip tap or text reply).
   * POST to /api/amp-demo/resume with their answer + the conversation
   * history we stashed when the decision arrived. The SSE response is
   * the same shape as the autonomous loop — voice frames, loop_turn,
   * loop_done, awaiting_user_card/text. We feed each event back through
   * the existing handlers so all three surfaces stay in sync.
   */
  const handleAnswerDecision = useCallback(
    async (answer: string) => {
      const decision = state.pendingDecision
      if (!decision) return
      dispatch({ type: 'CLEAR_PENDING_DECISION' })
      // Show the user's answer in the chat thread so it isn't lost.
      dispatch({
        type: 'ADD_ENTRY',
        entry: mkEntry('your-agent', 'chat', answer, { role: 'user' }),
      })
      setCallState('conversing')
      try {
        const res = await fetch('/api/amp-demo/resume', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            answer,
            brief: decision.brief,
            history: (decision.history ?? []).slice(-MAX_HISTORY_SENT),
          }),
        })
        if (!res.ok) {
          const err = (await res.json().catch(() => ({}))) as { error?: string }
          dispatch({ type: 'SET_ERROR', error: err.error || `Resume failed (${res.status})` })
          return
        }
        if (!res.body) {
          dispatch({ type: 'SET_ERROR', error: 'Resume failed (empty response)' })
          return
        }
        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            const raw = line.slice(6).trim()
            if (!raw) continue
            try {
              const p = JSON.parse(raw) as { type: string; data: Record<string, unknown> }
              if (p.type === 'envelope') {
                dispatch({ type: 'ADD_ENVELOPE', data: p.data })
              } else if (p.type === 'voice') {
                const d = p.data as { audio_b64?: string; speaker?: Speaker; transcript?: string }
                if (d.audio_b64 && d.speaker) {
                  enqueueVoiceClip({
                    speaker: d.speaker,
                    transcript: d.transcript ?? '',
                    audioB64: d.audio_b64,
                  })
                }
              } else if (p.type === 'loop_turn') {
                const d = p.data as { turn?: number; max?: number }
                if (typeof d.turn === 'number' && typeof d.max === 'number') {
                  setLoopProgress({ turn: d.turn, max: d.max })
                }
              } else if (p.type === 'awaiting_user_card' || p.type === 'awaiting_user_text') {
                const d = p.data as {
                  decisionId?: string
                  question?: string
                  options?: string[]
                  brief?: string
                  history?: Array<{ role: string; content: string }>
                }
                if (d.decisionId && d.question && d.brief && d.history) {
                  dispatch({
                    type: 'SET_PENDING_DECISION',
                    decision: {
                      id: d.decisionId,
                      question: d.question,
                      options: p.type === 'awaiting_user_card' ? d.options ?? [] : undefined,
                      brief: d.brief,
                      history: d.history,
                    },
                  })
                  setCallState('waiting_for_user')
                }
              } else if (p.type === 'loop_done') {
                const d = p.data as { summary?: string }
                setFinalSummary(d.summary ?? null)
                setCallState('done')
              } else if (p.type === 'error') {
                const d = p.data as { message?: string }
                dispatch({ type: 'SET_ERROR', error: d.message ?? 'Resume error' })
              }
            } catch {
              /* skip malformed */
            }
          }
        }
      } catch (err) {
        dispatch({
          type: 'SET_ERROR',
          error: err instanceof Error ? err.message : 'Resume failed',
        })
      }
    },
    [state.pendingDecision, enqueueVoiceClip],
  )

  // Resetting the call state when entering / exiting voice mode keeps
  // the UI honest: no stale "done" summary from a previous session, no
  // stuck "conversing" indicator if the user backs out mid-call.
  useEffect(() => {
    if (voiceUIMode) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- reset call state on dependency change (voiceUIMode), guarded
      setCallState('idle')
      setFinalSummary(null)
      setLoopProgress(null)
      dispatch({ type: 'CLEAR_SPOKEN_LOG' })
      dispatch({ type: 'CLEAR_PENDING_DECISION' })
      setLastTranscript(null)
    }
  }, [voiceUIMode])

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col">
      {/* Header */}
      <div className="shrink-0 px-6 pt-7 pb-4">
        {isMachine ? (
          <>
            <h1
              style={{
                fontFamily: MONO,
                fontSize: '12px',
                letterSpacing: '0.22em',
                color: '#E8E4DC',
                textTransform: 'uppercase',
                fontWeight: 700,
              }}
            >
              AGENT MESH PROTOCOL&nbsp;//&nbsp;LIVE
            </h1>
            <p
              style={{
                marginTop: '8px',
                fontFamily: MONO,
                fontSize: '11px',
                color: 'rgba(232,228,220,0.55)',
                letterSpacing: '0.02em',
              }}
            >
              &gt; Two agents communicating across platforms via AMP — each in its own window.
            </p>
          </>
        ) : (
          <>
            <h1
              className="font-[family-name:var(--font-newsreader)] text-[21px] font-normal leading-[27.3px]"
              style={{ color: '#4A3A31' }}
            >
              Agent Mesh Protocol
            </h1>
            <p
              className="mt-[6px] max-w-lg font-sans text-[13px] font-normal leading-[19.5px]"
              style={{ color: '#78716C' }}
            >
              Watch two agents communicate across platforms via AMP — each in their own window.
            </p>
          </>
        )}
      </div>

      {/* Agent windows (chatbot floats via portal to document.body) */}
      <div className="px-6 pb-6">
        <motion.div
          layout
          className={cn(
            'grid h-[820px] grid-cols-1 gap-5',
            state.porterActive ? 'md:grid-cols-3' : 'md:grid-cols-2',
          )}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
        >
          <motion.div
            layout
            className="min-h-0 h-full"
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          >
            <AgentWindow
              title="Your Agent"
              address="agent://you@example.com"
              entries={state.yourAgentEntries}
              envelopes={state.envelopes}
              agentId="your-agent"
              onAction={handleRendererAction}
            />
          </motion.div>
          <motion.div
            layout
            className="min-h-0 h-full"
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          >
            <AgentWindow
              title="Sunny Bakery"
              address="agent://sunny-bakery.example"
              entries={state.bakeryEntries}
              envelopes={state.envelopes}
              agentId="bakery"
              onAction={handleRendererAction}
            />
          </motion.div>
          <AnimatePresence>
            {state.porterActive && (
              <motion.div
                key="porter-window"
                layout
                className="min-h-0 h-full"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
              >
                <AgentWindow
                  title="Porter"
                  address="agent://porter.example.com"
                  entries={state.porterEntries}
                  envelopes={state.envelopes}
                  agentId="porter"
                  onAction={handleRendererAction}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Bottom-right: either the chat widget OR the voice-call overlay.
            They never coexist — entering voice mode hides the widget so the
            orbs become the only surface the user interacts with. */}
        {voiceUIMode ? (
          <VoiceCallOverlay
            activeSpeaker={activeSpeaker}
            isRecording={mic.isRecording}
            isTranscribing={mic.isTranscribing}
            isStreaming={state.isStreaming}
            porterActive={state.porterActive}
            lastTranscript={lastTranscript}
            transcriptLog={state.spokenLog}
            pendingDecision={state.pendingDecision}
            callState={callState}
            loopProgress={loopProgress}
            finalSummary={finalSummary}
            onMicDown={() => mic.startRecording({ mode: 'autonomous' })}
            onMicUp={mic.stopRecording}
            onAnswerDecision={handleAnswerDecision}
            onExit={() => setSurface('chat')}
            onRestart={() => {
              setCallState('idle')
              setFinalSummary(null)
              setLoopProgress(null)
              setLastTranscript(null)
              dispatch({ type: 'RESET_ALL' })
            }}
          />
        ) : (
          <ChatbotWidget
            state={state}
            dispatch={dispatch}
            sendMessage={sendMessage}
            handleSend={handleSend}
            handleOptionClick={handleOptionClick}
            inputRef={inputRef}
            mic={mic}
            onEnterVoiceMode={() => setSurface('voice')}
            onAnswerDecision={handleAnswerDecision}
          />
        )}
      </div>

    </div>
  )
}
