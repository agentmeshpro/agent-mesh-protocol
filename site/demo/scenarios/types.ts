// AMP Demo — Scenario Types
// These types drive the simulated and live demo scenarios.

export type TrustTier = 'internal' | 'owner' | 'verified' | 'external'

export type BodyType =
  | 'task.create'
  | 'task.delegate'
  | 'task.progress'
  | 'task.complete'
  | 'task.error'
  | 'task.acknowledge'
  | 'message'
  | 'session.init'
  | 'session.established'
  | 'voice.utterance'

export type StreamEventType =
  | 'thinking'
  | 'tool_call'
  | 'tool_result'
  | 'text_delta'
  | 'done'
  | 'heartbeat'

export interface DemoMessage {
  id: string
  sender: string
  recipient: string
  bodyType: BodyType
  trustTier: TrustTier
  headers: Record<string, string>
  body: Record<string, unknown>
  timestamp: number
  summary: string
}

export interface DemoStreamEvent {
  type: StreamEventType
  data: Record<string, unknown>
  timestamp: number
}

export interface DemoStep {
  message: DemoMessage
  streamEvents?: DemoStreamEvent[]
  delayMs: number
}

export interface DemoStats {
  messagesExchanged: number
  trustTier: TrustTier
  delegationDepth: number
  totalTimeMs: number
  bodyTypesUsed: BodyType[]
  costUsd: number
}

export type DemoMode = 'simulation' | 'real'

export type DemoScenario = 'multi-step'

export type DemoState = 'idle' | 'running' | 'complete'
