// AMP Demo — Multi-Step Research Scenario
// An 8-step demonstration of AMP protocol features:
// discovery, task creation, delegation, streaming progress, and cost tracking.

import type { DemoStep } from './types'

const AGENTS = {
  client: 'agent://client.example.com',
  helper: 'agent://helper.example.com',
  researcher: 'agent://researcher.example.com',
} as const

const TRACE_ID = 'trace-demo-7f3a9c2e'

export const multiStepScenario: DemoStep[] = [
  // ── Step 1: Discovery ──────────────────────────────────────────────
  {
    message: {
      id: 'msg-001',
      sender: AGENTS.client,
      recipient: AGENTS.helper,
      bodyType: 'message',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-001',
        'Nonce': 'n-a1b2c3d4',
        'Priority': 'normal',
      },
      body: {
        content:
          'I need a comparative analysis of AI agent protocols — specifically AMP, A2A, and MCP. Focus on trust models, delegation patterns, and streaming capabilities.',
      },
      timestamp: Date.now(),
      summary:
        'Client requests research on AI agent protocols (AMP, A2A, MCP)',
    },
    delayMs: 500,
  },

  // ── Step 2: Task Creation ──────────────────────────────────────────
  {
    message: {
      id: 'msg-002',
      sender: AGENTS.helper,
      recipient: AGENTS.helper,
      bodyType: 'task.create',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-002',
        'In-Reply-To': 'msg-001',
        'Nonce': 'n-e5f6g7h8',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01',
        title: 'Compare AI agent protocols: AMP vs A2A vs MCP',
        description:
          'Produce a structured comparison covering trust tiers, delegation chains, streaming support, and cost-tracking mechanisms across the three protocols.',
        requester: AGENTS.client,
      },
      timestamp: Date.now(),
      summary: 'Helper creates internal task for protocol research',
    },
    delayMs: 800,
  },

  // ── Step 3: Acknowledgement ────────────────────────────────────────
  {
    message: {
      id: 'msg-003',
      sender: AGENTS.helper,
      recipient: AGENTS.client,
      bodyType: 'task.acknowledge',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-003',
        'In-Reply-To': 'msg-001',
        'Nonce': 'n-i9j0k1l2',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01',
        status: 'accepted',
        estimatedDurationMs: 6000,
        note: 'Accepted. I will delegate deep research to a specialist agent and synthesise the results.',
      },
      timestamp: Date.now(),
      summary: 'Helper acknowledges task and estimates ~6 s',
    },
    delayMs: 400,
  },

  // ── Step 4: Delegation ─────────────────────────────────────────────
  {
    message: {
      id: 'msg-004',
      sender: AGENTS.helper,
      recipient: AGENTS.researcher,
      bodyType: 'task.delegate',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-004',
        'Delegation-Depth': '1',
        'Chain-Budget': 'remaining=4.50USD;max=5.00USD',
        'Visited-Agents': `${AGENTS.client},${AGENTS.helper}`,
        'In-Reply-To': 'msg-002',
        'Nonce': 'n-m3n4o5p6',
        'Priority': 'normal',
      },
      body: {
        parentTaskId: 'task-research-01',
        delegatedTaskId: 'task-research-01-sub',
        instruction:
          'Search the web for the latest documentation on AMP (Agent Mesh Protocol), Google A2A, and Anthropic MCP. Compare trust models, delegation mechanisms, and streaming approaches.',
        scopes: ['web_search', 'read_documents'],
        maxBudgetUsd: 4.5,
        maxDepth: 2,
      },
      timestamp: Date.now(),
      summary:
        'Helper delegates deep research to Researcher (budget $4.50, scopes: web_search, read_documents)',
    },
    delayMs: 600,
  },

  // ── Step 5: Progress 30 % with stream events ──────────────────────
  {
    message: {
      id: 'msg-005',
      sender: AGENTS.researcher,
      recipient: AGENTS.helper,
      bodyType: 'task.progress',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-005',
        'Delegation-Depth': '1',
        'In-Reply-To': 'msg-004',
        'Nonce': 'n-q7r8s9t0',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01-sub',
        progressPct: 30,
        note: 'Searching the web for protocol specifications and comparison articles.',
      },
      timestamp: Date.now(),
      summary: 'Researcher reports 30 % — searching the web',
    },
    streamEvents: [
      {
        type: 'thinking',
        data: {
          content:
            'I need to compare AMP, A2A, and MCP across trust, delegation, and streaming. Let me start with a web search for the latest specs.',
        },
        timestamp: Date.now(),
      },
      {
        type: 'tool_call',
        data: {
          tool: 'web_search',
          input: {
            query:
              'AMP Agent Mesh Protocol vs Google A2A vs Anthropic MCP comparison 2026',
          },
        },
        timestamp: Date.now() + 200,
      },
      {
        type: 'tool_result',
        data: {
          tool: 'web_search',
          output: {
            results: [
              'Agent Mesh Protocol (AMP) v0.2 — trust tiers, delegation chains, cost receipts',
              'Google A2A — Agent-to-Agent protocol, AgentCard discovery, task lifecycle',
              'Anthropic MCP — Model Context Protocol, tool servers, resource subscriptions',
            ],
          },
        },
        timestamp: Date.now() + 800,
      },
      {
        type: 'text_delta',
        data: {
          delta:
            'AMP distinguishes four trust tiers (internal → owner → verified → external) enforced per-hop. A2A uses opaque bearer tokens with optional OAuth2. MCP relies on the host application for authentication.',
        },
        timestamp: Date.now() + 1000,
      },
    ],
    delayMs: 1000,
  },

  // ── Step 6: Progress 80 % with text deltas ─────────────────────────
  {
    message: {
      id: 'msg-006',
      sender: AGENTS.researcher,
      recipient: AGENTS.helper,
      bodyType: 'task.progress',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-006',
        'Delegation-Depth': '1',
        'In-Reply-To': 'msg-004',
        'Nonce': 'n-u1v2w3x4',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01-sub',
        progressPct: 80,
        note: 'Synthesising findings into a structured comparison.',
      },
      timestamp: Date.now(),
      summary: 'Researcher reports 80 % — synthesising comparison',
    },
    streamEvents: [
      {
        type: 'text_delta',
        data: {
          delta:
            'Delegation: AMP supports multi-hop delegation with chain budgets and visited-agent loops detection. A2A allows task delegation but without built-in budget controls. MCP does not model delegation — it is a client-server tool protocol.',
        },
        timestamp: Date.now(),
      },
      {
        type: 'text_delta',
        data: {
          delta:
            'Streaming: AMP defines SSE-based streaming with typed events (thinking, tool_call, tool_result, text_delta, done, heartbeat). A2A supports streaming via SSE with sendSubscribe. MCP uses JSON-RPC notifications for progress but lacks a first-class streaming primitive.',
        },
        timestamp: Date.now() + 400,
      },
      {
        type: 'text_delta',
        data: {
          delta:
            'Cost tracking: AMP propagates cost receipts up the delegation chain with chain-budget headers. Neither A2A nor MCP include cost-tracking mechanisms in their wire protocol.',
        },
        timestamp: Date.now() + 800,
      },
    ],
    delayMs: 2000,
  },

  // ── Step 7: Researcher completes with cost receipt ─────────────────
  {
    message: {
      id: 'msg-007',
      sender: AGENTS.researcher,
      recipient: AGENTS.helper,
      bodyType: 'task.complete',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-007',
        'Delegation-Depth': '1',
        'In-Reply-To': 'msg-004',
        'Nonce': 'n-y5z6a7b8',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01-sub',
        status: 'completed',
        result: {
          comparison: {
            AMP: {
              trustModel: '4-tier (internal, owner, verified, external) — enforced per hop',
              delegation: 'Multi-hop with chain budgets, visited-agent loop detection, scoped permissions',
              streaming: 'SSE with typed events: thinking, tool_call, tool_result, text_delta, done, heartbeat',
              costTracking: 'Built-in cost receipts propagated up delegation chain',
            },
            A2A: {
              trustModel: 'Bearer tokens with optional OAuth2 via AgentCard',
              delegation: 'Task delegation via sendSubscribe — no budget controls',
              streaming: 'SSE-based streaming with task status updates',
              costTracking: 'Not included in wire protocol',
            },
            MCP: {
              trustModel: 'Delegated to host application — no wire-level trust',
              delegation: 'Not modelled — client-server tool protocol only',
              streaming: 'JSON-RPC notifications for progress — no first-class streaming',
              costTracking: 'Not included in wire protocol',
            },
          },
          verdict:
            'AMP provides the most comprehensive agent-to-agent framework with built-in trust, delegation, streaming, and cost tracking. A2A covers discovery and task lifecycle well but lacks budget controls. MCP excels as a tool-integration protocol but is not designed for peer agent communication.',
        },
        costReceipt: {
          agentId: AGENTS.researcher,
          costUsd: 0.02,
          breakdown: {
            llmTokens: 0.015,
            toolCalls: 0.005,
          },
        },
      },
      timestamp: Date.now(),
      summary:
        'Researcher completes with structured comparison and cost receipt ($0.02)',
    },
    delayMs: 1500,
  },

  // ── Step 8: Helper completes to client ─────────────────────────────
  {
    message: {
      id: 'msg-008',
      sender: AGENTS.helper,
      recipient: AGENTS.client,
      bodyType: 'task.complete',
      trustTier: 'verified',
      headers: {
        'Protocol-Version': '0.2',
        'Trust-Tier': 'verified',
        'Trace-Id': TRACE_ID,
        'Span-Id': 'span-008',
        'Delegation-Depth': '0',
        'In-Reply-To': 'msg-001',
        'Nonce': 'n-c9d0e1f2',
        'Priority': 'normal',
      },
      body: {
        taskId: 'task-research-01',
        status: 'completed',
        summary:
          'AMP leads in trust, delegation, and cost tracking. A2A is strong on discovery and task lifecycle. MCP is best for tool integration but not peer-to-peer agent communication. See the full structured comparison in the result payload.',
        costReceipt: {
          agentId: AGENTS.helper,
          costUsd: 0.03,
          breakdown: {
            self: 0.01,
            delegated: 0.02,
          },
        },
      },
      timestamp: Date.now(),
      summary:
        'Helper delivers final result to Client with total cost receipt ($0.03)',
    },
    delayMs: 500,
  },
]
