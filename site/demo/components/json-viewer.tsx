'use client'

import type { DemoMessage } from '../scenarios/types'

interface JsonViewerProps {
  message: DemoMessage | null
}

function highlightJson(json: string): string {
  return json
    // Keys (quoted strings before a colon)
    .replace(
      /("[\w\-.]+")\s*:/g,
      '<span style="color:#60a5fa">$1</span>:',
    )
    // String values (quoted strings NOT before a colon)
    .replace(
      /:\s*("(?:[^"\\]|\\.)*")/g,
      (match, value) => match.replace(value, `<span style="color:#4ade80">${value}</span>`),
    )
    // Numbers
    .replace(
      /:\s*(-?\d+\.?\d*)/g,
      (match, num) => match.replace(num, `<span style="color:#fbbf24">${num}</span>`),
    )
    // Booleans and null
    .replace(
      /:\s*(true|false|null)\b/g,
      (match, val) => match.replace(val, `<span style="color:#c084fc">${val}</span>`),
    )
}

export function JsonViewer({ message }: JsonViewerProps) {
  if (!message) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg bg-[#06060a] p-6">
        <p className="text-sm text-[oklch(var(--muted-foreground))]">
          Select a message to view its AMP envelope
        </p>
      </div>
    )
  }

  const envelope = {
    sender: message.sender,
    recipient: message.recipient,
    id: message.id,
    body_type: message.bodyType,
    headers: message.headers,
    body: message.body,
  }

  const raw = JSON.stringify(envelope, null, 2)
  const highlighted = highlightJson(raw)

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-lg bg-[#06060a]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2">
        <span className="text-sm font-semibold text-white/90">AMP Envelope</span>
        <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs font-medium text-white/70">
          {message.bodyType}
        </span>
      </div>

      {/* JSON Body */}
      <div className="flex-1 overflow-auto p-4">
        <pre
          className="font-mono text-sm leading-relaxed text-white/80"
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </div>
    </div>
  )
}
