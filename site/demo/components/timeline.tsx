'use client'

import { useEffect, useRef } from 'react'
import type { DemoMessage, DemoStreamEvent } from '../scenarios/types'
import { MessageCard } from './message-card'

interface TimelineProps {
  messages: DemoMessage[]
  streamEventsMap: Record<string, DemoStreamEvent[]>
  selectedMessageId: string | null
  onSelectMessage: (id: string) => void
}

export function Timeline({
  messages,
  streamEventsMap,
  selectedMessageId,
  onSelectMessage,
}: TimelineProps) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  if (messages.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-[oklch(var(--muted-foreground))]">
          Press Run Demo to start
        </p>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col overflow-y-auto scrollbar-thin">
      <div className="flex flex-col gap-3 p-4">
        {messages.map((message) => (
          <MessageCard
            key={message.id}
            message={message}
            streamEvents={streamEventsMap[message.id] ?? []}
            isSelected={message.id === selectedMessageId}
            onSelect={() => onSelectMessage(message.id)}
          />
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
