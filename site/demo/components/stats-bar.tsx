'use client'

import type { DemoStats } from '../scenarios/types'

interface StatsBarProps {
  stats: DemoStats
}

export function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="flex items-center gap-6 border-t border-white/10 bg-white/[0.02] px-4 py-2 font-mono text-xs">
      <span className="text-[oklch(var(--muted-foreground))]">
        Messages: <span className="text-[oklch(var(--foreground))]">{stats.messagesExchanged}</span>
      </span>

      <span className="text-[oklch(var(--muted-foreground))]">
        Trust: <span className="text-amber-400">{stats.trustTier}</span>
      </span>

      <span className="text-[oklch(var(--muted-foreground))]">
        Delegation depth: <span className="text-[oklch(var(--foreground))]">{stats.delegationDepth}</span>
      </span>

      <span className="text-[oklch(var(--muted-foreground))]">
        Time: <span className="text-[oklch(var(--foreground))]">{(stats.totalTimeMs / 1000).toFixed(1)}s</span>
      </span>

      <span className="text-[oklch(var(--muted-foreground))]">
        Cost: <span className="text-green-400">${stats.costUsd.toFixed(2)}</span>
      </span>

      {stats.bodyTypesUsed.length > 0 && (
        <span className="flex items-center gap-1.5 text-[oklch(var(--muted-foreground))]">
          Types:
          {stats.bodyTypesUsed.map((type) => (
            <span
              key={type}
              className="rounded-full bg-white/10 px-2 py-0.5 text-[oklch(var(--foreground))]"
            >
              {type}
            </span>
          ))}
        </span>
      )}
    </div>
  )
}
