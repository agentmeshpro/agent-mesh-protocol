'use client'

import { useState } from 'react'
import { MONO } from '@/lib/site'

export function CopyButton({ text, dark = true }: { text: string; dark?: boolean }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          // Clipboard can be blocked (insecure context, permissions); the text stays selectable.
        }
      }}
      aria-label="Copy to clipboard"
      style={{
        fontFamily: MONO,
        fontSize: 10,
        letterSpacing: '0.16em',
        textTransform: 'uppercase',
        color: dark ? 'rgba(232,228,220,0.7)' : '#78716C',
        border: `1px solid ${dark ? 'rgba(232,228,220,0.2)' : '#D6D3D1'}`,
        borderRadius: 6,
        padding: '3px 8px',
        background: 'transparent',
        cursor: 'pointer',
        flexShrink: 0,
      }}
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}
