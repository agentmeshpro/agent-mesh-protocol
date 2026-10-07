'use client'

import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'

export type AmpTheme = 'user' | 'machine'
export type AmpSurface = 'chat' | 'protocol' | 'voice'

interface AmpThemeContextValue {
  theme: AmpTheme
  setTheme: (t: AmpTheme) => void
  /**
   * True while the voice-call overlay is mounted. The page-level
   * FloatingThemeToggle reads this to hide its built-in toggle UI
   * (the inline header strip in the overlay takes over).
   */
  voiceCallActive: boolean
  setVoiceCallActive: (active: boolean) => void
  /**
   * Which of the three surfaces is currently selected by the three-way
   * switcher. `chat` and `protocol` correspond 1:1 with `theme`. `voice`
   * additionally opens the voice overlay (and pins theme to `chat` —
   * voice mode is themeless).
   */
  surface: AmpSurface
  setSurface: (s: AmpSurface) => void
}

const AmpThemeContext = createContext<AmpThemeContextValue | null>(null)

export function AmpThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<AmpTheme>('user')
  const setTheme = useCallback((next: AmpTheme) => setThemeState(next), [])
  const [voiceCallActive, setVoiceCallActiveState] = useState(false)
  const setVoiceCallActive = useCallback(
    (active: boolean) => setVoiceCallActiveState(active),
    [],
  )
  const [surface, setSurfaceState] = useState<AmpSurface>('chat')
  const setSurface = useCallback((s: AmpSurface) => {
    setSurfaceState(s)
    // Chat ↔ Protocol drive the existing theme. Voice is themeless and
    // pins theme to 'user' (warm) for the overlay's neutral aesthetic.
    if (s === 'chat') setThemeState('user')
    else if (s === 'protocol') setThemeState('machine')
    else if (s === 'voice') setThemeState('user')
  }, [])

  return (
    <AmpThemeContext.Provider
      value={{ theme, setTheme, voiceCallActive, setVoiceCallActive, surface, setSurface }}
    >
      {children}
    </AmpThemeContext.Provider>
  )
}

export function useAmpTheme(): AmpThemeContextValue {
  const ctx = useContext(AmpThemeContext)
  if (!ctx) throw new Error('useAmpTheme must be used inside <AmpThemeProvider>')
  return ctx
}
