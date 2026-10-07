'use client'

import dynamic from 'next/dynamic'
import { AmpThemeProvider } from './theme'

/**
 * Client-only mount for the entire AMP demo. The shell uses framer-motion
 * `animate` props whose computed values diverge between SSR and the client
 * first paint (color tokens, font-family stacks resolved against CSS vars
 * that don't exist server-side, etc.). Rendering the shell client-only
 * eliminates that whole class of hydration mismatches.
 */
const AmpPageShell = dynamic(
  () => import('./amp-page-shell').then((m) => m.AmpPageShell),
  {
    ssr: false,
    loading: () => (
      <div
        style={{
          height: '100%',
          width: '100%',
          backgroundColor: '#FBFBFB',
        }}
      />
    ),
  },
)

export function AmpClientRoot() {
  return (
    <AmpThemeProvider>
      <AmpPageShell />
    </AmpThemeProvider>
  )
}
