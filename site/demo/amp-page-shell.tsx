'use client'

import { motion } from 'framer-motion'
import { SiteNav } from '@/components/site-nav'
import { BLOB } from '@/lib/site'
import { AmpDemoClient } from './amp-demo-client'
import { useAmpTheme } from './theme'

const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"

const EASE = [0.22, 1, 0.36, 1] as const
const SKIN_DUR = 0.55

/* ─────────────────────────────────────────────────────────────────────────
 * Chat / Protocol / Voice switch. These are three views of the same live
 * conversation, so they switch in place rather than navigating. Sticky
 * under the site nav so it never covers the demo or the chat dock.
 * ──────────────────────────────────────────────────────────────────────── */
function ViewToggle() {
  const { theme, voiceCallActive, surface, setSurface } = useAmpTheme()
  // The voice-call overlay has its own controls in its header strip.
  if (voiceCallActive) return null

  const isMachine = theme === 'machine'

  return (
    <div className="sticky top-[64px] z-20 flex justify-center px-4 pt-2 pb-3">
      <motion.div
        role="tablist"
        aria-label="Demo view"
        layout
        animate={{
          backgroundColor: isMachine
            ? 'rgba(26,26,26,0.88)'
            : 'rgba(255,255,255,0.88)',
          borderColor: isMachine
            ? 'rgba(232,228,220,0.2)'
            : 'rgba(231,229,228,0.7)',
          borderRadius: isMachine ? 4 : 9999,
          boxShadow: isMachine
            ? '0 12px 40px rgba(0,0,0,0.55)'
            : '0 8px 24px rgba(74, 58, 49, 0.12)',
          padding: isMachine ? 0 : 4,
        }}
        transition={{
          layout: { duration: 0.35, ease: EASE },
          duration: SKIN_DUR,
          ease: EASE,
        }}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          borderStyle: 'solid',
          borderWidth: '1px',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          fontFamily: isMachine ? MONO : undefined,
          overflow: 'hidden',
        }}
      >
        {(['chat', 'protocol', 'voice'] as const).map((s) => {
          const active = s === surface
          const label =
            s === 'chat' ? (isMachine ? 'CHAT' : 'Chat') :
            s === 'protocol' ? (isMachine ? 'PROTOCOL' : 'Protocol') :
            (isMachine ? 'VOICE' : 'Voice')
          return (
            <motion.button
              key={s}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setSurface(s)}
              className="relative"
              animate={{
                color: isMachine
                  ? active ? '#121212' : 'rgba(232,228,220,0.7)'
                  : active ? '#FFFFFF' : '#78716C',
                paddingTop: isMachine ? 8 : 6,
                paddingBottom: isMachine ? 8 : 6,
                paddingLeft: isMachine ? 16 : 14,
                paddingRight: isMachine ? 16 : 14,
                fontSize: isMachine ? 10 : 13,
                letterSpacing: isMachine ? '0.24em' : '0',
                borderRadius: isMachine ? 0 : 9999,
              }}
              transition={{ duration: SKIN_DUR, ease: EASE }}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontFamily: isMachine ? MONO : undefined,
                fontWeight: active ? 700 : 500,
                textTransform: isMachine ? 'uppercase' : 'none',
              }}
            >
              {active && (
                <motion.span
                  layoutId="view-toggle-active"
                  className="absolute inset-0"
                  style={{
                    background: '#C86948',
                    borderRadius: isMachine ? 0 : 9999,
                    boxShadow: isMachine
                      ? 'none'
                      : '0 1px 3px rgba(200, 105, 72, 0.35)',
                    zIndex: 0,
                  }}
                  transition={{ duration: 0.3, ease: EASE }}
                />
              )}
              <span style={{ position: 'relative', zIndex: 1 }}>{label}</span>
            </motion.button>
          )
        })}
      </motion.div>
    </div>
  )
}

function DemoNote({ isMachine }: { isMachine: boolean }) {
  return (
    <p
      className="mx-auto mt-3 max-w-3xl px-2 text-center"
      style={{
        fontSize: isMachine ? 10 : 12,
        lineHeight: 1.5,
        color: isMachine ? 'rgba(232,228,220,0.6)' : '#78716C',
        fontFamily: isMachine ? MONO : undefined,
      }}
    >
      The bakery and delivery agents are played by a language model. Envelopes use the AMP envelope
      shape and are signed with Ed25519 and checked in your browser, but with a simplified scheme
      (canonical JSON in X-Signature headers). Real AMP peers sign each HTTP request with the RFC 9421
      profile in{' '}
      <a
        href={`${BLOB}/docs/WIRE-BINDING.md`}
        target="_blank"
        rel="noopener noreferrer"
        style={{ color: '#C86948', textDecoration: 'underline', textUnderlineOffset: 3 }}
      >
        WIRE-BINDING §12.15
      </a>
      .
    </p>
  )
}

/* ─────────────────────────────────────────────────────────────────────────
 * Demo page shell — one persistent DOM tree whose skin morphs between the
 * Chat (warm) and Protocol (machine) views.
 * ──────────────────────────────────────────────────────────────────────── */
export function AmpPageShell() {
  const { theme } = useAmpTheme()
  const isMachine = theme === 'machine'

  return (
    <motion.div
      className="amp-root h-full overflow-y-auto"
      animate={{
        backgroundColor: isMachine ? '#121212' : '#FBFBFB',
        color: isMachine ? '#E8E4DC' : '#4A3A31',
      }}
      transition={{ duration: SKIN_DUR, ease: EASE }}
      style={{ fontFamily: isMachine ? MONO : undefined }}
    >
      {/* Global tween rule — every property of every nested element glides.
          Plain <style> (not styled-jsx) to avoid SSR class-hash mismatch. */}
      <style
        dangerouslySetInnerHTML={{
          __html: `
.amp-root,
.amp-root *:not(canvas):not(pre):not(.no-skin-transition) {
  transition:
    background-color 550ms cubic-bezier(0.22, 1, 0.36, 1),
    background 550ms cubic-bezier(0.22, 1, 0.36, 1),
    border-color 550ms cubic-bezier(0.22, 1, 0.36, 1),
    border-radius 450ms cubic-bezier(0.22, 1, 0.36, 1),
    color 420ms cubic-bezier(0.22, 1, 0.36, 1),
    fill 420ms cubic-bezier(0.22, 1, 0.36, 1),
    stroke 420ms cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 550ms cubic-bezier(0.22, 1, 0.36, 1),
    filter 550ms cubic-bezier(0.22, 1, 0.36, 1),
    opacity 420ms cubic-bezier(0.22, 1, 0.36, 1),
    font-family 450ms cubic-bezier(0.22, 1, 0.36, 1),
    font-size 450ms cubic-bezier(0.22, 1, 0.36, 1),
    font-weight 450ms cubic-bezier(0.22, 1, 0.36, 1),
    letter-spacing 450ms cubic-bezier(0.22, 1, 0.36, 1),
    line-height 450ms cubic-bezier(0.22, 1, 0.36, 1),
    padding 450ms cubic-bezier(0.22, 1, 0.36, 1),
    margin 450ms cubic-bezier(0.22, 1, 0.36, 1),
    gap 450ms cubic-bezier(0.22, 1, 0.36, 1),
    transform 550ms cubic-bezier(0.22, 1, 0.36, 1);
}
.amp-root button:not(:disabled):hover { opacity: 0.92; }
.amp-root button:not(:disabled):active { opacity: 0.82; }
`,
        }}
      />

      <SiteNav dark={isMachine} />

      <ViewToggle />

      {/* Bottom padding leaves room for the chat dock on phones. */}
      <section id="demo" className="mx-auto max-w-7xl px-4 pb-48 sm:px-6 sm:pb-16">
        <motion.div
          animate={{
            backgroundColor: isMachine ? '#1A1A1A' : 'rgba(255,255,255,0.7)',
            borderColor: isMachine
              ? 'rgba(232,228,220,0.12)'
              : 'rgba(231,229,228,0.6)',
            borderRadius: isMachine ? 6 : 22,
          }}
          transition={{ duration: SKIN_DUR, ease: EASE }}
          style={{
            overflow: 'hidden',
            borderStyle: 'solid',
            borderWidth: '1px',
            backdropFilter: isMachine ? undefined : 'blur(12px)',
          }}
        >
          <AmpDemoClient />
        </motion.div>
        <DemoNote isMachine={isMachine} />
      </section>
    </motion.div>
  )
}
