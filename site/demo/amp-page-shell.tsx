'use client'

import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { AmpDemoClient } from './amp-demo-client'
import { useAmpTheme } from './theme'
import { TicketVisual } from './components/ticket-visual'
import { DemoNote, INSTALL_CMD, LandingSections, REPO_URL } from './landing-sections'

const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"
const SERIF = "var(--font-newsreader), 'Newsreader', Georgia, serif"

const EASE = [0.22, 1, 0.36, 1] as const
const SKIN_DUR = 0.55

/* ─────────────────────────────────────────────────────────────────────────
 * Floating bottom-center toggle. Single DOM tree that morphs via animate.
 * ──────────────────────────────────────────────────────────────────────── */
function FloatingThemeToggle() {
  const { theme, voiceCallActive, surface, setSurface } = useAmpTheme()
  const [mounted, setMounted] = useState(false)

  // eslint-disable-next-line react-hooks/set-state-in-effect -- client-after-hydration flag
  useEffect(() => setMounted(true), [])
  if (!mounted) return null
  // The voice-call overlay has its own integrated controls in its
  // header strip. Hide the page-level floating toggle while that's up
  // so the two controls don't collide.
  if (voiceCallActive) return null

  const isMachine = theme === 'machine'

  return createPortal(
    <motion.div
      className="fixed left-1/2 z-50 -translate-x-1/2"
      style={{ bottom: '24px' }}
      initial={{ y: 30, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1], delay: 0.1 }}
    >
      <motion.div
        role="tablist"
        aria-label="View mode"
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
            : '0 12px 32px rgba(74, 58, 49, 0.18)',
          padding: isMachine ? 0 : 4,
        }}
        transition={{
          layout: { duration: 0.35, ease: [0.22, 1, 0.36, 1] },
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
                  layoutId="theme-toggle-active"
                  className="absolute inset-0"
                  style={{
                    background: '#C86948',
                    borderRadius: isMachine ? 0 : 9999,
                    boxShadow: isMachine
                      ? 'none'
                      : '0 1px 3px rgba(200, 105, 72, 0.35)',
                    zIndex: 0,
                  }}
                  transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                />
              )}
              <span style={{ position: 'relative', zIndex: 1 }}>{label}</span>
            </motion.button>
          )
        })}
      </motion.div>
    </motion.div>,
    document.body,
  )
}

/* ─────────────────────────────────────────────────────────────────────────
 * Page shell — one persistent DOM tree. Every container morphs.
 * Only the hero CONTENT crossfades because the two layouts are genuinely
 * different shapes (giant serif AMP vs ticket-stub split).
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

      {/* ── NAV ── morphs in place */}
      <nav
        className="grid items-center gap-4 px-4 sm:px-8"
        style={{
          gridTemplateColumns: '1fr auto 1fr',
          paddingTop: isMachine ? 20 : 24,
          paddingBottom: isMachine ? 20 : 24,
          borderBottom: isMachine
            ? '1px solid rgba(232,228,220,0.08)'
            : '1px solid transparent',
        }}
      >
        <span />
        <span
          className="text-center"
          style={{
            fontFamily: isMachine ? MONO : SERIF,
            fontSize: isMachine ? 12 : 18,
            letterSpacing: isMachine ? '0.48em' : '0.02em',
            color: isMachine ? '#E8E4DC' : '#4A3A31',
            textTransform: isMachine ? 'uppercase' : 'none',
            fontWeight: isMachine ? 700 : 400,
          }}
        >
          AMP
        </span>
        <div className="flex items-center justify-end gap-3 sm:gap-6">
          {(['Docs', 'Demo', 'GitHub'] as const).map((label) => (
            <a
              key={label}
              href={
                label === 'GitHub'
                  ? REPO_URL
                  : label === 'Docs'
                    ? '#docs'
                    : '#demo'
              }
              target={label === 'GitHub' ? '_blank' : undefined}
              rel={label === 'GitHub' ? 'noopener noreferrer' : undefined}
              style={{
                fontFamily: isMachine ? MONO : undefined,
                fontSize: isMachine ? 10 : 14,
                letterSpacing: isMachine ? '0.22em' : '0',
                color: isMachine ? 'rgba(232,228,220,0.7)' : '#78716C',
                textTransform: isMachine ? 'uppercase' : 'none',
              }}
            >
              {isMachine ? label.toUpperCase() : label}
            </a>
          ))}
        </div>
      </nav>

      {/* ── HERO ── two genuinely different layouts; crossfade *just* this */}
      <section
        className="px-8"
        style={{
          paddingTop: isMachine ? 40 : 48,
          paddingBottom: isMachine ? 24 : 32,
        }}
      >
        <div className="mx-auto" style={{ maxWidth: isMachine ? 1024 : 720 }}>
          <AnimatePresence mode="wait">
            {isMachine ? <MachineHero key="m-hero" /> : <UserHero key="u-hero" />}
          </AnimatePresence>
        </div>
      </section>

      {/* ── DEMO ── one persistent container, skin morphs */}
      <section id="demo" className="mx-auto max-w-7xl px-6 pt-6 pb-12">
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
        <DemoNote />
      </section>

      <LandingSections />

      {/* ── TAGLINE ── only renders in user mode (collapses smoothly) */}
      <motion.section
        className="px-8 overflow-hidden"
        animate={{
          height: isMachine ? 0 : 'auto',
          opacity: isMachine ? 0 : 1,
          paddingBottom: isMachine ? 0 : 64,
        }}
        transition={{ duration: SKIN_DUR, ease: EASE }}
      >
        <p
          className="mx-auto max-w-xl text-center"
          style={{
            fontFamily: SERIF,
            fontSize: 21,
            lineHeight: '27.3px',
            color: '#4A3A31',
          }}
        >
          An open protocol so your AI agents can talk to each other, over AMP, A2A, PACT and MCP.
        </p>
      </motion.section>

      {/* ── FOOTER ── morphs */}
      <footer
        className="py-6 text-center"
        style={{
          fontFamily: isMachine ? MONO : undefined,
          fontSize: isMachine ? 10 : 13,
          letterSpacing: isMachine ? '0.22em' : '0',
          color: isMachine ? 'rgba(232,228,220,0.4)' : '#A8A29E',
          textTransform: isMachine ? 'uppercase' : 'none',
          borderTop: isMachine
            ? '1px solid rgba(232,228,220,0.08)'
            : '1px solid #E7E5E4',
        }}
      >
        {isMachine
          ? 'AGENT MESH PROTOCOL // APACHE 2.0'
          : 'Agent Mesh Protocol — Apache 2.0'}
      </footer>

      <FloatingThemeToggle />
    </motion.div>
  )
}

/* ─────────────────────────────────────────────────────────────────────────
 * Hero — user variant: giant serif "AMP" + tagline + install pill + CTA
 * ──────────────────────────────────────────────────────────────────────── */
function UserHero() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.4, ease: EASE }}
      className="flex flex-col items-center"
    >
      <h1
        className="text-center"
        style={{
          fontFamily: SERIF,
          fontSize: 96,
          lineHeight: 1,
          letterSpacing: '-0.02em',
          color: '#4A3A31',
        }}
      >
        AMP
      </h1>
      <p
        className="mt-6 max-w-xl text-center"
        style={{
          fontFamily: SERIF,
          fontSize: 21,
          lineHeight: '27.3px',
          color: '#4A3A31',
        }}
      >
        An open protocol for agent-to-agent communication: trust, delegation and compliance
        built in, and interoperable with A2A, PACT and MCP.
      </p>
      <div
        className="mt-8 max-w-full px-4 py-[6px]"
        style={{
          backgroundColor: '#E7E5E4',
          color: '#57534E',
          borderRadius: 18,
        }}
      >
        <code
          style={{ fontFamily: MONO, fontSize: 12, fontWeight: 500, overflowWrap: 'anywhere' }}
        >
          {INSTALL_CMD}
        </code>
      </div>
      <p className="mt-3 text-center" style={{ fontSize: 13, color: '#78716C' }}>
        Release 0.4.0 · installs from GitHub (repository access required) ·{' '}
        <a href="#interop" style={{ color: '#C86948' }}>
          What&apos;s new
        </a>
      </p>
      <a
        href="#demo"
        className="mt-6 inline-flex items-center px-4 py-[10px]"
        style={{
          backgroundColor: '#C86948',
          color: '#FFFFFF',
          borderRadius: 9999,
          fontSize: 14,
          fontWeight: 500,
        }}
      >
        Try demo →
      </a>
    </motion.div>
  )
}

/* ─────────────────────────────────────────────────────────────────────────
 * Hero — machine variant: ticket stub with WebGL dot-field
 * ──────────────────────────────────────────────────────────────────────── */
function MachineHero() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.4, ease: EASE }}
      style={{
        position: 'relative',
        overflow: 'hidden',
        borderRadius: 6,
        border: '1px solid rgba(232,228,220,0.12)',
        backgroundColor: '#2A2A2A',
        display: 'flex',
        flexDirection: 'row',
        minHeight: 320,
      }}
    >
      <div
        style={{
          flex: '1 1 50%',
          position: 'relative',
          borderRight: '1px solid rgba(232,228,220,0.1)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            top: '1.5rem',
            left: '1.5rem',
            fontSize: '0.7rem',
            lineHeight: 1.4,
            letterSpacing: '2px',
            opacity: 0.85,
            zIndex: 10,
            color: '#E8E4DC',
            pointerEvents: 'none',
            fontFamily: MONO,
          }}
        >
          <span style={{ display: 'block' }}>A G E N T &nbsp; M E S H</span>
          <span style={{ display: 'block', paddingLeft: '1.5rem' }}>P R O T O C O L</span>
          <span
            style={{
              display: 'block',
              paddingLeft: '0.5rem',
              marginTop: '8px',
              fontSize: '0.6rem',
              opacity: 0.5,
            }}
          >
            O P E N &nbsp; P R O T O C O L
          </span>
        </div>
        <TicketVisual />
      </div>

      <div
        style={{
          flex: '1 1 50%',
          padding: '2rem 1.5rem 1.5rem 1.5rem',
          display: 'flex',
          flexDirection: 'column',
          fontSize: '0.75rem',
          lineHeight: 1.2,
          color: '#E8E4DC',
          fontFamily: MONO,
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '80px 20px 1fr',
            rowGap: '6px',
          }}
        >
          {[
            ['TYPE', 'OPEN PROTOCOL'],
            ['TRANSPORT', 'HTTP + SSE'],
            ['INTEROP', 'A2A 1.0 / PACT / MCP'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'contents' }}>
              <div style={{ opacity: 0.55, textTransform: 'uppercase' }}>{k}</div>
              <div style={{ opacity: 0.4 }}>&gt;</div>
              <div style={{ opacity: 0.9, textTransform: 'uppercase' }}>{v}</div>
            </div>
          ))}
          <div style={{ height: '8px', gridColumn: '1 / -1' }} />
          {[
            ['RELEASE', 'v0.4.0'],
            ['PROTOCOL', '1.0.0'],
            ['LICENSE', 'APACHE 2.0'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'contents' }}>
              <div style={{ opacity: 0.55, textTransform: 'uppercase' }}>{k}</div>
              <div style={{ opacity: 0.4 }}>&gt;</div>
              <div style={{ opacity: 0.9, textTransform: 'uppercase' }}>{v}</div>
            </div>
          ))}
          <div style={{ opacity: 0.55, textTransform: 'uppercase' }}>INSTALL</div>
          <div style={{ opacity: 0.4 }}>&gt;</div>
          <div style={{ opacity: 0.9, overflowWrap: 'anywhere' }}>{INSTALL_CMD}</div>
        </div>

        <div
          style={{
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            lineHeight: 1,
            margin: '1.2rem 0',
            letterSpacing: '1px',
            opacity: 0.2,
            fontSize: '0.7rem',
          }}
        >
          {'L'.repeat(60)}
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '80px 20px 1fr',
            rowGap: '6px',
          }}
        >
          {[
            ['AGENT 01', 'YOU@EXAMPLE.COM'],
            ['AGENT 02', 'SUNNY-BAKERY.EXAMPLE'],
            ['AGENT 03', 'PORTER.EXAMPLE.COM'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'contents' }}>
              <div style={{ opacity: 0.55, textTransform: 'uppercase' }}>{k}</div>
              <div style={{ opacity: 0.4 }}>&gt;</div>
              <div style={{ opacity: 0.9, textTransform: 'uppercase' }}>{v}</div>
            </div>
          ))}
        </div>

        <div
          style={{
            marginTop: 'auto',
            borderTop: '1px solid rgba(232,228,220,0.15)',
            paddingTop: '1rem',
            fontSize: '0.65rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: '4px',
              textTransform: 'uppercase',
            }}
          >
            <span>
              AMP
              <span
                style={{
                  display: 'inline-block',
                  width: '4px',
                  height: '4px',
                  backgroundColor: '#E8E4DC',
                  margin: '0 8px',
                  verticalAlign: '2px',
                  opacity: 0.5,
                }}
              />
              LIVE DEMO
            </span>
            <a
              href="#demo"
              style={{
                color: '#C86948',
                letterSpacing: '0.16em',
                textTransform: 'uppercase',
              }}
            >
              [ RUN ]
            </a>
          </div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              opacity: 0.4,
              textTransform: 'uppercase',
            }}
          >
            <span>ID: 0029384-A</span>
            <span>VALID ON ENTRY ONLY</span>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
