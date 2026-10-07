'use client'

/**
 * A single envelope row in Protocol view — redacted by default,
 * reveals body only on press-and-hold or when pinned via shift-click.
 *
 * Shows a real trust pill driven by Web Crypto Ed25519 verification
 * against the /api/amp-demo/keys directory. Nothing about the pill is
 * mocked — if signature verification fails (tampering, wrong key,
 * missing header) the pill turns red and the reason is shown.
 *
 * The signature scheme itself is a simplified illustration (Ed25519 over
 * canonical JSON in X-Signature headers), not AMP's RFC 9421 profile;
 * the SIG row and the body header say so. See trust/envelope-crypto.ts.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTrustVerification } from '../trust/use-trust-verification'
import type { TrustState } from '../trust/envelope-crypto'

const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"

const PRESS_HOLD_MS = 250

interface Props {
  envelope: {
    sender: string
    recipient: string
    id: string
    body_type: string
    headers: Record<string, string>
    body: Record<string, unknown>
  }
  isMachine: boolean
}

/**
 * Abbreviate an agent URL so it leaks less on screen.
 *   agent://you@example.com    -> you@…
 *   agent://sunny-bakery.example.com -> sunny…
 */
function abbreviate(url: string): string {
  const stripped = url.replace(/^agent:\/\//, '')
  const at = stripped.indexOf('@')
  if (at > 0) {
    const local = stripped.slice(0, at)
    return `${local}@…`
  }
  const head = (stripped.split('.')[0] ?? stripped).slice(0, 8)
  return `${head}…`
}

function approxSize(envelope: Props['envelope']): string {
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(envelope.body)).length
    if (bytes < 1024) return `${bytes} B`
    return `${(bytes / 1024).toFixed(1)} KB`
  } catch {
    return '—'
  }
}

function bodyFieldCount(envelope: Props['envelope']): number {
  return Object.keys(envelope.body || {}).length
}

function headerCount(envelope: Props['envelope']): number {
  return Object.keys(envelope.headers || {}).length
}

function signedHeaderCount(envelope: Props['envelope']): number {
  return Object.keys(envelope.headers || {}).filter((k) =>
    k.startsWith('X-Signature') || k === 'X-Signer-Key' || k === 'X-Signed-At',
  ).length
}

function TrustPill({
  state,
  reason,
  isMachine,
}: {
  state: TrustState
  reason?: string
  isMachine: boolean
}) {
  const label =
    state === 'valid'
      ? 'VERIFIED'
      : state === 'invalid'
        ? 'INVALID'
        : state === 'unsigned'
          ? 'UNSIGNED'
          : 'CHECKING'

  const color =
    state === 'valid'
      ? '#8BB58A'
      : state === 'invalid'
        ? '#E06A5C'
        : state === 'unsigned'
          ? '#C99C55'
          : 'rgba(232,228,220,0.5)'

  const bgAlpha =
    state === 'valid'
      ? 'rgba(139,181,138,0.12)'
      : state === 'invalid'
        ? 'rgba(224,106,92,0.12)'
        : state === 'unsigned'
          ? 'rgba(201,156,85,0.12)'
          : 'rgba(232,228,220,0.05)'

  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.92 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.25 }}
      title={
        reason ??
        'Ed25519 signature checked in your browser. Simplified demo scheme, not the RFC 9421 profile.'
      }
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '2px 8px',
        border: `1px solid ${color}`,
        backgroundColor: isMachine ? bgAlpha : 'rgba(255,255,255,0.5)',
        color,
        borderRadius: isMachine ? 3 : 9999,
        fontFamily: MONO,
        fontSize: 10,
        letterSpacing: '0.16em',
        fontWeight: 700,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: 9999,
          backgroundColor: color,
          boxShadow: state === 'valid' ? `0 0 6px ${color}` : 'none',
        }}
      />
      {label}
    </motion.span>
  )
}

function LabelRow({
  label,
  value,
  valueColor,
  isMachine,
}: {
  label: string
  value: React.ReactNode
  valueColor?: string
  isMachine: boolean
}) {
  return (
    <>
      <div
        style={{
          color: isMachine ? 'rgba(232,228,220,0.55)' : '#78716C',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: isMachine ? 'rgba(232,228,220,0.25)' : '#C7C5C4',
        }}
      >
        &gt;
      </div>
      <div
        style={{
          color: valueColor ?? (isMachine ? '#E8E4DC' : '#3C3A36'),
        }}
      >
        {value}
      </div>
    </>
  )
}

export function ProtocolEnvelope({ envelope, isMachine }: Props) {
  const trust = useTrustVerification(envelope)
  const [revealed, setRevealed] = useState(false)
  const [pinned, setPinned] = useState(false)
  const holdTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearHoldTimer = useCallback(() => {
    if (holdTimer.current) {
      clearTimeout(holdTimer.current)
      holdTimer.current = null
    }
  }, [])

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if (e.shiftKey) {
        setPinned((p) => !p)
        return
      }
      clearHoldTimer()
      holdTimer.current = setTimeout(() => {
        setRevealed(true)
      }, PRESS_HOLD_MS)
    },
    [clearHoldTimer],
  )

  const onPointerUp = useCallback(() => {
    clearHoldTimer()
    setRevealed(false)
  }, [clearHoldTimer])

  const onPointerLeave = useCallback(() => {
    clearHoldTimer()
    setRevealed(false)
  }, [clearHoldTimer])

  useEffect(() => () => clearHoldTimer(), [clearHoldTimer])

  const bodyVisible = revealed || pinned
  const verb = envelope.body_type
  const from = abbreviate(envelope.sender)
  const to = abbreviate(envelope.recipient)
  const size = approxSize(envelope)
  const bodyFields = bodyFieldCount(envelope)
  const sigFields = signedHeaderCount(envelope)
  const totalHeaders = headerCount(envelope)

  const rootStyle = isMachine
    ? {
        marginBottom: '10px',
        padding: '10px 12px',
        backgroundColor: bodyVisible ? '#201A18' : '#1A1A1A',
        border: `1px solid ${
          trust.state === 'invalid'
            ? 'rgba(224,106,92,0.5)'
            : bodyVisible
              ? 'rgba(200,105,72,0.35)'
              : 'rgba(232,228,220,0.12)'
        }`,
        borderRadius: '3px',
        fontFamily: MONO,
        transition: 'background-color 300ms ease, border-color 300ms ease',
      }
    : {
        marginBottom: '10px',
        padding: '10px 12px',
        backgroundColor: bodyVisible ? '#FFF4EE' : 'rgba(255,255,255,0.6)',
        border: `1px solid ${
          trust.state === 'invalid'
            ? 'rgba(224,106,92,0.5)'
            : bodyVisible
              ? 'rgba(200,105,72,0.35)'
              : 'rgba(231,229,228,0.7)'
        }`,
        borderRadius: '6px',
        fontFamily: MONO,
        transition: 'background-color 300ms ease, border-color 300ms ease',
      }

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      style={rootStyle}
    >
      {/* Header grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '78px 18px 1fr auto',
          rowGap: '4px',
          alignItems: 'center',
          fontSize: '10px',
          letterSpacing: '0.04em',
        }}
      >
        <LabelRow
          label="VERB"
          value={<span style={{ color: '#C86948' }}>{verb}</span>}
          isMachine={isMachine}
        />
        <div style={{ gridColumn: 4, justifySelf: 'end' }}>
          <TrustPill state={trust.state} reason={trust.reason} isMachine={isMachine} />
        </div>

        <LabelRow label="FROM" value={from} isMachine={isMachine} />
        <div />
        <LabelRow label="TO" value={to} isMachine={isMachine} />
        <div />
        <LabelRow
          label="SIZE"
          value={`${size} · ${bodyFields} field${bodyFields === 1 ? '' : 's'}`}
          isMachine={isMachine}
        />
        <div />
        <LabelRow
          label="HEADERS"
          value={`${totalHeaders} · ${sigFields} signature`}
          isMachine={isMachine}
        />
        <div />
        <LabelRow
          label="SIG"
          value={
            <span title="The demo signs canonical JSON with Ed25519. Real AMP peers sign the HTTP request with the RFC 9421 profile (WIRE-BINDING §12.15).">
              Ed25519 · simplified demo scheme
            </span>
          }
          isMachine={isMachine}
        />
        <div />
        {trust.signerFingerprint && (
          <>
            <LabelRow
              label="KEY"
              value={
                <span style={{ letterSpacing: '0.04em' }}>
                  {trust.signerFingerprint}
                  {trust.signerKeyMatchesDirectory === false && (
                    <span
                      style={{
                        marginLeft: 6,
                        color: '#E06A5C',
                        fontSize: 9,
                        letterSpacing: '0.16em',
                      }}
                    >
                      ≠ {trust.expectedFingerprint}
                    </span>
                  )}
                </span>
              }
              isMachine={isMachine}
            />
            <div />
          </>
        )}
      </div>

      {/* Inspect affordance */}
      <div
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerLeave}
        onPointerCancel={onPointerLeave}
        onContextMenu={(e) => e.preventDefault()}
        style={{
          marginTop: '8px',
          padding: '6px 8px',
          borderTop: isMachine
            ? '1px dashed rgba(232,228,220,0.15)'
            : '1px dashed rgba(200,105,72,0.3)',
          cursor: 'pointer',
          userSelect: 'none',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '10px',
          letterSpacing: '0.16em',
          textTransform: 'uppercase',
          color: bodyVisible
            ? '#C86948'
            : isMachine
              ? 'rgba(232,228,220,0.55)'
              : '#78716C',
        }}
      >
        <span>
          {pinned
            ? '[ PINNED · SHIFT-CLICK TO UNPIN ]'
            : bodyVisible
              ? '[ INSPECTING… RELEASE TO SEAL ]'
              : '[ PRESS & HOLD TO INSPECT ]'}
        </span>
        <span style={{ opacity: 0.6 }}>
          {pinned ? '📌' : bodyVisible ? '🔓' : '🔒'}
        </span>
      </div>

      <AnimatePresence>
        {bodyVisible && (
          <motion.div
            key="body"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.22 }}
            style={{ overflow: 'hidden' }}
          >
            <div
              style={{
                marginTop: '8px',
                padding: '8px 10px',
                backgroundColor: isMachine ? '#0F0F0F' : 'rgba(0,0,0,0.04)',
                border: '1px solid rgba(200,105,72,0.35)',
                borderRadius: '3px',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '6px',
                  fontSize: '9px',
                  letterSpacing: '0.18em',
                  color: '#E06A5C',
                  textTransform: 'uppercase',
                }}
              >
                <span>⚠ SENSITIVE · PAYLOAD EXPOSED</span>
                <span>
                  {trust.state === 'valid'
                    ? 'DEMO SIGNATURE VERIFIED'
                    : trust.state === 'invalid'
                      ? trust.reason || 'SIG FAILED'
                      : trust.state.toUpperCase()}
                </span>
              </div>
              <pre
                className="no-skin-transition"
                style={{
                  fontSize: '10px',
                  color: isMachine
                    ? 'rgba(232,228,220,0.85)'
                    : '#3C3A36',
                  overflow: 'auto',
                  lineHeight: 1.45,
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {JSON.stringify(envelope.body, null, 2)}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
