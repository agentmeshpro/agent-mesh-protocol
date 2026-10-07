/**
 * Building blocks for the static pages (home, protocol, docs). Light skin
 * only: serif headings on warm white, mono for labels and code.
 */

import Link from 'next/link'
import type { ReactNode } from 'react'
import { ACCENT, MONO, SERIF } from '@/lib/site'
import { CopyButton } from './copy-button'

export const TEXT = '#4A3A31'
export const MUTED = '#78716C'
export const BORDER = '#E7E5E4'
export const PANEL = 'rgba(255,255,255,0.7)'

export function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <p
      style={{
        fontFamily: MONO,
        fontSize: 11,
        letterSpacing: '0.22em',
        textTransform: 'uppercase',
        color: ACCENT,
      }}
    >
      {children}
    </p>
  )
}

export function PageHeader({ eyebrow, title, children }: {
  eyebrow: string
  title: string
  children?: ReactNode
}) {
  return (
    <div className="mx-auto max-w-5xl px-4 pt-14 pb-4 sm:px-8 sm:pt-20">
      <Eyebrow>{eyebrow}</Eyebrow>
      <h1
        className="mt-3 text-[40px] sm:text-[56px]"
        style={{ fontFamily: SERIF, lineHeight: 1.05, letterSpacing: '-0.02em', color: TEXT }}
      >
        {title}
      </h1>
      {children && (
        <p className="mt-5 max-w-2xl text-[18px] sm:text-[20px]" style={{ fontFamily: SERIF, lineHeight: 1.45, color: MUTED }}>
          {children}
        </p>
      )}
    </div>
  )
}

export function Section({ id, eyebrow, title, children }: {
  id: string
  eyebrow: string
  title: string
  children: ReactNode
}) {
  return (
    <section id={id} className="mx-auto max-w-5xl scroll-mt-20 px-4 py-12 sm:px-8">
      <Eyebrow>{eyebrow}</Eyebrow>
      <h2
        className="mt-2 text-[28px] sm:text-[34px]"
        style={{ fontFamily: SERIF, lineHeight: 1.15, letterSpacing: '-0.01em', color: TEXT }}
      >
        {title}
      </h2>
      <div className="mt-6">{children}</div>
    </section>
  )
}

export function P({ children }: { children: ReactNode }) {
  return (
    <p className="max-w-3xl" style={{ fontSize: 16, lineHeight: 1.65, color: MUTED, marginTop: 12 }}>
      {children}
    </p>
  )
}

export function C({ children }: { children: ReactNode }) {
  return (
    <code style={{ fontFamily: MONO, fontSize: '0.88em', overflowWrap: 'anywhere' }}>{children}</code>
  )
}

export function Code({ children, label, copy = false }: {
  children: string
  label?: string
  copy?: boolean
}) {
  return (
    <div
      style={{
        marginTop: 14,
        border: '1px solid rgba(74,58,49,0.12)',
        borderRadius: 12,
        backgroundColor: '#2A2A2A',
        overflow: 'hidden',
      }}
    >
      {(label || copy) && (
        <div className="flex items-center justify-between gap-3" style={{ padding: '8px 14px 0' }}>
          <span
            style={{
              fontFamily: MONO,
              fontSize: 10,
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: 'rgba(232,228,220,0.5)',
            }}
          >
            {label}
          </span>
          {copy && <CopyButton text={children} />}
        </div>
      )}
      <pre
        style={{
          margin: 0,
          padding: '10px 14px 14px',
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: 1.55,
          color: '#E8E4DC',
          overflowX: 'auto',
        }}
      >
        <code>{children}</code>
      </pre>
    </div>
  )
}

/** External link (opens in a new tab). */
export function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={{ color: ACCENT, textDecoration: 'underline', textUnderlineOffset: 3 }}
    >
      {children}
    </a>
  )
}

/** Link to another page on this site. */
export function PageLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} style={{ color: ACCENT, textDecoration: 'underline', textUnderlineOffset: 3 }}>
      {children}
    </Link>
  )
}

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={className}
      style={{
        border: `1px solid ${BORDER}`,
        borderRadius: 18,
        backgroundColor: PANEL,
        padding: 20,
        minWidth: 0,
      }}
    >
      {children}
    </div>
  )
}

export function Badge({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        fontFamily: MONO,
        fontSize: 10,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: '#5A8B58',
        border: '1px solid rgba(90,139,88,0.3)',
        borderRadius: 9999,
        padding: '2px 8px',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  )
}

export function ButtonLink({ href, children, primary = false, external = false }: {
  href: string
  children: ReactNode
  primary?: boolean
  external?: boolean
}) {
  const style = {
    backgroundColor: primary ? ACCENT : 'transparent',
    color: primary ? '#FFFFFF' : TEXT,
    border: `1px solid ${primary ? ACCENT : '#D6D3D1'}`,
    borderRadius: 9999,
    fontSize: 14,
    fontWeight: 500,
  }
  const className = 'inline-flex items-center px-5 py-[10px] transition-opacity hover:opacity-90'
  return external ? (
    <a href={href} target="_blank" rel="noopener noreferrer" className={className} style={style}>
      {children}
    </a>
  ) : (
    <Link href={href} className={className} style={style}>
      {children}
    </Link>
  )
}
