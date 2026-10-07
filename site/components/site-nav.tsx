'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ACCENT, MONO, NAV, REPO_URL, SERIF } from '@/lib/site'

/**
 * Top navigation shared by every page. `dark` switches to the Protocol
 * (machine) skin used by the demo page.
 */
export function SiteNav({ dark = false }: { dark?: boolean }) {
  const pathname = usePathname()
  const muted = dark ? 'rgba(232,228,220,0.65)' : '#78716C'
  const text = dark ? '#E8E4DC' : '#4A3A31'

  const linkStyle = (active: boolean) => ({
    fontFamily: dark ? MONO : undefined,
    fontSize: dark ? 11 : 14,
    letterSpacing: dark ? '0.18em' : '0',
    textTransform: dark ? ('uppercase' as const) : ('none' as const),
    color: active ? (dark ? '#E8E4DC' : ACCENT) : muted,
    fontWeight: active ? 600 : 400,
  })

  return (
    <header
      style={{
        borderBottom: `1px solid ${dark ? 'rgba(232,228,220,0.08)' : '#E7E5E4'}`,
        backgroundColor: dark ? '#121212' : 'rgba(251,251,251,0.9)',
      }}
      className="sticky top-0 z-30 backdrop-blur"
    >
      <nav
        aria-label="Main"
        className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 sm:px-8"
      >
        <Link
          href="/"
          aria-label="Agent Mesh Protocol home"
          style={{
            fontFamily: dark ? MONO : SERIF,
            fontSize: dark ? 13 : 22,
            letterSpacing: dark ? '0.4em' : '0.01em',
            fontWeight: dark ? 700 : 400,
            color: text,
          }}
        >
          AMP
        </Link>
        <div className="flex items-center gap-4 sm:gap-7">
          {NAV.map(({ href, label }) => {
            const active = pathname === href || pathname.startsWith(`${href}/`)
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? 'page' : undefined}
                style={linkStyle(active)}
              >
                {label}
              </Link>
            )
          })}
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer" style={linkStyle(false)}>
            GitHub
          </a>
        </div>
      </nav>
    </header>
  )
}
