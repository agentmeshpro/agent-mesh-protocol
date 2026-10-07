import Link from 'next/link'
import { ButtonLink, Code, Eyebrow, MUTED, Panel, TEXT } from '@/components/content'
import { ACCENT, BLOB, DEMO_ENABLED, INSTALL_CMD, MONO, RELEASE, REPO_URL, SERIF } from '@/lib/site'

const PILLARS: Array<{ title: string; body: string; href: string }> = [
  {
    title: 'Signed delegation',
    body: 'Who may act for whom, how far a delegation reaches and what it may spend, carried in fully signed multi-hop chains whose limits only narrow.',
    href: '/protocol#security',
  },
  {
    title: 'Compliance built in',
    body: 'PII tagging, erasure and jurisdiction rules travel with each message instead of living in side agreements.',
    href: '/protocol#interop',
  },
  {
    title: 'Speaks A2A, PACT and MCP',
    body: 'Write handlers once and serve them over AMP, A2A 1.0 and MCP from one process, or host Brands as a PACT Provider.',
    href: '/protocol#guides',
  },
]

const VIEWS: Array<[string, string]> = [
  ['Chat', 'Talk to your agent the way a person would.'],
  ['Protocol', 'See the same conversation as signed AMP envelopes.'],
  ['Voice', 'Run the whole order as a spoken call.'],
]

export default function HomePage() {
  return (
    <>
      <section className="mx-auto max-w-5xl px-4 pt-16 pb-12 sm:px-8 sm:pt-24">
        <Link
          href="/releases"
          className="mb-6 inline-flex items-center gap-2 px-3 py-1 transition-colors hover:border-[#C86948]"
          style={{ border: '1px solid #E7E5E4', borderRadius: 9999, fontSize: 13, color: MUTED }}
        >
          <span style={{ fontFamily: MONO, fontSize: 11, color: ACCENT }}>NEW</span>
          {RELEASE}: delegation links v2 and safeguards for bridging protocols →
        </Link>
        <Eyebrow>Open protocol · release {RELEASE}</Eyebrow>
        <h1
          className="mt-4 text-[44px] sm:text-[72px]"
          style={{ fontFamily: SERIF, lineHeight: 1.02, letterSpacing: '-0.025em', color: TEXT }}
        >
          Agent Mesh Protocol
        </h1>
        <p
          className="mt-6 max-w-2xl text-[19px] sm:text-[22px]"
          style={{ fontFamily: SERIF, lineHeight: 1.4, color: MUTED }}
        >
          An open protocol for agent-to-agent communication: trust, delegation and compliance built
          in, and interoperable with A2A, PACT and MCP.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          {DEMO_ENABLED && (
            <ButtonLink href="/demo" primary>
              Try the live demo →
            </ButtonLink>
          )}
          <ButtonLink href="/docs" primary={!DEMO_ENABLED}>
            Read the docs
          </ButtonLink>
          <ButtonLink href={REPO_URL} external>
            View on GitHub
          </ButtonLink>
        </div>
        <div className="mt-10 max-w-3xl">
          <Code label="Install" copy>
            {INSTALL_CMD}
          </Code>
          <p className="mt-3" style={{ fontSize: 13, color: '#A8A29E' }}>
            Python 3.11+. On PyPI as <code style={{ fontFamily: MONO }}>ampro</code>.{' '}
            <Link href="/docs#install" style={{ color: ACCENT }}>
              Install options
            </Link>
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-12 sm:px-8">
        <Eyebrow>What AMP adds</Eyebrow>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {PILLARS.map(({ title, body, href }) => (
            <Link key={title} href={href} className="group block">
              <Panel className="h-full transition-colors group-hover:border-[#D6D3D1]">
                <h2 style={{ fontFamily: SERIF, fontSize: 24, lineHeight: 1.2, color: TEXT }}>{title}</h2>
                <p className="mt-3" style={{ fontSize: 15, lineHeight: 1.6, color: MUTED }}>
                  {body}
                </p>
                <p className="mt-4" style={{ fontSize: 14, color: ACCENT }}>
                  Learn more →
                </p>
              </Panel>
            </Link>
          ))}
        </div>
      </section>

      {DEMO_ENABLED && (
      <section className="mx-auto max-w-5xl px-4 py-12 sm:px-8">
        <div
          className="grid gap-8 p-6 sm:p-10 md:grid-cols-[1.2fr_1fr] md:items-center"
          style={{ borderRadius: 22, backgroundColor: '#1A1A1A', color: '#E8E4DC' }}
        >
          <div>
            <p style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.22em', textTransform: 'uppercase', color: ACCENT }}>
              Live demo
            </p>
            <h2 className="mt-3 text-[28px] sm:text-[34px]" style={{ fontFamily: SERIF, lineHeight: 1.15 }}>
              Order a cake and watch three agents work it out
            </h2>
            <p className="mt-4" style={{ fontSize: 15, lineHeight: 1.6, color: 'rgba(232,228,220,0.7)' }}>
              Your agent negotiates with a bakery agent, which brings in a delivery agent when needed.
              Every message is a signed envelope that your browser verifies.
            </p>
            <div className="mt-6">
              <Link
                href="/demo"
                className="inline-flex items-center px-5 py-[10px] transition-opacity hover:opacity-90"
                style={{ backgroundColor: ACCENT, color: '#FFFFFF', borderRadius: 9999, fontSize: 14, fontWeight: 500 }}
              >
                Open the demo →
              </Link>
            </div>
          </div>
          <ul className="grid gap-3">
            {VIEWS.map(([name, desc]) => (
              <li
                key={name}
                style={{ border: '1px solid rgba(232,228,220,0.12)', borderRadius: 12, padding: '12px 16px' }}
              >
                <span style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.18em', textTransform: 'uppercase' }}>
                  {name}
                </span>
                <p className="mt-1" style={{ fontSize: 14, color: 'rgba(232,228,220,0.65)' }}>{desc}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>
      )}

      <section className="mx-auto max-w-5xl px-4 pt-6 pb-20 sm:px-8">
        <Eyebrow>Start here</Eyebrow>
        <div className="mt-6 grid gap-4 sm:grid-cols-3">
          <Link href="/docs#quickstart" className="block">
            <Panel className="h-full">
              <h3 style={{ fontFamily: SERIF, fontSize: 20, color: TEXT }}>Quickstart</h3>
              <p className="mt-2" style={{ fontSize: 14, color: MUTED }}>Build and serve your first agent.</p>
            </Panel>
          </Link>
          <Link href="/protocol" className="block">
            <Panel className="h-full">
              <h3 style={{ fontFamily: SERIF, fontSize: 20, color: TEXT }}>How AMP compares</h3>
              <p className="mt-2" style={{ fontSize: 14, color: MUTED }}>AMP next to A2A, PACT and MCP.</p>
            </Panel>
          </Link>
          <a href={`${BLOB}/docs/WIRE-BINDING.md`} target="_blank" rel="noopener noreferrer" className="block">
            <Panel className="h-full">
              <h3 style={{ fontFamily: SERIF, fontSize: 20, color: TEXT }}>Read the spec ↗</h3>
              <p className="mt-2" style={{ fontSize: 14, color: MUTED }}>The normative HTTP wire binding.</p>
            </Panel>
          </a>
        </div>
      </section>
    </>
  )
}
