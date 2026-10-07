import type { Metadata } from 'next'
import {
  Badge,
  BORDER,
  C,
  Code,
  ExtLink,
  MUTED,
  P,
  PageHeader,
  PageLink,
  Panel,
  PANEL,
  Section,
  TEXT,
} from '@/components/content'
import { ACCENT, BLOB, EXT_URI, MONO, RELEASE, SERIF } from '@/lib/site'

export const metadata: Metadata = {
  title: 'Protocol · Agent Mesh Protocol',
  description:
    'How AMP adds signed delegation, compliance and hardened security on top of A2A, PACT and MCP.',
}

const COMPARISON: Array<[string, string, string, string, string]> = [
  [
    'Purpose',
    'Agent mesh: trust, delegation, compliance',
    'Agent-to-agent transport',
    'Personal agents acting for users on A2A',
    'Tools and context for models',
  ],
  ['Signed multi-hop delegation chains', '✅', '❌', '❌ (single-hop OAuth grant)', '❌'],
  ['User consent via OAuth device flow', 'via PACT', '❌', '✅', '❌'],
  ['Compliance (PII, erasure, jurisdiction)', '✅', '❌', '❌', '❌'],
  ['Served by ampro', '✅ native', '✅ adapter', '✅ adapter', '✅ adapter'],
]

const SECURITY: Array<[string, string]> = [
  [
    'Delegation links v2',
    'The whole link is signed, extensions included, with a crit list a verifier must honour. Limits only narrow down the chain, trust never rises, money is typed with a currency, lifetimes are capped and a chain is bound to its holder.',
  ],
  [
    'Key compromise semantics',
    'A key revoked for compromise invalidates every signature it made, whatever timestamp the signature claims. A rotated key keeps the signatures it made before rotation.',
  ],
  [
    'X25519 session key agreement',
    'The session binding key is derived with X25519 + HKDF on both sides and never transmitted. The per-message HMAC covers the body.',
  ],
  [
    'Hardened RFC 9421',
    '@method, @target-uri and @authority must be covered, a body requires a matching content-digest, and the signature is verified before the nonce is recorded.',
  ],
  [
    'SSRF guard',
    'One guard with DNS-pinned connections, covering CGNAT, NAT64, 6to4 and IPv4-mapped forms, used by the client, callbacks, JWKS and interop clients.',
  ],
  [
    'Server security pipeline',
    'Size limit → authentication → rate limit → validation → sender binding → recipient check → loop detection → caller-scoped dedup → concurrency limit → handler timeout. Exception details never reach clients.',
  ],
]

const TOC: Array<[string, string]> = [
  ['#interop', 'How AMP compares'],
  ['#one-agent', 'One agent, every protocol'],
  ['#guides', 'Interop guides'],
  ['#security', 'Security'],
]

function ComparisonTable() {
  const cell = {
    padding: '10px 12px',
    borderBottom: `1px solid ${BORDER}`,
    textAlign: 'left' as const,
    verticalAlign: 'top' as const,
  }
  return (
    <div style={{ overflowX: 'auto', border: `1px solid ${BORDER}`, borderRadius: 18, backgroundColor: PANEL }}>
      <table style={{ width: '100%', minWidth: 640, borderCollapse: 'collapse', fontSize: 14, color: TEXT }}>
        <thead>
          <tr style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.12em', textTransform: 'uppercase', color: MUTED }}>
            <th style={cell} />
            {['AMP', 'A2A', 'PACT', 'MCP'].map((h) => (
              <th key={h} scope="col" style={{ ...cell, color: h === 'AMP' ? ACCENT : MUTED }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {COMPARISON.map(([row, ...vals]) => (
            <tr key={row}>
              <th scope="row" style={{ ...cell, fontWeight: 500, color: MUTED }}>{row}</th>
              {vals.map((v, i) => (
                <td key={i} style={cell}>{v}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function GuideCard({ title, badge, children }: { title: string; badge: string; children: React.ReactNode }) {
  return (
    <Panel>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 style={{ fontFamily: SERIF, fontSize: 24, color: TEXT }}>{title}</h3>
        <Badge>{badge}</Badge>
      </div>
      {children}
    </Panel>
  )
}

export default function ProtocolPage() {
  return (
    <>
      <PageHeader eyebrow={`Protocol · ${RELEASE}`} title="The hard part of a real agent mesh">
        A2A moves messages, PACT lets personal agents act for users and MCP gives models tools. AMP adds
        who may act for whom, how far a delegation reaches, what it may spend and which data may cross
        which border, and speaks the other three natively.
      </PageHeader>

      <nav aria-label="On this page" className="mx-auto max-w-5xl px-4 pt-4 sm:px-8">
        <ul className="flex flex-wrap gap-2">
          {TOC.map(([href, label]) => (
            <li key={href}>
              <a
                href={href}
                className="inline-block px-3 py-1 transition-colors hover:border-[#C86948]"
                style={{ border: `1px solid ${BORDER}`, borderRadius: 9999, fontSize: 13, color: MUTED }}
              >
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <Section id="interop" eyebrow="Interoperability" title="AMP works with A2A, PACT and MCP">
        <P>
          The industry is converging on A2A as the transport, PACT for personal agents acting for users,
          and MCP for tools. None of them standardise delegation reach, spending limits or data
          residency. AMP rides on top of A2A rather than competing with it: AMP agents publish an A2A
          Agent Card, accept A2A calls, and carry delegation and compliance data in an A2A extension
          that plain A2A clients ignore.
        </P>
        <div className="mt-8">
          <ComparisonTable />
        </div>
      </Section>

      <Section id="one-agent" eyebrow="One agent, every protocol" title="Write handlers once, serve them everywhere">
        <P>
          An <C>AgentApp</C> is served over AMP, A2A 1.0 and MCP from the same process. The{' '}
          <PageLink href="/docs#quickstart">quickstart</PageLink> walks through it.
        </P>
        <Code label="shell">{`ampro-server agent:agent --port 8000 --protocols amp,a2a,mcp`}</Code>
        <P>
          AMP at <C>POST /agent/message</C>, A2A 1.0 at <C>/.well-known/agent-card.json</C> and{' '}
          <C>/a2a</C>, MCP over Streamable HTTP at <C>/mcp</C>. The server binds to <C>127.0.0.1</C> by
          default.
        </P>
      </Section>

      <Section id="guides" eyebrow="Interop guides" title="One guide per protocol">
        <div className="grid gap-5">
          <GuideCard title="A2A 1.0" badge="a2a-sdk verified">
            <P>
              Serve any <C>AgentApp</C> as an A2A agent (Agent Card, HTTP+JSON and JSON-RPC, SSE
              streaming, tasks) and call A2A agents with <C>A2AClient</C>. Delegation and compliance data
              ride in the AMP extension <C>{EXT_URI}</C>; configure <C>chain_verifier=</C> to accept a
              delegation chain. Verified against the official <C>a2a-sdk</C>{' '}
              client.
            </P>
            <Code>{`from ampro.interop.a2a import A2AClient

async with A2AClient("https://agent.example.com/.well-known/agent-card.json") as a2a:
    reply = await a2a.send_message("Where is my order?")`}</Code>
            <P>
              <ExtLink href={`${BLOB}/docs/INTEROP-A2A.md`}>INTEROP-A2A.md</ExtLink> ·{' '}
              <ExtLink href={`${BLOB}/examples/46_a2a_agent.py`}>example 46</ExtLink>
            </P>
          </GuideCard>
          <GuideCard title="PACT" badge="Conformance 10/10 · 9/9">
            <P>
              Host Brands as a PACT Provider: personal-agent JWT identity, OAuth 2.0 device-code
              delegation (RFC 8628), scopes and step-up, signed receipts. Passes the official PACT
              conformance suite: Identity 10/10, Delegated 9/9.
            </P>
            <Code>{`from ampro.interop.pact import Brand, PACTProvider, ProviderKeySet

provider = PACTProvider(
    public_url="https://provider.example.com",
    registry=registry,
    audience="provider-aud-7f3c",
    keys=ProviderKeySet.from_env(),
)
provider.add_brand(Brand("acme", acme_app, name="Acme Support"))
asgi_app = provider.as_server().asgi()`}</Code>
            <P>
              <ExtLink href={`${BLOB}/docs/INTEROP-PACT.md`}>INTEROP-PACT.md</ExtLink> ·{' '}
              <ExtLink href={`${BLOB}/examples/48_pact_provider.py`}>example 48</ExtLink>
            </P>
          </GuideCard>
          <GuideCard title="MCP" badge="mcp SDK verified">
            <P>
              Publish <C>@agent.tool</C> functions, plus an <C>amp_task</C> tool for your{' '}
              <C>task.create</C> handler, to MCP hosts such as Claude Code, Claude Desktop and Cursor.
              Import tools from remote MCP servers with <C>MCPToolSource</C>. Verified against the
              official <C>mcp</C> SDK.
            </P>
            <Code>{`ampro-server agent:agent --protocols amp,mcp --port 8000
claude mcp add --transport http travel http://127.0.0.1:8000/mcp`}</Code>
            <P>
              <ExtLink href={`${BLOB}/docs/INTEROP-MCP.md`}>INTEROP-MCP.md</ExtLink> ·{' '}
              <ExtLink href={`${BLOB}/examples/47_mcp_tools.py`}>example 47</ExtLink>
            </P>
          </GuideCard>
        </div>
      </Section>

      <Section id="security" eyebrow="Security" title="Hardened for production">
        <div className="grid gap-4 md:grid-cols-2">
          {SECURITY.map(([t, d]) => (
            <Panel key={t}>
              <h3
                style={{
                  fontFamily: MONO,
                  fontSize: 12,
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  color: TEXT,
                  fontWeight: 700,
                }}
              >
                {t}
              </h3>
              <p style={{ marginTop: 8, fontSize: 15, lineHeight: 1.55, color: MUTED }}>{d}</p>
            </Panel>
          ))}
        </div>
        <div
          className="mt-6 max-w-3xl"
          style={{ borderLeft: `3px solid ${ACCENT}`, padding: '4px 0 4px 16px' }}
        >
          <p style={{ fontSize: 15, lineHeight: 1.6, color: MUTED }}>
            <strong style={{ color: TEXT }}>Breaking changes in {RELEASE}:</strong> <C>validate_chain</C>{' '}
            refuses v1 delegation chains unless <C>allow_v1=True</C>, and the A2A adapter only exposes a
            delegation chain it has verified. See <PageLink href="/releases">releases</PageLink> for every
            change, and read the{' '}
            <ExtLink href={`${BLOB}/docs/SECURITY-MODEL.md`}>security model</ExtLink>.
          </p>
        </div>
      </Section>
      <div className="pb-12" />
    </>
  )
}
