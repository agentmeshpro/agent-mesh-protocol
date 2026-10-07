'use client'

/**
 * Landing-page content below the demo: interoperability, the comparison
 * table, security, install and docs. Copy follows the repository README
 * and CHANGELOG for 0.4.0; keep them in sync when either changes.
 *
 * Uses the same two skins as the rest of the page (user = serif on warm
 * white, machine = mono on charcoal) via useAmpTheme.
 */

import type { ReactNode } from 'react'
import { useAmpTheme } from './theme'

const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"
const SERIF = "var(--font-newsreader), 'Newsreader', Georgia, serif"
const ACCENT = '#C86948'

export const REPO_URL = 'https://github.com/agentmeshpro/agent-mesh-protocol'
const BLOB = `${REPO_URL}/blob/main`
export const INSTALL_CMD =
  'pip install "ampro[all] @ git+https://github.com/agentmeshpro/agent-mesh-protocol.git"'
const EXT_URI = 'https://github.com/agentmeshpro/agent-mesh-protocol/ext/amp/v1'

function useSkin() {
  const { theme } = useAmpTheme()
  const m = theme === 'machine'
  return {
    m,
    text: m ? '#E8E4DC' : '#4A3A31',
    muted: m ? 'rgba(232,228,220,0.6)' : '#78716C',
    border: m ? 'rgba(232,228,220,0.12)' : '#E7E5E4',
    panel: m ? '#1A1A1A' : 'rgba(255,255,255,0.7)',
    radius: m ? 6 : 18,
  }
}

function Section({ id, eyebrow, title, children }: {
  id: string
  eyebrow: string
  title: string
  children: ReactNode
}) {
  const k = useSkin()
  return (
    <section id={id} className="mx-auto max-w-5xl px-4 py-12 sm:px-8">
      <p
        style={{
          fontFamily: MONO,
          fontSize: 11,
          letterSpacing: '0.22em',
          textTransform: 'uppercase',
          color: ACCENT,
        }}
      >
        {eyebrow}
      </p>
      <h2
        className="mt-2"
        style={{
          fontFamily: k.m ? MONO : SERIF,
          fontSize: k.m ? 18 : 34,
          lineHeight: 1.15,
          letterSpacing: k.m ? '0.12em' : '-0.01em',
          textTransform: k.m ? 'uppercase' : 'none',
          color: k.text,
          fontWeight: k.m ? 700 : 400,
        }}
      >
        {title}
      </h2>
      <div className="mt-6">{children}</div>
    </section>
  )
}

function P({ children }: { children: ReactNode }) {
  const k = useSkin()
  return (
    <p
      className="max-w-3xl"
      style={{ fontSize: k.m ? 12 : 16, lineHeight: 1.6, color: k.muted, marginTop: 12 }}
    >
      {children}
    </p>
  )
}

function C({ children }: { children: ReactNode }) {
  return (
    <code style={{ fontFamily: MONO, fontSize: '0.88em', overflowWrap: 'anywhere' }}>
      {children}
    </code>
  )
}

function Code({ children, label }: { children: string; label?: string }) {
  const k = useSkin()
  return (
    <div
      className="no-skin-transition"
      style={{
        marginTop: 14,
        border: `1px solid ${k.m ? 'rgba(232,228,220,0.12)' : 'rgba(74,58,49,0.12)'}`,
        borderRadius: k.m ? 4 : 12,
        backgroundColor: k.m ? '#0F0F0F' : '#2A2A2A',
        overflow: 'hidden',
      }}
    >
      {label && (
        <div
          style={{
            fontFamily: MONO,
            fontSize: 10,
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            color: 'rgba(232,228,220,0.5)',
            padding: '8px 14px 0',
          }}
        >
          {label}
        </div>
      )}
      <pre
        className="no-skin-transition"
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

function DocLink({ href, children }: { href: string; children: ReactNode }) {
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

function Card({ title, badge, children }: { title: string; badge: string; children: ReactNode }) {
  const k = useSkin()
  return (
    <div
      style={{
        border: `1px solid ${k.border}`,
        borderRadius: k.radius,
        backgroundColor: k.panel,
        padding: 20,
        minWidth: 0,
      }}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3
          style={{
            fontFamily: k.m ? MONO : SERIF,
            fontSize: k.m ? 14 : 24,
            letterSpacing: k.m ? '0.16em' : 0,
            textTransform: k.m ? 'uppercase' : 'none',
            color: k.text,
            fontWeight: k.m ? 700 : 400,
          }}
        >
          {title}
        </h3>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 10,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: k.m ? '#8BB58A' : '#5A8B58',
            border: `1px solid ${k.m ? 'rgba(139,181,138,0.4)' : 'rgba(90,139,88,0.3)'}`,
            borderRadius: k.m ? 3 : 9999,
            padding: '2px 8px',
          }}
        >
          {badge}
        </span>
      </div>
      {children}
    </div>
  )
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

function ComparisonTable() {
  const k = useSkin()
  const cell = {
    padding: '10px 12px',
    borderBottom: `1px solid ${k.border}`,
    textAlign: 'left' as const,
    verticalAlign: 'top' as const,
  }
  return (
    <div
      style={{
        overflowX: 'auto',
        border: `1px solid ${k.border}`,
        borderRadius: k.radius,
        backgroundColor: k.panel,
      }}
    >
      <table style={{ width: '100%', minWidth: 640, borderCollapse: 'collapse', fontSize: k.m ? 11 : 14, color: k.text }}>
        <thead>
          <tr style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.12em', textTransform: 'uppercase', color: k.muted }}>
            <th style={cell} />
            {['AMP', 'A2A', 'PACT', 'MCP'].map((h) => (
              <th key={h} style={{ ...cell, color: h === 'AMP' ? ACCENT : k.muted }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {COMPARISON.map(([row, ...vals]) => (
            <tr key={row}>
              <th scope="row" style={{ ...cell, fontWeight: 500, color: k.muted }}>{row}</th>
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

const SECURITY: Array<[string, string]> = [
  [
    'Fully signed delegation chains',
    'Every field of a delegation link is signed. Children cannot raise max_depth, and fan-out and budgets are enforced.',
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

const DOCS: Array<[string, string, string]> = [
  ['README', `${BLOB}/README.md`, 'Overview, tour and production checklist'],
  ['Wire binding', `${BLOB}/docs/WIRE-BINDING.md`, 'The normative HTTP wire format'],
  ['Security model', `${BLOB}/docs/SECURITY-MODEL.md`, 'What the protocol guarantees, and what it leaves to you'],
  ['A2A interop', `${BLOB}/docs/INTEROP-A2A.md`, 'Serving and calling A2A 1.0 agents'],
  ['PACT interop', `${BLOB}/docs/INTEROP-PACT.md`, 'Hosting Brands as a PACT Provider'],
  ['MCP interop', `${BLOB}/docs/INTEROP-MCP.md`, 'Exposing and importing MCP tools'],
  ['Examples', `${REPO_URL}/tree/main/examples`, '41-45 AMPI, 46 A2A, 47 MCP, 48 PACT'],
  ['Changelog', `${BLOB}/CHANGELOG.md`, 'What changed in 0.4.0, including breaking wire changes'],
]

export function DemoNote() {
  const k = useSkin()
  return (
    <p
      className="mx-auto mt-3 max-w-3xl px-2 text-center"
      style={{ fontSize: k.m ? 10 : 12, lineHeight: 1.5, color: k.muted, fontFamily: k.m ? MONO : undefined }}
    >
      The bakery and delivery agents are played by a language model. Envelopes use the AMP 0.4.0
      shape and are signed with Ed25519 and checked in your browser, but with a simplified scheme
      (canonical JSON in X-Signature headers). Real AMP peers sign each HTTP request with the RFC 9421
      profile in <DocLink href={`${BLOB}/docs/WIRE-BINDING.md`}>WIRE-BINDING §12.15</DocLink>.
    </p>
  )
}

export function LandingSections() {
  const k = useSkin()
  return (
    <div style={{ color: k.text }}>
      <Section id="interop" eyebrow="0.4.0 · Interoperability" title="AMP works with A2A, PACT and MCP">
        <P>
          The industry is converging on A2A as the transport, PACT for personal agents acting for
          users, and MCP for tools. What none of them standardise is the hard part of a real mesh:
          who may act for whom, how far a delegation reaches, what it may spend, and which data may
          cross which border. AMP adds exactly that, and speaks the other protocols natively, so you
          don&apos;t have to choose.
        </P>
        <div className="mt-8">
          <ComparisonTable />
        </div>
      </Section>

      <Section id="one-agent" eyebrow="One agent, every protocol" title="Write handlers once, serve them everywhere">
        <P>
          An <C>AgentApp</C> is served over AMP, A2A 1.0 and MCP from the same process.
        </P>
        <Code label="agent.py">{`from ampro.ampi.app import AgentApp

agent = AgentApp(
    agent_id="agent://my-bot.example.com",
    endpoint="https://my-bot.example.com/agent/message",
)

@agent.on("task.create")
async def handle(msg, ctx):
    return {"echo": msg.body["description"], "via": ctx.protocol, "trust": ctx.trust_tier.value}

@agent.tool("add", description="Add two numbers")
def add(a: int, b: int) -> dict:
    return {"sum": a + b}`}</Code>
        <Code label="shell">{`ampro-server agent:agent --port 8000 --protocols amp,a2a,mcp`}</Code>
        <P>
          AMP at <C>POST /agent/message</C>, A2A 1.0 at <C>/.well-known/agent-card.json</C> and{' '}
          <C>/a2a</C>, MCP over Streamable HTTP at <C>/mcp</C>. The server binds to{' '}
          <C>127.0.0.1</C> by default.
        </P>
      </Section>

      <Section id="protocols" eyebrow="Interop guides" title="One section per protocol">
        <div className="grid gap-5 md:grid-cols-3">
          <Card title="A2A 1.0" badge="a2a-sdk verified">
            <P>
              Serve any <C>AgentApp</C> as an A2A agent (Agent Card, HTTP+JSON and JSON-RPC,
              SSE streaming, tasks) and call A2A agents with <C>A2AClient</C>. Delegation and
              compliance data ride in the AMP extension <C>{EXT_URI}</C>; plain A2A clients
              ignore it. Verified against the official <C>a2a-sdk</C> client.
            </P>
            <Code>{`from ampro.interop.a2a import A2AClient

async with A2AClient("https://agent.example.com/.well-known/agent-card.json") as a2a:
    reply = await a2a.send_message("Where is my order?")`}</Code>
            <P>
              <DocLink href={`${BLOB}/docs/INTEROP-A2A.md`}>INTEROP-A2A.md</DocLink> ·{' '}
              <DocLink href={`${BLOB}/examples/46_a2a_agent.py`}>example 46</DocLink>
            </P>
          </Card>
          <Card title="PACT" badge="Conformance 10/10 · 9/9">
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
              <DocLink href={`${BLOB}/docs/INTEROP-PACT.md`}>INTEROP-PACT.md</DocLink> ·{' '}
              <DocLink href={`${BLOB}/examples/48_pact_provider.py`}>example 48</DocLink>
            </P>
          </Card>
          <Card title="MCP" badge="mcp SDK verified">
            <P>
              Publish <C>@agent.tool</C> functions, plus an <C>amp_task</C> tool for your{' '}
              <C>task.create</C> handler, to MCP hosts such as Claude Code, Claude Desktop and
              Cursor. Import tools from remote MCP servers with <C>MCPToolSource</C>. Verified
              against the official <C>mcp</C> SDK.
            </P>
            <Code>{`ampro-server agent:agent --protocols amp,mcp --port 8000
claude mcp add --transport http travel http://127.0.0.1:8000/mcp`}</Code>
            <P>
              <DocLink href={`${BLOB}/docs/INTEROP-MCP.md`}>INTEROP-MCP.md</DocLink> ·{' '}
              <DocLink href={`${BLOB}/examples/47_mcp_tools.py`}>example 47</DocLink>
            </P>
          </Card>
        </div>
      </Section>

      <Section id="security" eyebrow="Security" title="Hardened for production in 0.4.0">
        <div className="grid gap-4 md:grid-cols-2">
          {SECURITY.map(([t, d]) => (
            <div
              key={t}
              style={{
                border: `1px solid ${k.border}`,
                borderRadius: k.radius,
                backgroundColor: k.panel,
                padding: 18,
              }}
            >
              <h3
                style={{
                  fontFamily: MONO,
                  fontSize: 12,
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  color: k.text,
                  fontWeight: 700,
                }}
              >
                {t}
              </h3>
              <p style={{ marginTop: 8, fontSize: k.m ? 12 : 15, lineHeight: 1.55, color: k.muted }}>{d}</p>
            </div>
          ))}
        </div>
        <P>
          <strong style={{ color: k.text }}>Breaking wire changes:</strong> session binding,
          delegation links, federation proofs and RFC 9421 verification rules changed. 0.4.0 peers
          do not interoperate with 0.3.x peers on those features. Read the{' '}
          <DocLink href={`${BLOB}/docs/SECURITY-MODEL.md`}>security model</DocLink> and the{' '}
          <DocLink href={`${BLOB}/CHANGELOG.md`}>changelog</DocLink>.
        </P>
      </Section>

      <Section id="install" eyebrow="Install" title="Get the 0.4.0 reference implementation">
        <Code label="shell">{INSTALL_CMD}</Code>
        <P>
          <C>ampro</C> is installed from the public GitHub repository, not from PyPI. Requires Python 3.11+. Extras: <C>server</C>, <C>a2a</C>, <C>pact</C>,{' '}
          <C>mcp</C>, <C>flask</C>, <C>all</C>. The core package depends only on pydantic,
          cryptography, base58 and httpx. Pre-1.0: the wire format may still evolve between minor
          versions.
        </P>
      </Section>

      <Section id="docs" eyebrow="Docs" title="Read the spec and guides">
        <ul className="grid gap-3 sm:grid-cols-2">
          {DOCS.map(([name, href, desc]) => (
            <li
              key={href}
              style={{
                border: `1px solid ${k.border}`,
                borderRadius: k.radius,
                backgroundColor: k.panel,
                padding: '12px 16px',
              }}
            >
              <DocLink href={href}>{name}</DocLink>
              <p style={{ marginTop: 4, fontSize: k.m ? 11 : 14, color: k.muted }}>{desc}</p>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  )
}
