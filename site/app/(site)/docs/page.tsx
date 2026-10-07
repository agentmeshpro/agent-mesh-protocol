import type { Metadata } from 'next'
import { BORDER, C, Code, ExtLink, MUTED, P, PageHeader, PageLink, PANEL, Section, TEXT } from '@/components/content'
import {
  BLOB,
  INSTALL_ALL_CMD,
  INSTALL_CMD,
  INSTALL_MAIN_CMD,
  MONO,
  PYPI_URL,
  RELEASE,
  REPO_URL,
  SERIF,
  TREE,
} from '@/lib/site'

export const metadata: Metadata = {
  title: 'Docs · Agent Mesh Protocol',
  description: 'Install ampro, build your first agent, and find the AMP specification and guides.',
}

const EXTRAS: Array<[string, string]> = [
  ['server', 'uvicorn, for ampro-server'],
  ['a2a', 'A2A 1.0 interop (JWT verification)'],
  ['pact', 'PACT Provider (JWT verification)'],
  ['mcp', 'MCP interop'],
  ['flask', 'Flask integration'],
  ['redis', 'Shared stores for multi-worker deployments'],
  ['conformance', 'JSON Schema validation in ampro-conformance'],
  ['all', 'server, a2a, pact, mcp, redis and conformance'],
]

const ENDPOINTS: Array<[string, string]> = [
  ['AMP', 'GET /.well-known/agent.json, POST /agent/message'],
  ['A2A 1.0', 'GET /.well-known/agent-card.json, POST /a2a/message:send, /a2a/message:stream, /a2a/tasks/…, JSON-RPC at POST /a2a'],
  ['MCP', 'Streamable HTTP at /mcp: your @tool functions plus an amp_task tool'],
]

const DOC_GROUPS: Array<{ title: string; items: Array<[string, string, string]> }> = [
  {
    title: 'Specification',
    items: [
      ['Wire binding', `${BLOB}/docs/WIRE-BINDING.md`, 'The normative HTTP wire format'],
      ['Schemas and OpenAPI', `${TREE}/spec`, 'JSON Schemas, registries and openapi.yaml'],
      ['Protocol contracts', `${BLOB}/docs/PROTOCOL-CONTRACTS.md`, 'Behaviour every implementation must honour'],
      ['Extensions', `${BLOB}/docs/EXTENSIONS.md`, 'How to extend AMP without breaking peers'],
      ['Conformance', `${BLOB}/docs/CONFORMANCE.md`, 'Tools for testing any implementation, in any language'],
    ],
  },
  {
    title: 'Guides',
    items: [
      ['README', `${BLOB}/README.md`, 'Overview, tour and production checklist'],
      ['Architecture', `${BLOB}/docs/ARCHITECTURE.md`, 'How the reference implementation fits together'],
      ['Scaling', `${BLOB}/docs/SCALING.md`, 'Shared stores, readiness and multi-worker deployment'],
      ['Examples', `${TREE}/examples`, '41-45 AMPI, 46 A2A, 47 MCP, 48 PACT'],
    ],
  },
  {
    title: 'Interop',
    items: [
      ['A2A interop', `${BLOB}/docs/INTEROP-A2A.md`, 'Serving and calling A2A 1.0 agents'],
      ['PACT interop', `${BLOB}/docs/INTEROP-PACT.md`, 'Hosting Brands as a PACT Provider'],
      ['MCP interop', `${BLOB}/docs/INTEROP-MCP.md`, 'Exposing and importing MCP tools'],
    ],
  },
  {
    title: 'Security and project',
    items: [
      ['Security model', `${BLOB}/docs/SECURITY-MODEL.md`, 'What the protocol guarantees, and what it leaves to you'],
      ['Reporting a vulnerability', `${BLOB}/SECURITY.md`, 'How to report security issues'],
      ['Changelog', `${BLOB}/CHANGELOG.md`, 'Every change, release by release'],
      ['Contributing', `${BLOB}/CONTRIBUTING.md`, 'How to propose changes'],
      ['Governance', `${BLOB}/GOVERNANCE.md`, 'How the spec evolves'],
    ],
  },
]

const TOC: Array<[string, string]> = [
  ['#install', 'Install'],
  ['#quickstart', 'Quickstart'],
  ['#reference', 'Reference'],
]

export default function DocsPage() {
  return (
    <>
      <PageHeader eyebrow="Docs" title="Build with AMP">
        Install the reference implementation, serve your first agent, and find the specification and
        guides.
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

      <Section id="install" eyebrow="Install" title={`Get the ${RELEASE} reference implementation`}>
        <Code label="shell" copy>
          {INSTALL_CMD}
        </Code>
        <P>
          <C>ampro</C> is on <ExtLink href={PYPI_URL}>PyPI</ExtLink> and requires Python 3.11+. The core
          package depends only on pydantic, cryptography, base58 and httpx. Pre-1.0, the wire format may
          still change between minor versions: see <PageLink href="/releases">releases</PageLink> for
          what changed. To add every optional integration:
        </P>
        <Code label="shell" copy>
          {INSTALL_ALL_CMD}
        </Code>
        <div
          className="mt-6 max-w-3xl overflow-hidden"
          style={{ border: `1px solid ${BORDER}`, borderRadius: 18, backgroundColor: PANEL }}
        >
          <table className="w-full" style={{ borderCollapse: 'collapse', fontSize: 14, color: TEXT }}>
            <thead>
              <tr style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.12em', textTransform: 'uppercase', color: MUTED }}>
                <th scope="col" className="px-4 py-3 text-left">Extra</th>
                <th scope="col" className="px-4 py-3 text-left">Adds</th>
              </tr>
            </thead>
            <tbody>
              {EXTRAS.map(([name, desc]) => (
                <tr key={name} style={{ borderTop: `1px solid ${BORDER}` }}>
                  <td className="whitespace-nowrap px-4 py-2 align-top"><C>{name}</C></td>
                  <td className="px-4 py-2 align-top" style={{ color: MUTED }}>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <P>
          To try unreleased changes, install from the main branch on GitHub instead:
        </P>
        <Code label="shell" copy>
          {INSTALL_MAIN_CMD}
        </Code>
      </Section>

      <Section id="quickstart" eyebrow="Quickstart" title="Your first agent in two files">
        <P>
          AMPI is the declarative framework for building an agent, the way ASGI is for web apps. Handlers
          receive the message and a context with the caller, the wire protocol and its trust tier.
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
        <Code label="shell" copy>{`ampro-server agent:agent --port 8000 --protocols amp,a2a,mcp`}</Code>
        <div
          className="mt-6 max-w-3xl overflow-hidden"
          style={{ border: `1px solid ${BORDER}`, borderRadius: 18, backgroundColor: PANEL }}
        >
          <table className="w-full" style={{ borderCollapse: 'collapse', fontSize: 14, color: TEXT }}>
            <tbody>
              {ENDPOINTS.map(([proto, eps], i) => (
                <tr key={proto} style={{ borderTop: i ? `1px solid ${BORDER}` : undefined }}>
                  <th scope="row" className="px-4 py-3 text-left align-top" style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>
                    {proto}
                  </th>
                  <td className="px-4 py-3 align-top" style={{ color: MUTED }}><C>{eps}</C></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <P>
          The server binds to <C>127.0.0.1</C> by default. Before exposing it, follow the{' '}
          <ExtLink href={`${BLOB}/README.md#production-deployment`}>production checklist</ExtLink>. To see
          how AMP sits next to A2A, PACT and MCP, read the <PageLink href="/protocol">protocol overview</PageLink>.
        </P>
      </Section>

      <Section id="reference" eyebrow="Reference" title="Specification and guides">
        <div className="grid gap-8 md:grid-cols-2">
          {DOC_GROUPS.map(({ title, items }) => (
            <div key={title}>
              <h3 style={{ fontFamily: SERIF, fontSize: 22, color: TEXT }}>{title}</h3>
              <ul className="mt-3 grid gap-2">
                {items.map(([name, href, desc]) => (
                  <li
                    key={href}
                    style={{ border: `1px solid ${BORDER}`, borderRadius: 14, backgroundColor: PANEL, padding: '12px 16px' }}
                  >
                    <ExtLink href={href}>{name}</ExtLink>
                    <p style={{ marginTop: 4, fontSize: 14, color: MUTED }}>{desc}</p>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <P>
          Everything lives in the <ExtLink href={REPO_URL}>GitHub repository</ExtLink>.
        </P>
      </Section>
      <div className="pb-12" />
    </>
  )
}
