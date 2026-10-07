import type { Metadata } from 'next'
import { BORDER, C, ExtLink, MUTED, PageHeader, PANEL, TEXT } from '@/components/content'
import { ACCENT, BLOB, MONO, PYPI_URL, RELEASE, RELEASES_URL, SERIF } from '@/lib/site'

export const metadata: Metadata = {
  title: 'Releases · Agent Mesh Protocol',
  description: 'What changed in each AMP release, including breaking wire changes and how to upgrade.',
}

type Item = { title: string; body: React.ReactNode }

type Release = {
  version: string
  date?: string
  summary: string
  added: Item[]
  breaking: Item[]
}

const RELEASES: Release[] = [
  {
    version: '0.5.0',
    summary:
      'Foundational safeguards for bridging AMP to other agent protocols: A2A, MCP, PACT, ACP, AP2, x402, Web Bot Auth and more.',
    added: [
      {
        title: 'Delegation links v2',
        body: (
          <>
            The whole link is signed, extensions included, and a <C>crit</C> list names extensions a
            verifier must understand or reject. Links carry typed constraints (money in integer minor
            units with an ISO 4217 currency), audience, origin and principal. Every limit narrows down the
            chain, <C>trust_tier</C> never rises, lifetimes are capped and a chain is bound to its holder.{' '}
            <C>authorize_action</C> checks an action against a validated chain, including spend tracking.
          </>
        ),
      },
      {
        title: 'Key compromise semantics',
        body: (
          <>
            A key revoked for compromise or decommissioning invalidates every signature it made, whatever
            timestamp the signature claims. A rotated key keeps the signatures it made before rotation.
          </>
        ),
      },
      {
        title: 'Foreign identifiers',
        body: (
          <>
            <C>agent.json</C> can list MCP client IDs, <C>did:key</C>, <C>did:web</C>, <C>did:wba</C> and
            HTTP message signature key directories. They confer no trust unless an identity link proof
            verifies.
          </>
        ),
      },
      {
        title: 'One error for missing authority',
        body: (
          <>
            <C>urn:amp:error:authority-required</C> (403) says what is missing: scopes, constraints, payment,
            human approval or audience. It maps to MCP <C>insufficient_scope</C>, A2A and PACT{' '}
            <C>AUTH_REQUIRED</C>, and HTTP 402.
          </>
        ),
      },
      {
        title: 'Trace context and hop count everywhere',
        body: (
          <>
            W3C <C>traceparent</C> and <C>tracestate</C> plus an <C>AMP-Hop-Count</C> header travel through
            A2A, MCP, PACT and native AMP, so loops that cross protocols are stopped.
          </>
        ),
      },
    ],
    breaking: [
      {
        title: 'v1 delegation chains are refused by default',
        body: (
          <>
            <C>validate_chain</C> rejects v1 chains unless you pass <C>allow_v1=True</C>, because v1 links
            cannot carry restrictions an older verifier must honour. v2 chains need <C>keys=</C> and{' '}
            <C>holder=</C>.
          </>
        ),
      },
      {
        title: 'The A2A adapter no longer exposes unverified chains',
        body: (
          <>
            Configure <C>chain_verifier=</C>. Without one, <C>ctx.delegation_chain</C> stays <C>None</C> and
            the raw chain is kept only under <C>ctx.metadata[&quot;amp.unverifiedDelegationChain&quot;]</C>.
          </>
        ),
      },
      {
        title: 'Spec identifiers moved with the repository',
        body: (
          <>
            Schema <C>$id</C>s and the A2A extension URI now use{' '}
            <C>github.com/agentmeshpro/agent-mesh-protocol</C>. Peers that match them by exact string must
            update.
          </>
        ),
      },
    ],
  },
  {
    version: '0.4.0',
    date: '2026-10-07',
    summary: 'Interoperability and production hardening.',
    added: [
      {
        title: 'A2A 1.0, PACT and MCP',
        body: (
          <>
            Serve any <C>AgentApp</C> as an A2A agent or over MCP, call A2A agents, and host Brands as a PACT
            Provider that passes the official conformance suite (Identity 10/10, Delegated 9/9).
          </>
        ),
      },
      {
        title: 'One server, several protocols',
        body: (
          <>
            <C>ampro-server --protocols amp,a2a,mcp</C> and a framework-free ASGI binding, with a full
            security pipeline in front of every message.
          </>
        ),
      },
      {
        title: 'Machine-readable spec and conformance suite',
        body: (
          <>
            JSON Schemas, OpenAPI and registries in <C>spec/</C>, and <C>ampro-conformance</C> to test any
            implementation over HTTP.
          </>
        ),
      },
      {
        title: 'Multi-worker deployments',
        body: (
          <>
            A Redis implementation of every stateful store, readiness checks and graceful shutdown.
          </>
        ),
      },
    ],
    breaking: [
      {
        title: 'Signed wire artefacts changed',
        body: (
          <>
            Session binding, delegation links, federation proofs and RFC 9421 verification rules changed,
            so 0.4.0 peers do not interoperate with 0.3.x peers on those features.
          </>
        ),
      },
    ],
  },
]

function ItemList({ items, accent }: { items: Item[]; accent?: boolean }) {
  return (
    <ul className="mt-3 grid gap-3">
      {items.map(({ title, body }) => (
        <li
          key={title}
          style={{
            border: `1px solid ${BORDER}`,
            borderLeft: accent ? `3px solid ${ACCENT}` : `1px solid ${BORDER}`,
            borderRadius: 14,
            backgroundColor: PANEL,
            padding: '14px 18px',
          }}
        >
          <h4 style={{ fontSize: 16, fontWeight: 600, color: TEXT }}>{title}</h4>
          <p className="mt-1" style={{ fontSize: 15, lineHeight: 1.6, color: MUTED }}>{body}</p>
        </li>
      ))}
    </ul>
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <h3
      className="mt-8"
      style={{ fontFamily: MONO, fontSize: 11, letterSpacing: '0.18em', textTransform: 'uppercase', color: MUTED }}
    >
      {children}
    </h3>
  )
}

export default function ReleasesPage() {
  return (
    <>
      <PageHeader eyebrow="Releases" title="What changed, release by release">
        The protocol and the <C>ampro</C> package are versioned together. Before 1.0, a minor release can
        change the wire format, so each release lists its breaking changes first.
      </PageHeader>

      <div className="mx-auto max-w-5xl px-4 pb-20 sm:px-8">
        {RELEASES.map((r) => (
          <section
            key={r.version}
            id={`v${r.version}`}
            className="scroll-mt-20 py-10"
            style={{ borderTop: `1px solid ${BORDER}` }}
          >
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
              <h2 style={{ fontFamily: SERIF, fontSize: 36, lineHeight: 1.1, color: TEXT }}>{r.version}</h2>
              {r.version === RELEASE && (
                <span
                  style={{
                    fontFamily: MONO,
                    fontSize: 10,
                    letterSpacing: '0.14em',
                    textTransform: 'uppercase',
                    color: '#FFFFFF',
                    backgroundColor: ACCENT,
                    borderRadius: 9999,
                    padding: '2px 8px',
                  }}
                >
                  Latest
                </span>
              )}
              {r.date && <span style={{ fontSize: 14, color: MUTED }}>{r.date}</span>}
            </div>
            <p className="mt-3 max-w-3xl" style={{ fontSize: 17, lineHeight: 1.6, color: MUTED }}>
              {r.summary}
            </p>

            <Label>Breaking changes</Label>
            <ItemList items={r.breaking} accent />

            <Label>Added</Label>
            <ItemList items={r.added} />
          </section>
        ))}

        <section className="py-10" style={{ borderTop: `1px solid ${BORDER}` }}>
          <h2 style={{ fontFamily: SERIF, fontSize: 28, color: TEXT }}>Full history</h2>
          <p className="mt-3 max-w-3xl" style={{ fontSize: 16, lineHeight: 1.6, color: MUTED }}>
            Every change, fix and earlier release is in the{' '}
            <ExtLink href={`${BLOB}/CHANGELOG.md`}>changelog</ExtLink>. Packages are on{' '}
            <ExtLink href={PYPI_URL}>PyPI</ExtLink>, and tagged releases are on{' '}
            <ExtLink href={RELEASES_URL}>GitHub</ExtLink>.
          </p>
        </section>
      </div>
    </>
  )
}
