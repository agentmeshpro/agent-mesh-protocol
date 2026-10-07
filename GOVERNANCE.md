# AMP Governance

This document covers how the Agent Mesh Protocol specification changes,
how it is versioned, and what implementers can rely on. It governs the
protocol. The `ampro` Python package follows [RELEASING.md](RELEASING.md).

## What the specification is

The protocol is defined by these artefacts, in order of precedence:

1. **[docs/WIRE-BINDING.md](docs/WIRE-BINDING.md)** is normative. RFC 2119
   keywords (MUST, SHOULD, MAY) mean what RFC 2119 and RFC 8174 say.
2. **[docs/PROTOCOL-CONTRACTS.md](docs/PROTOCOL-CONTRACTS.md)** is normative
   for the semantics that span body types: errors, schema evolution, event
   ordering, federation, jurisdiction, cache invalidation and retries.
3. **[spec/](spec/)** holds the machine-readable form: JSON Schemas, OpenAPI
   3.1 and the registries. It is generated from the reference
   implementation and the tables in WIRE-BINDING. CI fails when it drifts.
   If it ever disagrees with the prose, the prose wins, and the
   disagreement is a bug to fix in the same release.
4. **[tests/vectors/](tests/vectors/)** are the conformance vectors. A vector
   that contradicts the prose is a bug in one of them.
5. **`ampro-conformance`** ([docs/CONFORMANCE.md](docs/CONFORMANCE.md)) is
   the black-box test of a running implementation.

`ampro` is the reference implementation, not the specification. If a
behaviour exists only in `ampro`, it is not a protocol requirement.

## Roles

- **Maintainers** merge changes and cut releases. They are listed in
  `.github/CODEOWNERS`. A maintainer who has not reviewed or merged a change in 12
  months becomes emeritus.
- **Spec editors** are the maintainers who own WIRE-BINDING and the
  registries. Every normative change needs approval from at least one
  spec editor who did not write it.
- **Implementers** are anyone shipping an independent AMP implementation.
  Implementers who report passing `ampro-conformance` results are invited
  to review every proposal that changes the wire format.
- **Contributors** are anyone else. Anyone can propose a change.

New maintainers are nominated by an existing maintainer and confirmed by
lazy consensus of the maintainers over 7 days.

## How a change is made

Every change to protocol behaviour starts as an **AMP proposal**. Use the
[spec proposal issue template](.github/ISSUE_TEMPLATE/spec_proposal.md).
Editorial fixes (typos, clarifications that change no requirement, and
broken links) can go straight to a pull request.

1. **Proposal.** Open an issue with the motivation, the wire-level design,
   the compatibility class (below) and the conformance impact. The test in
   [CONTRIBUTING.md](CONTRIBUTING.md) applies: if two independent
   implementations need to agree on it, it is protocol. Otherwise it is
   implementation guidance, or an [extension](docs/EXTENSIONS.md).
2. **Discussion.** The issue stays open for comment for at least **14 days**
   for a MINOR change and **30 days** for a MAJOR change. Security fixes
   may shorten this (see below).
3. **Decision.** The spec editors decide by lazy consensus. A maintainer
   objection must give a technical reason, and is resolved by discussion
   or by a simple majority vote of the maintainers. The decision and its
   reasons are recorded on the issue, which is then labelled `accepted`
   or `declined`.
4. **Pull request.** An accepted proposal lands as one pull request that
   updates all of these together:
   - the WIRE-BINDING text and any PROTOCOL-CONTRACTS text;
   - the reference models, and the files regenerated with
     `python scripts/generate_spec.py`;
   - test vectors for any new schema or signed artefact;
   - a conformance check, when the behaviour is observable over HTTP;
   - a CHANGELOG entry.
5. **Release.** The change ships in the next protocol release of the
   matching class.

A proposal for a new body type, header or event SHOULD first ship as a
namespaced [extension](docs/EXTENSIONS.md). Evidence from that experiment
is the strongest argument for standardising it.

## Versioning

The protocol has its own [SemVer 2.0.0](https://semver.org) version, for
example `1.0.0`. It is carried in `agent.json` (`protocol_version`) and in
the `Protocol-Version` header, and negotiated with `Accept-Version`
(WIRE-BINDING 18.4). It is separate from the `ampro` package version.

| Class | When | Examples |
|---|---|---|
| **MAJOR** | A conforming receiver of the previous version could reject, or silently misread, a conforming message of the new one | A new required field, or a removed body type, header or field. A changed field type or meaning, or a narrowed enum. A changed canonical form of a signed artefact. |
| **MINOR** | Additive. Every conforming peer of the previous MINOR stays conforming | New optional fields, body types, headers, stream events, error types, extension URIs, enum values, or endpoints at a level ≥ 1 |
| **PATCH** | No change to any requirement | Clarifications, examples, typo fixes, more vectors or conformance checks for existing requirements |

[PROTOCOL-CONTRACTS section 2](docs/PROTOCOL-CONTRACTS.md#2-schema-evolution)
lists the change classes in detail. While the protocol is at `1.x`, the
`since` fields in `spec/registry/` give the version that introduced each
name. A value below 1.0.0 refers to the `ampro` release before the 1.0.0
freeze.

## Compatibility guarantees

Within one protocol MAJOR version:

- A message that conforms to version `M.n` also conforms to every later
  `M.x`.
- Receivers MUST ignore unknown body types, headers, fields, stream
  events and `agent.json` members (WIRE-BINDING 5.1.4, 5.1.5 and 4.1.2).
  This is why MINOR additions are safe.
- Receivers MUST accept any well-formed version with a MAJOR they
  support, and MUST NOT reject one because of its MINOR, PATCH,
  pre-release or build component (18.4).
- Registry names (body types, headers, error URNs, extension URIs, event
  types) are never reassigned to a different meaning. A removed name
  stays reserved.
- `$id`s under `https://github.com/agentmeshpro/agent-mesh-protocol/spec/`
  are permanent. A schema can gain optional properties within a MAJOR,
  but it never loses accepted inputs.

**Security exception.** When a flaw makes a signed or verified artefact
unsafe, the maintainers may change that artefact in a MINOR release. Such
a release must:

- publish a security advisory (see [SECURITY.md](SECURITY.md));
- list the affected artefacts under "Security exceptions" in
  PROTOCOL-CONTRACTS and in the CHANGELOG;
- ship regenerated vectors.

Peers on both sides must then upgrade together. The 0.4.0 session,
delegation, federation, DID and RFC 9421 changes were made under this
rule.

## Deprecation

- A deprecated element is marked `"status": "deprecated"` in
  `spec/registry/`, with `deprecated_in` and, when known, `replaced_by`.
  WIRE-BINDING and the CHANGELOG say what replaces it.
- A deprecated element keeps working for at least **two MINOR releases and
  at least 6 months**, whichever is longer. It is removed only in a MAJOR
  release.
- A deprecated element MUST still be accepted by receivers during that
  window. Senders SHOULD stop emitting it.
- A whole protocol version is deprecated by announcing an end-of-support
  date. Servers SHOULD send the `Sunset` header (18.5) for that version
  from then on. A supported MAJOR is kept for at least **12 months** after
  the next MAJOR is released.

## Extensions and registration

Anyone can define body types, headers, error types, stream events and
extension URIs in a namespace they control, without asking permission
and without forking the protocol. [docs/EXTENSIONS.md](docs/EXTENSIONS.md)
gives the naming rules.

Registration in `spec/third-party.json` is optional and
first-come-first-served. It exists for discoverability. Maintainers
review only the naming rules, completeness and clashes, not merit, and
SHOULD respond within 14 days. Only maintainers may assign names in the
reserved AMP namespaces (the AMP body-type namespaces, `urn:amp:`, the
`X-AMP-` header prefix and URIs under
`https://github.com/agentmeshpro/agent-mesh-protocol/`), and only through the
proposal process above.

## Changing this document

Changes to this document follow the MAJOR proposal process: 30 days of
discussion, then approval by a majority of maintainers.
