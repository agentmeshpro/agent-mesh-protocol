---
name: Spec proposal
about: Propose a change or addition to the AMP protocol specification
title: '[PROPOSAL] '
labels: proposal
assignees: ''
---

<!--
Read first:
- GOVERNANCE.md: how proposals are discussed and decided, versioning
  (MAJOR/MINOR/PATCH), compatibility guarantees and deprecation windows.
- docs/EXTENSIONS.md: most additions can ship today as a namespaced
  extension (com.example.*, X-Example-*, urn:com.example:error:*) with no
  proposal. Consider shipping one first and linking to the experience here.
-->

## Summary

One-paragraph description of what you are proposing.

## Motivation

What problem does this solve? What is the use case? Why can't existing
protocol mechanisms, or a [namespaced extension](../../docs/EXTENSIONS.md),
address it? Would two independent implementations need to agree on it
to interoperate?

## Detailed Design

How would this work concretely? Cover the wire format, headers, body
schemas (JSON Schema 2020-12 preferred), HTTP status codes and problem
types, and the trust and compliance implications. Name the
WIRE-BINDING sections it changes.

## Compatibility class

- [ ] PATCH: clarification only, no requirement changes
- [ ] MINOR: additive; every conforming peer of the previous MINOR stays conforming
- [ ] MAJOR: a conforming receiver of the current version could reject or misread it
- [ ] Security exception (see GOVERNANCE.md)

What is the migration and deprecation path for existing implementations?

## Machine-readable spec and conformance

- Registries in `spec/registry/` to add or change (body types, headers,
  errors, extension URIs, stream events):
- Schemas in `spec/schemas/` affected:
- New or changed test vectors in `tests/vectors/`:
- New `ampro-conformance` checks, if the behaviour is observable over HTTP:

## Alternatives Considered

What else did you consider? Why this approach?

## Prior Art / Implementation Experience

Was this tried as an extension first? Are there other implementations or
deployments?

## Open Questions

What's still undecided?
