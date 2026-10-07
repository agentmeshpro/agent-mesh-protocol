# Security Policy

## Reporting a Vulnerability

The Agent Mesh Protocol takes security seriously. We appreciate responsible
disclosure of vulnerabilities found in the protocol specification or this
reference implementation.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, report them privately through one of these channels:

1. **GitHub private vulnerability reporting (preferred):**
   [open a draft security advisory](https://github.com/agentmeshpro/agent-mesh-protocol/security/advisories/new).
   Only the maintainers can see it, and we can collaborate on a fix and
   a CVE in the same place.
2. **Email:** **security@ampro.sh**.

Include in your report:
- Description of the vulnerability and its potential impact
- Steps to reproduce
- Affected versions (if known)
- Suggested mitigation (if you have one)
- Whether you wish to be credited in the disclosure

## Supported Versions

Security fixes are released for the latest minor version only. Until 1.0,
upgrade to the newest release to receive fixes.

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Response Process

| Stage | Target |
|-------|--------|
| Acknowledge receipt | Within 72 hours |
| Initial triage + severity assessment | Within 7 days |
| Fix + coordinated disclosure | Within 90 days for HIGH/CRITICAL; longer for complex issues |

We follow coordinated disclosure: we ask reporters to refrain from public
disclosure until a fix is released and downstream implementers have had
reasonable time to update.

## Scope

In scope:
- Vulnerabilities in the `ampro` Python reference implementation
- Specification ambiguities that lead to insecure implementations
- Cryptographic flaws in the protocol design
- Auth, trust, or authorization bypasses

Out of scope:
- Vulnerabilities in third-party platforms that consume `ampro`
- Issues requiring physical access to a host
- Social-engineering or phishing reports

## Past Security Reviews

The protocol has undergone two formal security audits:

- **v0.2.0 audit** — see `docs/SECURITY-AUDIT.md`. 47 findings (13 CRITICAL, 14 HIGH, 14 MEDIUM, 6 LOW). All P0/P1 closed in v0.2.1.
- **v0.2.1 re-audit** — see `docs/SECURITY-AUDIT-V2.md`. Verified fix effectiveness, identified bypasses. All CRITICAL+HIGH closed in v0.2.3.

The v0.2.3 release closed all 66 CRITICAL+HIGH security findings from the
Phase 0 sprint. See `CHANGELOG.md` §0.2.3.

## Hall of Fame

We thank the following researchers for responsibly disclosing vulnerabilities:

_(empty — be the first!)_
