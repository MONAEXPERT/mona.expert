# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.0   | ✅ Active — latest hardened release |
| 0.1.0   | ⚠️ Maintenance — update to 0.2.0 recommended |
| < 0.1.0 | ❌ Unsupported |

Security fixes are applied to the latest stable release. Patch releases are tagged when fixes are validated.

## Reporting a Vulnerability

Please do not open public issues for exploitable vulnerabilities or sensitive findings.

Report security issues privately to the repository owner with:

- A short summary of the issue
- Steps to reproduce
- Impact and affected files or endpoints
- Whether secrets, personal data, or audit logs may be exposed
- Any suggested mitigation

The maintainer should acknowledge receipt, validate impact, prepare a fix, and publish a security note when disclosure is appropriate.

## Triage and Disclosure

- Acknowledge reports within 3 business days when possible.
- Classify impact against the local prototype scope below.
- Fix high-impact secret exposure, policy bypass, or audit integrity issues before a public release.
- Publish release notes or an advisory when users need to rotate data, upgrade, or change deployment behavior.

## Release Security Gates

Before a public release candidate, maintainers should confirm:

- `npm run check` and `npm test` pass locally or in CI.
- Safety-engine, redaction, event-schema, audit-chain, and package-surface tests cover the changed behavior.
- `.mona-dashboard/events.jsonl` contains only fake or approved test data.
- Release notes call out known limitations, security-relevant changes, and any required user action.
- Any new network, credential, or tool-execution path has a reviewed threat model before release.

## Scope

In scope:

- `src/safety-engine.js` decision and redaction behavior
- Local server request handling
- Audit event redaction
- Documentation that could lead to unsafe deployment

Out of scope for the current local prototype:

- Denial of service against a local-only development server
- Findings that require disabling local operating system protections
- Issues in hypothetical production integrations not present in this repository

## Secret Handling

Do not commit real API keys, bearer tokens, private keys, passwords, customer data, or personal data. If a secret is exposed, rotate it immediately and treat any generated audit output as sensitive until reviewed.

Audit events redact common secrets and email addresses, but redaction is best-effort. Treat `.mona-dashboard/events.jsonl` as sensitive local evidence and review it before sharing logs.

If audit evidence must be shared for a security report, prefer the smallest relevant excerpt, replace real identifiers with test values, and preserve `schemaVersion`, `type`, `decision`, `hash`, and `previousHash` fields when they are needed to reproduce an audit-chain finding.

## Current Limitations

The local safety engine is rule-based and should be treated as a defense-in-depth control, not a complete moderation or data-loss prevention system.

The server binds to `127.0.0.1` by default and is intended for local release evaluation. Production deployment requires a reviewed threat model, authentication, authorization, network controls, monitoring, backup handling, and incident response procedures.
