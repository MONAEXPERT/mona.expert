# Contributing

Thanks for helping improve `mona.expert`.

## Local Checks

Run these before opening a pull request:

```sh
npm run check
npm test
```

The project currently uses Node ESM and no dependencies. Please avoid adding dependencies unless the release benefit clearly outweighs the extra supply-chain and maintenance cost.

For changes that affect runtime behavior, also run the local server with `npm start`, submit a representative request to `/api/safety-run`, and confirm the dashboard audit stream records the decision without real secrets or personal data.

## Development Guidelines

- Keep changes small and reviewable.
- Prefer local-first behavior and avoid network calls in tests.
- Preserve the local-only safety posture unless a change explicitly introduces a reviewed integration.
- Add tests for safety-engine behavior when changing policy rules, thresholds, controls, or redaction.
- Update documentation when user-facing commands, decisions, controls, or security assumptions change.

## Pull Requests

Include:

- What changed
- Why it changed
- Commands run
- Security impact
- Audit or release-readiness impact
- Any known limitations

Update `docs/GITHUB_RELEASE_READINESS.md` when a release gate changes, and update `docs/COMPLIANCE_MATRIX.md` when the evidence for a control changes.

## Security Findings

Do not file public issues for sensitive vulnerabilities. Follow [SECURITY.md](SECURITY.md).
