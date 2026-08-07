<div align="center">

# mona.expert

**Secure AI Agent Wrapper — injection-proof, auditable, environment-controlled.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](./CHANGELOG.md)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](./.nvmrc)
[![Tests](https://img.shields.io/badge/tests-161%20passing-success.svg)](./test)

[Website](https://mona.expert) · [Dashboard](https://wrapper.mona.expert) · [Pricing](https://mona.expert/pricing.html) · [Security Policy](./SECURITY.md)

</div>

---

mona.expert is a lightweight security wrapper for AI agents. It runs alongside any
LLM application, detects prompt-injection attempts in real time, records every API
call and analysis in a tamper-evident audit log, and connects to a web dashboard for
centralized management.

> **Non-profit oriented.** mona.expert is run as a mission-driven project — we cover
> our costs, we don't maximize profit. The open-source core is free forever. Hosted
> subscriptions and enterprise licenses fund development so the core stays accessible
> to students, researchers, NGOs, and small teams.

## Quick start

One command — non-interactive, auto-starts the wrapper:

```bash
curl -fsSL https://mona.expert/download/install.sh | bash -s -- --start
```

Then connect your wrapper to your web account:

```bash
# Create an account at https://wrapper.mona.expert to get your token
mona-expert connect mxn_your_token_here
mona-expert start
```

## How to use it

| Tier | Price | For whom |
|------|-------|----------|
| Open Source (self-host) | Free forever | Anyone — full features, no limits |
| Hosted (SaaS) | Subscription (covers costs) | Teams who don't want to self-host |
| On-Prem / Enterprise | Custom | Air-gapped, regulated, NGO-discounted |

NGOs and non-profits: reduced or free terms are available — see
[pricing](https://mona.expert/pricing.html) or get in touch.

## Features

- **Sentinel agent** — locked-down safe environment (0700 sandbox, zero secrets on
  disk), continuous system/agent/security monitoring, and wrapper-gateway routing:
  all outbound traffic goes through `wrapper.mona.expert`, with MySQL/FTP health
  checks performed by the wrapper (credentials never touch the agent).
- **Injection guard** — real-time detection of prompt injection, role-play,
  delimiter escapes, and encoded payloads.
- **Full audit trail** — every LLM call, API request, and agent action is logged
  with tokens, cost, and duration, in a hash-linked chain.
- **Website connection** — link a local wrapper to a web account with a single token.
- **Multi-agent management** — install, configure, and control multiple agents from
  the dashboard.
- **mTLS-ready** — designed for optional mutual-TLS authentication.
- **LLM proxy** — route LLM requests through the wrapper for full observability.

## Commands

| Command | Description |
|---------|-------------|
| `mona-expert setup` | First-time configuration |
| `mona-expert start` | Start the wrapper server |
| `mona-expert connect <token>` | Link wrapper to web account |
| `mona-expert status` | Show wrapper and agent status |
| `mona-expert agent list` | List installed agents |
| `mona-expert doctor` | Run diagnostics |

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Browser /   │     │  Website Gateway │     │  Wrapper     │
│  Dashboard   │────▶│  (PHP + MySQL)   │────▶│  (Node.js)   │
│              │     │                  │     │              │
│  Account,    │     │  Auth, Tokens,   │     │  Injection   │
│  Agent Mgmt  │     │  Audit Store     │     │  Guard, LLM  │
└──────────────┘     └──────────────────┘     │  Proxy,      │
                                              │  Agent Mgmt  │
                                              └──────────────┘
```

## Wrapper API (localhost:4189)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/status` | GET | Wrapper status |
| `/api/security-check` | POST | Scan text for injection |
| `/api/llm` | POST | Proxy LLM request (guarded) |
| `/api/audit` | GET | Local audit log |
| `/api/agents` | GET | List installed agents |
| `/api/agents/install` | POST | Install a new agent |
| `/api/sync` | POST | Remote sync from website |

## Requirements

- Node.js >= 20
- macOS, Linux, or WSL2
- Internet connection for website features

## License & compliance

- Open-source core under the [MIT License](./LICENSE). The packaged commercial
  release is licensed separately (single-user, machine-bound).
- Built for **GDPR / EU AI Act** transparency: consent manager, full audit log, mTLS.
- We make **no unverified certification claims** — every compliance feature is code
  you can inspect. See [`SECURITY.md`](./SECURITY.md) for reporting vulnerabilities.

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and our
[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) before opening a pull request.

---

<div align="center">
<sub>Built for people who need AI agents they can actually trust.</sub>
</div>
