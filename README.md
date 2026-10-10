# LatticeAG PolyMesh 🌐

<p align="center">
  <a href="https://github.com/LatticeAG/PolyMesh/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/LatticeAG/PolyMesh?style=for-the-badge" alt="License" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh/actions/workflows/ci-full.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/LatticeAG/PolyMesh/ci-full.yml?branch=main&style=for-the-badge&label=CI" alt="CI" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/LatticeAG/PolyMesh/release.yml?branch=main&style=for-the-badge&label=Release" alt="Release" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh/stargazers">
    <img src="https://img.shields.io/github/stars/LatticeAG/PolyMesh?style=for-the-badge" alt="GitHub stars" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh/issues">
    <img src="https://img.shields.io/github/issues/LatticeAG/PolyMesh?style=for-the-badge&label=Issues" alt="GitHub issues" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh">
    <img src="https://img.shields.io/github/languages/top/LatticeAG/PolyMesh?style=for-the-badge" alt="Top language" />
  </a>
  <a href="https://github.com/LatticeAG/PolyMesh">
    <img src="https://img.shields.io/badge/TypeScript-5.8-blue?style=for-the-badge&logo=typescript" alt="TypeScript" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  </a>
</p>

<blockquote>
<p><strong>MCP gave agents tools. A2A gave agents a phone book. PolyMesh gives them a neighborhood - routing, rooms, permissions, and it works offline.</strong></p>
</blockquote>

<p align="center">
  Local-first agent mesh. TypeScript + Python. Internet optional.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#why-polymesh">Why PolyMesh</a> ·
  <a href="#packages">Packages</a> ·
  <a href="#speak-a2a-wire-vs-product">Speak A2A</a> ·
  <a href="docs/positioning.md">Positioning</a> ·
  <a href="#offline-re-route-demo">Offline demo</a> ·
  <a href="#how-it-works">How It Works</a> ·
  <a href="#configuration-precedence">Configuration</a> ·
  <a href="#file-tree">File Tree</a> ·
  <a href="#known-issues">Known Issues</a>
</p>

---

PolyMesh is an open, local-first protocol for agents to declare capabilities and exchange bounded tasks. Agents discover each other through a lightweight broker, negotiate capability contracts, and execute tasks with verified lifecycle events. No cloud required for the local path.

Built as the LatticeAG Poly series protocol layer. Works with any framework, any language, any runtime.

Full competitive matrix, four locked positioning statements, honest limits, and FAQ: **[docs/positioning.md](docs/positioning.md)**.

## Why PolyMesh

- **Capability routing, not hardcoded addresses** - agents declare what they can do in Agent Cards; the broker dispatches tasks to registered capabilities across a changing membership set.
- **Local-first, works offline** - the full task lifecycle runs over loopback WebSocket with no cloud, no accounts, no public endpoints. Three agents on a laptop can lose a worker mid-task and re-route to a peer (see [Offline demo](#offline-re-route-demo)).
- **Framework-agnostic** - TypeScript broker/client/CLI plus a Python SDK speaking the same protocol, pinned by shared compatibility vectors. Any language, any runtime, any agent framework.
- **Bounded tasks with verified lifecycle** - validated envelopes, contract-aligned payloads, accepted -> progress -> terminal completion or rejection. No fire-and-forget JSON over the wall.
- **Security fails closed** - loopback-only by default for local dev; remote transport is explicitly configured WSS with mutual enrollment and TLS; mDNS is opt-in hints that convey no trust and never auto-enroll.

### How PolyMesh is different

MCP gave agents tools and A2A gave them a wire protocol between known endpoints. PolyMesh is the product layer above the wire: integrated capability routing, rooms, permissions, and offline re-route in one local-first runtime - while still speaking A2A as a leaf dialect where the ecosystem requires it. Full matrix and locked positioning: [docs/positioning.md](docs/positioning.md).

## Quick Start

```bash
# Create a new project from the starter template
npx @latticeag/create-polymesh-app my-agents
cd my-agents
npm install
npm run demo
```

The demo starts a local broker and client, exchanges a safe ping/pong, and exits cleanly.

For a process-boundary demonstration with multiple agents:

```bash
docker compose up --build
```

It prints the broker, Alice, and Bob lifecycle and exits when Alice receives Bob's echo result.

> **Experimental software**: Review [SECURITY.md](SECURITY.md) before exposing a listener or allowing any side-effecting capability. PolyMesh does not provide a hosted relay in this repository.

## Packages

| Package | Layer | Purpose | Language |
| --- | --- | --- | --- |
| `@latticeag/polymesh-broker` | PRODUCT | WebSocket broker and local registry | TypeScript |
| `@latticeag/polymesh-client` | PRODUCT | Client SDK, CLI, capability router | TypeScript |
| `@latticeag/polymesh-a2a` | WIRE (leaf dialect) | A2A adapter; ships with M5 | TypeScript |
| `@latticeag/polymesh-gateway` | WIRE / relay | Blind native REST/SSE/WSS relay | TypeScript |
| `@latticeag/create-polymesh-app` | app | Starter generator for the ping/pong example | TypeScript |
| `latticeag-polymesh` | PRODUCT | Python SDK; import as `polymesh` | Python |

PRODUCT owns routing, rooms, permissions, task lifecycle, and local-first runtime. WIRE speaks standards as dialects at the leaf. The gateway stays a blind pipe.

## Speak A2A (WIRE vs PRODUCT)

> We don't compete with A2A. We speak it. The mesh routes by capability; the wire is whatever the ecosystem speaks.

| Layer | What it is | PolyMesh role |
| --- | --- | --- |
| STANDARDS | A2A, MCP, ACP | Adopted. Never competed with. |
| WIRE | Native envelopes + A2A JSON-RPC as a dialect | Leaf translation in `@latticeag/polymesh-a2a` / `polymesh-a2a` |
| PRODUCT | Capability routing, rooms, permissions, offline re-route | Where PolyMesh differentiates |

A2A WIRE is point-to-point. Multi-agent runtimes on top of A2A exist independently (ADK, community routers). PolyMesh's differentiation is integrated routing + rooms + local-first in one product layer.

If you already have two known HTTPS agents and a static topology, use A2A alone. Use PolyMesh when you need capability dispatch across a changing membership set, rooms, offline operation, or bounded re-route when a worker fails. Details: [docs/positioning.md](docs/positioning.md).

### Short comparison

| Capability | PolyMesh | A2A | ACP | AgentChat | Caspian |
| --- | --- | --- | --- | --- | --- |
| Agent-to-agent | YES | YES | n/a (UI) | YES | no (A2H) |
| Capability-based routing | YES | no (address) | n/a | no (address) | no |
| Multi-agent topology / rooms | YES | no (wire P2P; runtimes on top exist) | n/a | DMs + @mention groups; no capability re-route; hosted | no |
| Local-first, offline | YES | no (needs endpoints) | n/a | no (hosted) | no |
| Structured task lifecycle | YES | YES (endpoint-local); distributed re-route n/a | n/a | chat | no |
| Interops with A2A | YES (v6 spec; ships with M5) | native | n/a | via A2A | via A2A |

Bold product-layer cells are the only fair "we win" claims. Full matrix + evidence: [docs/positioning.md](docs/positioning.md).

## Offline re-route demo

Three agents on a laptop, no internet. One drops mid-task. The mesh re-routes to a peer with the same capability. Zero config, no public endpoints.

```bash
./scripts/demo-offline-reroute.sh
```

This is also an executable conformance test (`tests/demo-offline-reroute.test.ts`) that asserts all nine §D.3.6 observations in order. See [scripts/offline-reroute/README.md](scripts/offline-reroute/README.md).

The TypeScript CLI is provided by `@latticeag/polymesh-client`:

```bash
npx @latticeag/polymesh-client help
```

Configuration is TOML-based, read from `~/.config/polymesh/config.toml` by default. Use `POLYMESH_CONFIG` or `--config FILE` to select another file:

```bash
npx @latticeag/polymesh-client config show
```

## How It Works

```mermaid
flowchart LR
  A[Alice Agent] -->|task.submit| B[Local Broker]
  B -->|task.submit| C[Bob Agent]
  C -->|accepted/progress/completed| B
  B -->|lifecycle events| A

  A -.->|Agent Card: capabilities| B
  C -.->|Agent Card: capabilities| B
```

Each agent publishes an **Agent Card** with its identity and capability contracts. A task is validated against the target contract, accepted or rejected, and ends in one terminal lifecycle event. The broker routes tasks between agents using registered capabilities, not hardcoded addresses.

### Core Protocol Flow

| Phase | Description |
|-------|------------|
| **Discovery** | Agents announce capabilities via broker registry or opt-in mDNS hints |
| **Handshake** | Capability negotiation and profile selection (`polymesh` v0.1 or `polymesh.0.2` native) |
| **Task Submission** | Validated task envelope with contract-aligned payload |
| **Lifecycle** | Accepted -> progress events -> terminal completion or rejection |
| **Compression** | Optional zstd framing for `polymesh.0.2` native profile |

## Configuration Precedence

The TypeScript CLI merges settings in this order:

```
defaults < TOML config file < environment variables < command-line flags
```

Supported TOML sections are `[broker]`, `[client]`, and `[discovery]`. Keep credentials in the configured token file, not in command arguments, URLs, or source code.

Verified defaults (from `polymesh config show` against the stock config):

| Setting | Default |
| --- | --- |
| `broker.host` / `broker.port` | `127.0.0.1` / `7337` |
| `client.default_timeout` | `60000` ms |
| `client.reconnect` | `false` |
| `discovery.mdns_enabled` | `false` (opt-in hints only) |

Full command surface (from `polymesh --help`): `config show`, `start`, `connect`, `peers`, `capabilities`, `call`. `connect` also accepts `--gateway-url` / `--api-key` for the internet relay (see [PolyMesh Gateway](#polymesh-gateway)).

## Support Matrix

| Capability | Status in v0.5.0 | Notes |
| --- | --- | --- |
| v0.1 local task lifecycle | Supported | TypeScript broker/client and Python SDK are covered by shared compatibility vectors |
| `polymesh.0.2` native SDK profile | Experimental | Explicit opt-in with profile negotiation and optional zstd framing |
| v2 gateway REST/SSE adapter | Experimental, loopback-only | Node reference adapter for local `/v2/tasks` and `/v2/events` |
| mDNS discovery | TypeScript supported, Python pending | Opt-in, WSS-only; hint-based, never auto-enrollment |
| Remote transport | Explicitly configured WSS only | Mutual enrollment and TLS requirements fail closed |
| Docker Compose demo | Supported local fixture | Repeatable development demo, not production architecture |
| DeckAgent carrier | Client-side experimental | No production DeckAgent service or relay deployment |

### Profile Support

| Profile | TypeScript | Python | Security Boundary |
| --- | --- | --- | --- |
| Numeric-loopback dev WebSocket | Supported | Supported (v0.1) | Local development only; never bridge across LAN/Internet |
| `polymesh.0.2` native profile | Experimental explicit opt-in | Experimental explicit opt-in | Scoped to selected broker mesh |
| Enrolled WSS | Supported | Not advertised as general secure-carrier | Mutual enrollment and TLS fail closed |
| mDNS WSS discovery hints | Supported, opt-in | Optional dependency | Discovery conveys no trust, never initiates enrollment |
| Hosted/remote relay | Not available | Not available | Planned separately |

## Verification

The v0.5.0 release gate runs clean installs, TypeScript type checking/build/tests, Python tests/builds, package artifact smoke tests, and shared compatibility fixtures.

From a source checkout:

```bash
npm ci
npm run typecheck
npm test
npm run build

uv sync --dev
uv run pytest -q
uv build
```

## Architecture

For the full architectural overview and dependency graph, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Test Report

41 TypeScript test files (262 tests) + 129 Python tests pass, including the shared compatibility vectors covering both v0.1 and `polymesh.0.2` profiles and the offline re-route conformance test. TypeScript typecheck (`tsc --noEmit`) is clean. See [TEST-REPORT.md](TEST-REPORT.md) for the per-file breakdown.

## Scope and Limitations

PolyMesh does **not** claim:

- A competing wire format, or "A2A alternative / killer"
- Hosted DM identity / WhatsApp-for-agents (AgentChat's lane)
- Editor UI protocol leadership in v6 (ACP deferred to v7)
- Agent-to-human channel suite (Caspian's lane)
- Generic end-to-end envelope signing or delegated authorization grants
- Continuous task-output streaming or generic pub/sub
- A hosted Worker relay inside this repository (see [polymesh-gateway](https://github.com/LatticeAG/polymesh-gateway))

Gateway SSE is task-event observation, not general streaming or a topic system.

Messaging bans and reviewer checklist: [docs/positioning.md](docs/positioning.md#messaging-bans).

## File Tree

```text
polymesh/
├── packages/
│   ├── broker/            # @latticeag/polymesh-broker - WebSocket broker + registry
│   ├── client/            # @latticeag/polymesh-client - SDK, CLI (polymesh), router
│   ├── a2a/               # @latticeag/polymesh-a2a - A2A leaf dialect adapter
│   └── gateway/           # @latticeag/polymesh-gateway - local v2 REST/SSE adapter
├── templategen/packages/create-polymesh-app/  # starter generator (template/ has demo.js)
├── src/polymesh/          # latticeag-polymesh - Python SDK
├── tests/                 # 41 Vitest suites incl. compat vectors + offline re-route
├── conformance/           # shared compatibility vectors (TS + Python)
├── schemas/               # capability contract schemas
├── scripts/               # incl. demo-offline-reroute.sh + offline-reroute/
├── docs/                  # positioning.md + design docs
├── ARCHITECTURE.md  TEST-REPORT.md  SECURITY.md  AGENTS.md
└── docker-compose.yml     # Alice/Bob/broker process-boundary demo
```

## Known Issues

- **better-sqlite3 needs a native rebuild on some machines** - the broker's `postinstall` probes the native binding at install time and rebuilds it automatically when it fails to load. If durable-store suites still fail with `Module did not self-register` (e.g. a `node_modules` reused across a Node version change), run `npm rebuild better-sqlite3` inside `packages/broker` and re-run `npm test`. All failures observed to date were this environment issue, never protocol regressions.
- **No hosted relay in this repository** - anything beyond loopback/WSS needs the separate [polymesh-gateway](#polymesh-gateway) deployment. This is intentional (local-first), not a missing feature.
- **mDNS is hints only** - discovery conveys no trust and never auto-enrolls; WSS still requires explicit mutual enrollment.

## Development Feedback

When reporting an issue, include the package versions, selected profile, redacted command output, and a minimal reproduction. Do not include runtime tokens, private keys, certificates, raw task data, or confidential specifications.

## License

PolyMesh is released under the [MIT License](LICENSE). Built by [LatticeAG](https://github.com/LatticeAG).

---

### PolyMesh Gateway

**Product vs infra, in one line: this repo is the product (protocol, broker, SDKs, local runtime). The gateway repo is the infra (hosted internet relay you deploy yourself).**

Want to take PolyMesh beyond localhost? The [**polymesh-gateway**](https://github.com/LatticeAG/polymesh-gateway) is a separate Cloudflare Workers relay (Workers + D1 + one Durable Object per mesh) that connects agents across the internet. Same task envelopes and lifecycle events - only the transport changes.

- **Agent meshes** — join named rooms with invite codes. Friends, dev teams, personal agents.
- **Capability discovery** — find peers by what they can do, not just by address.
- **Blind router** — the gateway routes envelopes; permission decisions stay on your agent.
- **Free-tier CF** — Workers + D1 + Durable Objects. No infra costs for small meshes.
- **Direct WSS** — each agent connects its own socket. No broker bridge needed.

```bash
# Deploy your own relay (in a checkout of LatticeAG/polymesh-gateway)
npx wrangler deploy
```

```ts
// From your agent (client.connectGateway supports apiKey + gatewayUrl)
await client.connectGateway({
  apiKey: "<pmgk_...>",
  gatewayUrl: "wss://your-gateway.workers.dev",
});
```

See the [polymesh-gateway repo](https://github.com/LatticeAG/polymesh-gateway) for deployment, API docs, and full protocol spec.