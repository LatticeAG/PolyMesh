<div align="center">

# PolyMesh

**The phone network for AI agents.** An open-sourced protocol — not a product — for agents to discover each other, exchange capabilities, and delegate tasks.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Language: TypeScript](https://img.shields.io/badge/language-TypeScript-3178C6.svg)](https://www.typescriptlang.org/)
[![GitHub stars](https://img.shields.io/github/stars/LatticeAG/PolyMesh?style=social)](https://github.com/LatticeAG/PolyMesh/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/LatticeAG/PolyMesh)](https://github.com/LatticeAG/PolyMesh/issues)
[![CI](https://github.com/LatticeAG/PolyMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/PolyMesh/actions/workflows/ci.yml)

<img align="center" alt="PolyMesh" src="https://img.shields.io/badge/status-experimental-orange">

**The phone network for AI agents.** An open-sourced protocol — not a product.

[What is PolyMesh](#what-is-polymesh) · [Quick Start](#quick-start) · [Why PolyMesh](#why-polymesh) · [Architecture](#architecture) · [Features](#features) · [Examples](#examples) · [Security](SECURITY.md) · [Status](#status) · [License](#license)

</div>

---

## What is PolyMesh?

PolyMesh is an **open protocol** to discover each other, exchange capability declarations, delegate tasks, and coordinate locally.

> **Security:** Read [SECURITY.md](SECURITY.md) before exposing a listener or giving an agent access to data or side-effecting capabilities. The reference implementation is experimental; network deployment requires an explicitly configured secure profile.

Think of it as the **phone network for AI agents**: any agent can pick up the protocol, announce what it can do, and call on another agent without needing cloud infrastructure, a global registry, or a blockchain.

It is designed to be:

- **Local-first** — works on the same machine via Unix sockets, and across a LAN via WebSocket + mDNS.
- **Framework-agnostic** — Hermes Agent, Codex, Claude Code, or your custom agent can all implement it.
- **Self-describing** — every agent publishes an **Agent Card** declaring its identity, capabilities, and endpoints.
- **Internet-optional** — no cloud, no DNS, no chain. Internet bridging is a future opt-in layer.

PolyMesh is part of the [LatticeAG](https://latticeag.com) ecosystem, alongside PolyBrain, PolyGnosis, PolyScribe, and PolyForge.

---

## Quick Start

### Install

```bash
# Clone the reference implementation
git clone https://github.com/mosesman831/polymesh.git
cd polymesh

# Install dependencies and build
npm install
npm run build
```

### Start a local development broker

```bash
# Create an owner-only 32-byte runtime token for this local session.
umask 077
node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))" \
  > "${XDG_RUNTIME_DIR:?}/polymesh-token"

# Plain ws:// is deliberately limited to an explicitly named loopback-dev profile.
npx @polymesh/client start --token-file "${XDG_RUNTIME_DIR}/polymesh-token" --insecure-loopback-dev
```

The local development broker listens on `ws://127.0.0.1:7337` by default and maintains a local registry of connected agents. For LAN or production deployment, use the enrolled WSS profile described in [SECURITY.md](SECURITY.md).

### Connect from a client

```bash
npx @polymesh/client connect ws://127.0.0.1:7337 \
  --token-file "${XDG_RUNTIME_DIR}/polymesh-token" \
  --insecure-loopback-dev
```

### Call another agent

```bash
npx @polymesh/client \
  call calendar-agent org.polymesh.calendar.read '{"date": "2026-07-18"}' \
  --url ws://127.0.0.1:7337 \
  --token-file "${XDG_RUNTIME_DIR}/polymesh-token" \
  --insecure-loopback-dev
```

That’s it. The broker routes the message, the target agent accepts or rejects the task, and you receive progress and completion events.

---

## Why PolyMesh?

| Problem | How PolyMesh solves it |
|---------|------------------------|
| Agents live in silos (Claude Code, Codex, Hermes, custom) | Common wire format + capability vocabulary |
| Discovery requires manual configuration | mDNS + local registry: zero-config on LAN |
| Cloud APIs add latency, cost, and lock-in | Local Unix sockets and loopback WebSockets |
| Agents can't describe what they can do | Agent Cards publish typed capabilities with JSON Schema |
| Task hand-off is ad-hoc | Deterministic lifecycle: submit → accept/reject → progress → complete/cancel |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PolyMesh Network                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐      WebSocket / Unix socket      ┌──────────────┐       │
│   │   Agent A    │ ◄──────────────────────────────► │   Broker     │       │
│   │  (Hermes)    │                                 │   Registry   │       │
│   └──────────────┘                                 └──────┬───────┘       │
│          │                                                │               │
│          │           ┌──────────────┐                     │               │
│          │           │   Agent B    │ ◄───────────────────┘               │
│          └────────►  │   (Codex)    │         mDNS / LAN                   │
│                      └──────────────┘                                      │
│                                                                              │
│   Each agent publishes an Agent Card:                                        │
│   { agent_id, capabilities[{method, input_schema, output_schema}], endpoints }│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Reference implementation

| Package | Purpose |
|---------|---------|
| `@polymesh/broker` | WebSocket broker + local agent registry |
| `@polymesh/client` | Client SDK, CLI, and mDNS LAN discovery |

- **Language:** TypeScript
- **Tests:** 143 Vitest tests (across 26 files)
- **Wire format:** JSON, JSON-RPC inspired
- **Max message size:** 1 MiB

---

## Features

- **Agent Discovery**
  - Local registry via Unix socket
  - LAN discovery via mDNS
  - Optional HTTP hint records
- **Agent Cards**
  - Capability declarations with JSON Schema typed inputs/outputs
  - Automatic exchange on connection
  - Digest-verified card snapshots
- **Task Lifecycle**
  - `task.submit`, `task.accepted`, `task.rejected`, `task.progress`, `task.completed`, `task.cancel`, `task.status`
  - At-least-once delivery with idempotency keys
  - Deadline-aware execution
- **Transports**
  - WebSocket (loopback and LAN)
  - Unix domain sockets (same machine)
- **Security Model**
  - OS-authenticated local sessions
  - Capability-level authorization
  - Resource limits and message framing
- **Error Taxonomy**
  - Structured, machine-readable error codes
  - Clear retry semantics

---

## Why PolyMesh over A2A and alternatives

| | PolyMesh | Google A2A | MCP (Anthropic) |
|---|---|---|---|
| **Architecture** | Peer-to-peer mesh | Client-server over HTTP | Client-server over HTTP |
| **Transport** | WebSocket / Unix socket | HTTPS (REST + SSE) | HTTP + SSE |
| **Internet needed?** | No — works fully offline | Yes — agents need public HTTPS | Yes (stdlib) or local (custom) |
| **Discovery** | mDNS + local registry | Agent Card URL registry | None (manual endpoint config) |
| **Push vs Poll** | Persistent connection, push | Webhook / polling | SSE push (server→client) |
| **Auth** | Unix creds / loopback token / enrolled WSS | OAuth 2.0 + JWKS | None in spec |
| **Latency** | Sub-millisecond (UDS), real-time WS | HTTP request-response (10-100ms+) | HTTP + SSE (similar) |
| **Framework** | Framework-agnostic — any agent implements the spec | Google-centric | Anthropic-centric |
| **Deploy** | `npm install && polymesh start` | Requires DNS, TLS, OAuth infra | Requires HTTP server |
| **Offline** | Full local operation | Impossible | Partial (local transport exists) |
| **License** | MIT | Apache 2.0 | MIT |

### When to choose PolyMesh

- **You want agents to talk on your laptop** without deploying infrastructure
- **You need sub-millisecond latency** for tight agent coordination loops
- **Your agents run in an air-gapped or local environment**
- **You want framework-agnostic** — Hermes, Codex, Claude Code, or your custom agent
- **You want real-time push** — no polling, no webhook configuration

### When A2A makes more sense

- **Cross-organization agent communication** over the public internet
- **You're already in the Google Cloud ecosystem** and want native integration
- **You need a published, multi-vendor standard** with Google's backing

PolyMesh is not a competitor to A2A for the enterprise internet-scale use case. It's an alternative for the **local-first, low-latency, no-infrastructure** use case that A2A explicitly doesn't address — the same way WebSockets didn't replace HTTP, they serve different parts of the stack.



For a local demo, use the token-file and explicit `--insecure-loopback-dev` commands in [Quick Start](#quick-start). Do not use a tokenless listener or put a runtime token in a URL. LAN and production demos require the enrolled WSS profile; see [SECURITY.md](SECURITY.md).

### Programmatic client

```typescript
import { PolyMeshClient } from '@polymesh/client';
import { createAgentCard } from '@polymesh/broker';

const client = new PolyMeshClient({
  card: createAgentCard({ agent_id: 'my-agent' }),
  url: 'ws://127.0.0.1:7337',
  // Read from an owner-only token file or keychain; never embed it in a URL.
  token: process.env.POLYMESH_LOCAL_TOKEN,
  allowInsecureLoopbackDevelopment: true,
});

await client.connect();

const result = await client.call('executor-agent', 'echo', {
  message: 'hello world',
});

console.log(result);
```

---

## Status

> **Version:** 0.2.0 · **Status:** Experimental reference implementation · **Tests:** 143 passing ✅

PolyMesh is under active development. **Current version:** 0.2.0 — **Test suite:** 143 tests across 26 files.

> **⚠️ Experimental:** This is a reference implementation for controlled experimentation. Review [SECURITY.md](SECURITY.md) before deploying with sensitive data, privileged handlers, LAN exposure, or internet access. No production security profile is claimed without a release explicitly documenting otherwise.

### Roadmap

- [x] Core protocol specification
- [x] TypeScript reference implementation
- [x] Local broker + client
- [x] mDNS LAN discovery
- [x] Internet bridging via Cloudflare Workers (spec)
- [x] DeckAgent tunnel carrier (implemented)
- [ ] Additional language implementations

---

## Links

- **Security guidance and disclosure:** [`SECURITY.md`](./SECURITY.md)
- **Repository:** https://github.com/LatticeAG/PolyMesh
| **Ecosystem:** https://latticeag.vercel.app
- **Related protocols:**
  - PolyBrain
  - PolyGnosis
  - PolyScribe
  - PolyForge

## License

PolyMesh is released under the [MIT License](LICENSE).

A [LatticeAG](https://latticeag.vercel.app) protocol.
