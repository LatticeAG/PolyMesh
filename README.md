<div align="center">

# PolyMesh

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Language: TypeScript](https://img.shields.io/badge/language-TypeScript-3178C6.svg)](https://www.typescriptlang.org/)
[![GitHub stars](https://img.shields.io/github/stars/mosesman831/polymesh?style=social)](https://github.com/mosesman831/polymesh/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/mosesman831/polymesh)](https://github.com/mosesman831/polymesh/issues)
[![GitHub clones](https://img.shields.io/badge/clones-live-20c997)](https://github.com/mosesman831/polymesh/graphs/traffic)
[![GitHub traffic](https://img.shields.io/github/commit-activity/m/mosesman831/polymesh)](https://github.com/mosesman831/polymesh/graphs/traffic)

**The phone network for AI agents.**

An open, local-first protocol for agent-to-agent communication.

[What is PolyMesh](#what-is-polymesh) · [Quick Start](#quick-start) · [Why PolyMesh](#why-polymesh) · [Architecture](#architecture) · [Features](#features) · [Examples](#examples) · [Status](#status) · [License](#license)

</div>

---

## What is PolyMesh?

PolyMesh is an **open protocol** — not a product — for AI agents to discover each other, exchange capability declarations, delegate tasks, and coordinate locally.

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

### Start a broker

```bash
npx @polymesh/broker
```

The broker listens on `ws://127.0.0.1:8080` by default and maintains a local registry of connected agents.

### Connect from a client

```bash
npx @polymesh/client --connect ws://127.0.0.1:8080 --agent-id my-agent
```

### Call another agent

```bash
npx @polymesh/client \
  --connect ws://127.0.0.1:8080 \
  --target calendar-agent \
  --method org.polymesh.calendar.read \
  --params '{"date": "2026-07-18"}'
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
- **Tests:** 17 Vitest tests
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

## Examples / Demo

### Two agents on the same broker

Terminal 1 — start a broker:

```bash
npx @polymesh/broker --port 8080
```

Terminal 2 — register an executor agent:

```bash
npx @polymesh/client \
  --connect ws://127.0.0.1:8080 \
  --agent-id executor-agent \
  --capability '{"method":"echo","input_schema":{"type":"object"}}'
```

Terminal 3 — send it a task:

```bash
npx @polymesh/client \
  --connect ws://127.0.0.1:8080 \
  --agent-id caller-agent \
  --target executor-agent \
  --method echo \
  --params '{"message": "hello world"}'
```

### Programmatic client

```typescript
import { PolyMeshClient } from '@polymesh/client';

const client = new PolyMeshClient({
  brokerUrl: 'ws://127.0.0.1:8080',
  agentId: 'my-agent',
});

await client.connect();

const result = await client.call('executor-agent', 'echo', {
  message: 'hello world',
});

console.log(result);
```

---

## Status

> **Version:** 0.1.0 · **Status:** Draft specification + reference implementation

PolyMesh is under active development. The wire format, message types, and Agent Card schema are defined in `SPEC.md`. The reference implementation passes the current test suite and is ready for experimentation.

### Roadmap

- [x] Core protocol specification
- [x] TypeScript reference implementation
- [x] Local broker + client
- [x] mDNS LAN discovery
- [ ] Internet bridging via Cloudflare Workers
- [ ] DeckAgent tunnel support
- [ ] Additional language implementations

---

## Links

- **Protocol specification:** [`SPEC.md`](./SPEC.md)
- **Repository:** https://github.com/mosesman831/polymesh
- **Ecosystem:** https://latticeag.com
- **Related protocols:**
  - PolyBrain
  - PolyGnosis
  - PolyScribe
  - PolyForge

## License

PolyMesh is released under the [MIT License](LICENSE).

A [LatticeAG](https://latticeag.com) protocol.
