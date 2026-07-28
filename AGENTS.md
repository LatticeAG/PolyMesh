# AGENTS.md - PolyMesh

This file tells AI agents (Hermes, Cursor, Claude Code, etc.) how PolyMesh works and how to interact with it.

## What is PolyMesh?

PolyMesh is an open, local-first protocol for agent-to-agent communication. It lets AI agents discover each other, declare capabilities, and exchange bounded tasks -- no cloud required.

**Tagline:** Agents talking to agents on your network.

## Core Concepts

- **Agent Cards** - Each agent publishes a card declaring its identity and capabilities
- **Broker** - Routes tasks between agents using registered capabilities, not hardcoded addresses
- **Tasks** - Bounded, validated work units with full lifecycle (submitted -> accepted -> progress -> completed/failed)
- **Mesh** - A group of agents connected through a shared broker, able to discover and task each other

## Packages

| Package | What it does | Lang |
| --- | --- | --- |
| `@latticeag/polymesh-broker` | WebSocket broker + local registry | TS |
| `@latticeag/polymesh-client` | Client SDK + CLI + mDNS discovery | TS |
| `@latticeag/polymesh-gateway` | REST/SSE gateway adapter (local) | TS |
| `@latticeag/create-polymesh-app` | Starter generator | TS |
| `latticeag-polymesh` | Python SDK (import as `polymesh`) | Python |

## Architecture Layers

```
Application code (capability handlers / callers)
  -> Application layer (task lifecycle, contracts, validation)
    -> Envelope layer (JSON records, IDs, deadlines)
      -> Handshake layer (hello, card, auth, ready)
        -> Framing layer (bounded text frames)
          -> Transport layer (loopback WS or enrolled WSS)
```

## How Agents Interact

1. **Start a broker** - One agent runs `@latticeag/polymesh-broker` (or the CLI)
2. **Connect agents** - Each agent connects to the broker via WebSocket
3. **Register cards** - Agents publish their capability contracts
4. **Task submission** - An agent submits a task to another agent's registered capability
5. **Lifecycle** - Task accepted -> progress events -> terminal completion or failure

## Transport Modes

- **Loopback WS** - Local dev, numeric loopback endpoint only
- **Enrolled WSS** - Mutual enrollment, TLS required
- **DeckAgent** - Experimental carrier for agent-to-agent tunnels
- **PolyMesh Gateway** - CF Workers relay for cross-internet meshes (separate repo)

## Key Protocol Messages

From agent to broker: `card.register`, `mesh.join`, `task.submit`, `task.accept`, `task.progress`, `task.complete`, `task.fail`, `mesh.leave`

From broker to agent: `card.registered`, `mesh.joined`, `task.submit` (from others), `task.accepted/progress/completed/failed`, `token.expiring`, `error`

## CLI Usage

```bash
# Install
npm i -g @latticeag/polymesh-client

# Start a broker
polymesh broker start

# Connect an agent
polymesh agent connect --capabilities my-cap.json

# List agents in mesh
polymesh mesh list

# Submit a task
polymesh task submit --target <agent-id> --capability <cap> --payload '{"...":"..."}'
```

## Design Principles

1. **Local-first** - Works fully offline. Cloud is optional, never required.
2. **Framework-agnostic** - Any language, any runtime, any agent framework
3. **No central broker dependency** - The broker is a lightweight process, not a cloud service
4. **Capability-based** - Agents find each other by what they can do, not by address
5. **Security by default** - Explicit opt-in for non-loopback transport, mutual enrollment for WSS

## Related

- [polyMesh Gateway](https://github.com/LatticeAG/polymesh-gateway) - Cloudflare Workers relay for internet-scale meshes
- [LatticeAG](https://github.com/LatticeAG) - More Poly series projects

## License

MIT. Built by LatticeAG.
