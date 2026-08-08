# `@latticeag/polymesh-client`

PRODUCT layer. This is where PolyMesh differentiates: capability routing, the client SDK, and the CLI.

## What's in here

- `client.ts`: a stateful WebSocket client. Handles the hello/card/auth/ready handshake and turns task envelopes into a `call()` / handler API.
- `router.ts`: the capability routing engine. Ranks candidates by capability, health, permission, dialect preference, locality, and freshness. Dispatch by what an agent can do, not by address. This module does not depend on any wire dialect and must not parse A2A payloads.
- `cli.ts`: the `polymesh` command-line tool (connect, list peers, submit tasks).
- `mdns.ts`: optional same-LAN discovery.
- `config.ts`, `gateway-transport.ts`, `deckagent-carrier.ts`: config loading and alternate transports.

## Install

```bash
npm i @latticeag/polymesh-client
```

## Usage

```ts
import { createAgentCard } from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client/client";

const card = createAgentCard({ agent_id: "demo.worker-a", capabilities: [] });
const client = new PolyMeshClient({ url: "ws://127.0.0.1:8765", card });
await client.connect();
```

`CapabilityRouter` (in `router.ts`) is the piece that ranks candidates and picks a target by capability rather than by address. The broker and CLI both build on top of it; most application code interacts with routing through `PolyMeshClient` rather than instantiating the router directly.

Depends on `@latticeag/polymesh-broker` for shared protocol types and validation.

## Positioning

For how capability routing compares to A2A, AgentChat, ACP, and Caspian, see [`docs/positioning.md`](../../docs/positioning.md).
