# `@latticeag/polymesh-broker`

PRODUCT layer. The WebSocket broker and local registry that every PolyMesh agent connects through.

## What's in here

- `broker.ts`: the WebSocket router. Authenticates a connection, runs the hello/card/ready handshake, records the live agent lease, and forwards validated envelopes without rewriting sender or recipient fields. Task execution and task persistence live in agents, not here.
- `registry.ts`: tracks which agents are connected and what they advertise.
- `routing.ts`: shared routing primitives used by the broker and by `@latticeag/polymesh-client`'s router.
- `protocol.ts`: envelope types, validation, and canonical JSON handling.
- `durable-store.ts` / `durable-store-v2.ts`: optional durable delivery for at-least-once semantics.
- `security.ts`, `rate-limit.ts`, `compression.ts`: transport-level hardening.

## Install

```bash
npm i @latticeag/polymesh-broker
```

## Usage

```ts
import { Broker } from "@latticeag/polymesh-broker";

const broker = new Broker({ port: 8765 });
await broker.listen();
```

The broker is a lightweight process, not a cloud service. It owns session and routing state; it does not own capability dispatch decisions or task business logic, both of which live in `@latticeag/polymesh-client`.

## Positioning

For how the broker and mesh compare to A2A, AgentChat, ACP, and Caspian, see [`docs/positioning.md`](../../docs/positioning.md).
