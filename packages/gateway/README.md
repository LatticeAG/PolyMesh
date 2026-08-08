# `@latticeag/polymesh-gateway`

WIRE layer (relay). A loopback-only REST/SSE adapter in front of the broker. It is a blind pass-through, not a policy brain.

## What it does

- Verifies HTTP credentials and reduces them to a closed authorization context before the broker ever sees a request. Raw bearer tokens never enter an envelope, task input, event, or broker adapter call.
- Forwards native PolyMesh envelopes between HTTP/SSE clients and the broker.
- Does not parse A2A, or any other leaf dialect. Dialect translation happens at the agent edge (see `@latticeag/polymesh-a2a`), never in the gateway.

## What it is not

- Not a hosted or durable cloud relay. This package documents a loopback-only local adapter and does not claim to be a remote relay.
- Not a place for routing logic. Capability dispatch lives in `@latticeag/polymesh-client`'s router (PRODUCT layer).
- Not a place for dialect knowledge. If a change makes this package aware of A2A payload structure, that change is wrong.

## Install

```bash
npm i @latticeag/polymesh-gateway
```

## Usage

```ts
import { createGatewayServer } from "@latticeag/polymesh-gateway";

const gateway = createGatewayServer({
  authenticate: async (bearerToken) => resolvePrincipal(bearerToken),
  broker: myGatewayBrokerAdapter,
});
gateway.server.listen(8080);
```

`broker` implements `GatewayBroker`: it resolves capability contracts and admits or reads tasks against your actual broker connection. Depends on `@latticeag/polymesh-broker` for envelope types and validation.

## Positioning

For why the gateway stays blind and what that buys PolyMesh against A2A, AgentChat, ACP, and Caspian, see [`docs/positioning.md`](../../docs/positioning.md).
