# `@latticeag/polymesh-a2a`

WIRE layer (leaf dialect). PolyMesh v6's A2A adapter. It translates at the agent edge; it does not become a second router or a gateway feature.

Outbound (M2): translates mesh capability tasks to A2A JSON-RPC `tasks/send|get|cancel`,
polls with normative backoff, terminates mesh credentials at the dialect boundary.

Inbound JSON-RPC / AgentCard publisher ships in M3.

Capability routing stays native to the mesh and lives in `@latticeag/polymesh-client`'s router, not here. When the router resolves an A2A-native peer as the target, this adapter handles the translation after that decision is made. See [`docs/positioning.md`](../../docs/positioning.md) for why PolyMesh speaks A2A instead of competing with it.

```ts
import { A2AAdapter, loadA2AAdapterConfig } from "@latticeag/polymesh-a2a";
import { CapabilityRouter } from "@latticeag/polymesh-client/router";

const adapter = new A2AAdapter(loadA2AAdapterConfig(process.env, {
  outbound_enabled: true,
  trusted_endpoints: ["http://127.0.0.1:9999/a2a"],
}));
router.setA2AOutboundBridge(adapter.createOutboundBridge());
```

Depends on `@latticeag/polymesh-client`. The client MUST NOT depend on this package.
