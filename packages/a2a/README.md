# `@latticeag/polymesh-a2a`

PolyMesh v6 A2A leaf-dialect adapter (WIRE layer).

Outbound (M2): translates mesh capability tasks to A2A JSON-RPC `tasks/send|get|cancel`,
polls with normative backoff, terminates mesh credentials at the dialect boundary.

Inbound JSON-RPC / AgentCard publisher ships in M3.

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
