# Docs

Short index for the PolyMesh v6 docs. Start with the root [README](../README.md) for install and quickstart, and [ARCHITECTURE.md](../ARCHITECTURE.md) for how the layers fit together.

## Competitive positioning

[`positioning.md`](./positioning.md) is the source of truth for how PolyMesh talks about A2A, ACP, AgentChat, and Caspian: the three-layer model, the four locked positioning statements, the full competitive matrix, honest limits, and the FAQ. Copy from here, don't improvise comparison language elsewhere.

## Offline re-route demo

`scripts/demo-offline-reroute.sh` runs the launch demo: three agents on one laptop, no internet, one worker dies mid-task, the mesh re-routes to a healthy peer. See [`positioning.md`](./positioning.md#offline-re-route-demo) for the thesis and the nine observations a successful run must show.

## Package layers

Every package README states which layer it lives in:

| Layer | Meaning | Packages |
|-------|---------|----------|
| PRODUCT | Capability routing, rooms, permissions, task lifecycle. Where PolyMesh differentiates. | `@latticeag/polymesh-client`, `@latticeag/polymesh-broker`, `latticeag-polymesh` (Python) |
| WIRE | Dialect translation at the leaf. Speaks a standard, doesn't own it. | `@latticeag/polymesh-a2a` |
| WIRE / relay | Blind pass-through. Doesn't parse or hold routing logic. | `@latticeag/polymesh-gateway` |

The mesh core never depends on a wire dialect. See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full layer diagram and package dependency graph.
