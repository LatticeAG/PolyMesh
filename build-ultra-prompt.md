You are building PolyMesh v2 from the Ultra spec. Read V2-SPEC-ULTRA.md and the existing source code.

TASK: Implement the remaining v2 protocol features that aren't yet built. Use spawn_agent internally.

SUB-AGENT 1 — v2 Wire Format Updates
- Read V2-SPEC-ULTRA.md sections "Sub-agent 1 — v2 Wire Format" (§§1-8)
- Read packages/broker/src/protocol.ts (current wire format)
- Update protocol.ts with:
  - V2_PROTOCOL_VERSION and V2_HANDSHAKE_VERSION constants
  - mesh_id field in hello/auth/ready records
  - Profile version selection (v0.1 vs v0.2)
  - Session correlation value (sid) format
  - Updated card record with v2 fields
  - JSON Schemas for v2 handshake records
  - Delivery receipt record format
- These are spec types and interfaces ONLY — no orchestration logic

SUB-AGENT 2 — Compression Negotiation Protocol
- Read V2-SPEC-ULTRA.md section 9 (zstd compression)
- Read packages/broker/src/compression.ts (current compression)
- Update compression.ts with:
  - Proposal record format (compression.proposal)
  - Ready record format (compression.ready)
  - ZstdWrapper record format (compression.zstd)
  - Full compression negotiation flow: hello → proposal → ready → compressed
  - JSON Schemas for all compression records
  - Compression negotiation state machine state/transitions

SUB-AGENT 3 — REST/SSE Gateway
- Read V2-SPEC-ULTRA.md section 7.x (REST/SSE Gateway)
- Create packages/gateway/ with:
  - Gateway HTTP server (Express or http module)
  - POST /v2/gateway/tasks — submit a task via JSON body
  - GET /v2/gateway/events — SSE stream for task lifecycle events
  - Gateway auth (bearer token forwarded to broker)
  - Gateway translates HTTP requests into PolyMesh envelopes
  - Gateway translates broker events into SSE messages
- Create tests/gateway.test.ts

SUB-AGENT 4 — v2 Integration Tests
- Create tests/v2-wire-format.test.ts — tests for new v2 handshake, profile selection, mesh_id validation
- Create tests/v2-compression-protocol.test.ts — tests for compression negotiation flow
- Create tests/v2-health-routing.test.ts — tests for health state machine transitions (if not covered)

RULES:
- Output TypeScript implementations
- The existing 143 tests MUST still pass
- Run npm test after all changes
- Output "DONE" with test results summary

NO web searches. Use your training knowledge and the appended spec and source.
