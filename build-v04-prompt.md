You are building the PolyMesh v0.4.0 release. Read the appended V04-SPEC-ULTRA.md and current repo state.

TASK: Implement the full v0.4.0 native v2 SDK. Use spawn_agent internally to delegate.

SUB-AGENT 1 — P-01: v2 Profile Schema Bundle
- Create schemas/v2/envelope-v2.json, schemas/v2/handshake-v2.json, schemas/v2/card-v2.json, schemas/v2/common.json
- common.json: UUIDv7 regex, ErrorCode enum (PMX.SESSION.AUTH, PMX.SESSION.PROFILE, PMX.SESSION.TRANSPORT, PMX.TASK.DEADLINE_EXCEEDED, PMX.TASK.EVENT_CONFLICT, PMX.PROTOCOL.COMPRESSION, etc.), JsonObject definition
- envelope-v2.json: v2 envelope with mesh_id field, delivery_id nested structure, profile field
- handshake-v2.json: v2.init, v2.ack, v2.error records with profile negotiation fields
- card-v2.json: v2 agent card with mesh identity, profile support array
- Update packages/broker/src/protocol.ts to add v2 type definitions matching schemas

SUB-AGENT 2 — P-02 + P-03: Compression + Mesh Identity
- Add zstd compression to packages/broker/src/compression.ts:
  - zstd.propose → zstd.ready → zstd.wrapper state machine (v2 handshake)
  - Use @bokuweb/zstd-wasm for Node.js and browser compat
  - Compression test: known plaintext → compress → decompress = original
- Add mesh_id to routing.ts:
  - Generate UUIDv7 per broker instance on startup
  - Include in all v2 handshake records
  - Rendezvous hashing for multi-instance routing (already built)
  - Route fencing with mesh_id
- Update all handshake paths to support profile negotiation

SUB-AGENT 3 — S-01 + S-02: TypeScript v2 Client + Durable Store
- Extend PolyMeshClient in packages/client/src/client.ts:
  - profile: "polymesh.0.2" constructor option
  - v2 handshake flow: connects → sends v2.init → receives v2.ack → negotiates compression
  - zstd transport wrapper for compressed frames
- Create packages/broker/src/durable-store-v2.ts:
  - SQLite tables: v2_envelopes(id TEXT PK, mesh_id TEXT, profile TEXT, envelope TEXT, created_at INTEGER), v2_inbox(target TEXT, envelope_id TEXT REFERENCES v2_envelopes, status TEXT, delivered_at INTEGER), v2_tasks(id TEXT PK, capability TEXT, input TEXT, status TEXT, executor TEXT, created_at INTEGER)
  - Transactional insert: atomically write envelope + deliver to inbox
  - Delivery cursor for SSE replay

SUB-AGENT 4 — S-03: v2 Gateway
- Extend packages/gateway/src/index.ts:
  - POST /v2/tasks with profile field in request body
  - GET /v2/events with cursor and profile query params
  - SSE event types matching v2 envelope types
  - Profile negotiation on gateway connection
  - Document gateway as loopback-only (no remote relay claim)

SUB-AGENT 5 — S-10: Python v2 Support
- Add v2 profile support to src/polymesh/client.py:
  - profile="polymesh.0.2" parameter
  - v2 handshake protocol
- Add zstd compression to src/polymesh/transport.py:
  - pyzstd dependency
  - compress/decompress wrapper matching TS protocol
- Add v2 compat vectors to tests/compat/
- Ensure all 60 existing tests still pass

RULES:
- All 171 TypeScript tests must still pass
- All 60 Python tests must still pass
- All compat vector tests (TS + Python) must pass
- Output "DONE" with test results summary
- Do NOT modify governed spec files

NO web searches. Use your training knowledge and the attached spec.
