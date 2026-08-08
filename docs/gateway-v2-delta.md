# PM-G v2 (PolyMesh v6) — Gateway delta (PR-ready)

> **Status:** Spec delta for the separate Cloudflare Workers gateway repo  
> **Normative source:** `PM-V6-SPEC.md` Part C (rev 6.0.0-ultimate)  
> **Baseline:** `PM-GATEWAY-V1-SPEC.md` (PM-G v1)  
> **Target repo:** `LatticeAG/polymesh-gateway` (not this monorepo)  
> **SDK release:** PolyMesh `0.5.0` (protocol v6 / M5)  
> **Deploy status:** PENDING — `/home/ubuntu/polymesh-gateway` was not cloned at M5 cut; implement and deploy in the gateway repo.

This document is the exact Part C implementation checklist for a PR against `polymesh-gateway`. The local `@latticeag/polymesh-gateway` package in this monorepo is a **loopback REST/SSE adapter**, not MeshDO/D1. Do not implement Cloudflare Worker semantics there.

---

## Thesis (non-negotiable)

PM-G remains a **product-layer free relay and blind router**. A2A is a wire-layer dialect that terminates at the agent leaf. The gateway MUST NOT learn, parse, translate, proxy, or terminate A2A.

- Dialect awareness is for **discovery metadata only**.
- No new REST/WSS paths vs PM-G v1.
- No A2A JSON-RPC in the Worker or MeshDO.

---

## C.5 Summary of changes

| Change | Normative effect |
|--------|------------------|
| Dialect pass-through in discovery | Capability objects MAY include `dialect` (+ optional `a2a_url`); discovery MUST return them unchanged |
| Registration / announce MAY advertise `dialect: "a2a"` | Discovery can show A2A-reachable peers |
| No new gateway endpoints | Same `/api/v1` REST + WSS as v1 |
| No A2A parsing in the worker | Reject unknown `type`; do not interpret JSON-RPC |
| No A2A JSON-RPC in MeshDO | No A2A methods, states, polling, or translation |

---

## C.6 Capabilities JSON (D1 — no migration)

`agents.capabilities` remains `TEXT` JSON blob. Extend object shape only — **no `ALTER TABLE`**.

### Capability object (normative)

```json
{
  "name": "org.polymesh.calendar.check",
  "dialect": "native"
}
```

```json
{
  "name": "org.polymesh.calendar.check",
  "dialect": "a2a",
  "a2a_url": "https://alice.example.com/a2a"
}
```

### Validation on write (§C.6.4)

1. `name` REQUIRED, non-empty string.
2. Absent `dialect` → treat as `"native"` (SHOULD normalize on write).
3. Present `dialect` MUST be exactly `"native"` or `"a2a"`; else reject (`INVALID_CAPABILITY` / HTTP 400).
4. `dialect: "a2a"` → `a2a_url` REQUIRED, absolute `https:` URL, no userinfo credentials.
5. `dialect: "native"` → `a2a_url` SHOULD be omitted; strip or reject; MUST NOT use the URL.
6. MUST NOT fetch `a2a_url` at write time.
7. MUST NOT store A2A Authorization / API keys / bearer tokens in D1.
8. `security` is opaque store-and-return; do not validate string values.

### §C.6.6 MeshDO hydration (REQUIRED)

MeshDO in-memory `agentCards` MUST carry the same capability objects as D1 (including `dialect` / `a2a_url`).

**On DO activation (including after eviction):** MeshDO MUST lazily hydrate `agentCards` from D1 for the mesh on first access. Agents MUST NOT be required to re-`card.announce` after a DO wake. `card.announce` remains authoritative for updates.

---

## C.8 Discovery dialect filter

### Query params

| Field | Rule |
|-------|------|
| `dialect` | OPTIONAL. If present, MUST be `native` or `a2a`. When set, only capabilities with that dialect are returned; agents appear only if ≥1 capability remains. |

When omitted, agents MAY appear with mixed-dialect capability arrays.

### §C.8.2.1 Filter response shape

The `dialect` filter constrains which **capabilities** are returned inside each agent's array — not membership. Client routers MUST NOT infer dialect-negative facts from a filtered response; re-query without the filter for negatives.

### Wire requirements on read (§C.8.4)

- `capabilities[].dialect` REQUIRED on the wire in v6 responses. Historical rows missing it MUST emit `"native"`.
- `a2a_url` REQUIRED when `dialect` is `a2a`; MUST be absent/null when `native`.
- Gateway MUST NOT reorder/suppress A2A-tagged capabilities unless the client supplied an explicit `dialect` filter.

Same shape for REST `GET /api/v1/meshes/:id/agents`, WS `discovery.response`, and `GET /api/v1/agents/:id/card`.

---

## C.9 `card.announce` REPLACE semantics (§C.9.1)

```json
{
  "type": "card.announce",
  "display_name": "Alice",
  "capabilities": [ /* CapabilityObject[] */ ]
}
```

Rules:

1. `capabilities` MUST be an array of validated CapabilityObjects.
2. On success: update MeshDO cache and SHOULD persist to D1 `agents.capabilities`.
3. Respond with `card.registered` (v1 ack).
4. **REPLACE:** the new `capabilities` array replaces the stored array **atomically** in both MeshDO cache and D1. Clients that need to add a capability MUST re-send the full array.

`mesh.joined` member lists / embedded cards MUST include dialect tags when present (same normalization as discovery).

REST `POST /api/v1/meshes/:id/join` MAY accept optional `capabilities` with the same validation.

---

## C.10 Reject A2A-shaped JSON-RPC on WS

Allowed agent→gateway `type` values remain the v1 set (`card.announce`, `mesh.join`, `mesh.leave`, `discovery.request`, `task.submit`, `task.accept`, `task.progress`, `task.complete`, `task.fail`).

If `type` is missing/not a string/not in the allowed set:

```json
{
  "type": "error",
  "code": "PROTOCOL_UNKNOWN_TYPE",
  "message": "Unknown gateway wire type"
}
```

MUST NOT interpret frames as JSON-RPC 2.0. MUST NOT close the WebSocket solely for a single unknown-type message. HTTP `/api/v1/*` with JSON-RPC bodies → HTTP 400 (malformed), not A2A execution.

---

## C.12 `envelope_log` retention (§C.12.4)

`envelope_log` retention MUST be bounded by at least one of:

- TTL (default **7 days**, cleanup via cron), OR
- per-mesh row cap (e.g. 100k rows, oldest evicted), OR
- size cap (e.g. 100 MB per mesh)

Operator MUST configure at least one. **Default: TTL 7 days.**

Optional: extend logged metadata with dialect when routing context already knows it. MUST NOT parse A2A payloads to populate dialect. MUST NOT log A2A Authorization, full payloads by default, or raw JWT/API keys.

---

## Forbidden (do not add)

| Class | Examples |
|-------|----------|
| A2A JSON-RPC HTTP | `POST /a2a`, `POST /rpc`, `POST /tasks/send` |
| A2A AgentCard on gateway | `GET /.well-known/agent.json` as mesh proxy |
| Dialect translation APIs | `POST /api/v1/translate`, `POST /api/v1/a2a/proxy` |
| A2A credential vault | `POST /api/v1/agents/:id/a2a-credentials` |

---

## Implementation checklist (PR)

- [ ] Capability validation module (§C.6.4) shared by announce / join / register update
- [ ] Persist + return `dialect` / `a2a_url` unchanged after validation
- [ ] Discovery + card fetch emit dialect (default `native` for legacy rows)
- [ ] Optional `dialect` query/filter on REST + WS discovery (§C.8.2 / §C.8.2.1)
- [ ] MeshDO lazy hydrate from D1 on wake (§C.6.6) — test eviction → first access without re-announce
- [ ] `card.announce` atomic REPLACE in cache + D1 (§C.9.1) — test partial announce does not merge
- [ ] Unknown WS `type` → `PROTOCOL_UNKNOWN_TYPE`; JSON-RPC body not dispatched
- [ ] `envelope_log` TTL default 7d (or configured cap) (§C.12.4)
- [ ] No A2A secrets in D1; auth-boundary tests unchanged
- [ ] Existing v1 auth/join/discover/submit/lifecycle tests still green when dialect unused (§C.13)

### Suggested tests

1. Announce native + a2a duplicate capability name → discovery returns both.
2. `?dialect=native` filters capability arrays; agent still listed if ≥1 match.
3. Invalid dialect / missing `a2a_url` / http URL → reject.
4. DO wake hydrates cards from D1 without re-announce.
5. Second `card.announce` with smaller array fully replaces prior capabilities.
6. WS frame `{ "jsonrpc":"2.0","method":"tasks/send",... }` → `PROTOCOL_UNKNOWN_TYPE`.
7. Cron/cleanup removes `envelope_log` rows older than retention TTL.

---

## Ship note

PolyMesh SDK `0.5.0` (M5) claims **“Interops with A2A ecosystem: YES”** at the product/docs layer via leaf adapters. Hosted PM-G dialect pass-through is a **separate deploy** of this delta. Until deployed, local broker + A2A leaf adapters already provide bidirectional interop offline/on-loopback.
