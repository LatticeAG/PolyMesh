# PolyMesh v6 M5 — Release runbook (SDK 0.5.0)

**Protocol:** PolyMesh v6 (PM-V6-SPEC.md rev 6.0.0-ultimate)  
**SDK version:** `0.5.0` (NOT 1.0.0 — protocol is v6; package semver is 0.5.0)  
**Date:** 2026-08-08  
**Milestone:** M5 — publish, gateway pass-through delta, release gates  

Part D claim now TRUE: **Interops with A2A ecosystem: YES (v6 spec; ships with M5 release)**.

---

## Versions bumped

| Artifact | Name | Version |
|----------|------|---------|
| npm | `@latticeag/polymesh-broker` | `0.5.0` |
| npm | `@latticeag/polymesh-client` | `0.5.0` |
| npm | `@latticeag/polymesh-gateway` | `0.5.0` |
| npm | `@latticeag/polymesh-a2a` | `0.5.0` |
| npm | `@latticeag/create-polymesh-app` | `0.5.0` |
| PyPI | `latticeag-polymesh` | `0.5.0` |
| Workspace | `polymesh` (private) | `0.5.0` |

Internal workspace deps updated to `^0.5.0`. Lockfiles: `package-lock.json`, `uv.lock`.

---

## §E.6 Release gates (real evidence)

### E.6.1 Namespace and packaging — PASS

```
packages/a2a/package.json: name=@latticeag/polymesh-a2a version=0.5.0 PASS
packages/client/package.json: name=@latticeag/polymesh-client version=0.5.0 PASS
packages/broker/package.json: name=@latticeag/polymesh-broker version=0.5.0 PASS
packages/gateway/package.json: name=@latticeag/polymesh-gateway version=0.5.0 PASS
a2a depends on client: True
client lists a2a: False
python name: latticeag-polymesh version: 0.5.0
a2a optional extra: ['httpx>=0.27,<1']
core has httpx: False
polymesh.a2a import OK /home/ubuntu/polymesh/src/polymesh/a2a/__init__.py
```

- Published npm A2A name: `@latticeag/polymesh-a2a`
- Python import: `polymesh.a2a`; PyPI name `latticeag-polymesh` with optional extra `a2a` (documented; not a separate wheel)
- Client MUST NOT depend on A2A: verified
- Python core does not pull `httpx` unless `[a2a]` / other extras

### E.6.2 Existing tests unchanged — PASS

```
npm test → Test Files  41 passed (41) / Tests  262 passed (262)
uv run pytest -q → 129 passed in 2.37s
```

Targets were ≥181 TS / ≥69 Python (pre-v6 floors). Actual: **262 TS**, **129 Python**. No weakened frozen assertions required for this release.

Prerequisite: `npm rebuild better-sqlite3` completed successfully before the suite.

### E.6.3 Interop both directions — PASS

| Direction | Command | Result |
|-----------|---------|--------|
| M2 outbound TS | `npx vitest run tests/v6-a2a-outbound-m2.test.ts` | **20 passed** |
| M3 inbound TS | `npx vitest run tests/v6-a2a-inbound-m3.test.ts` | **15 passed** |
| M2+M3 Python | `uv run pytest tests/unit/test_a2a_outbound_m2.py tests/unit/test_a2a_inbound_m3.py -q` | **29 passed** |

Auth-boundary / redaction / rate-limit focused re-run:

```
vitest -t 'auth|redact|rate_limit|credential|mesh' → 9 passed | 26 skipped
pytest -k 'auth or redact or rate or credential or mesh' → 7 passed, 22 deselected
```

Inbound rate limiting enabled by default (`packages/a2a/src/config.ts`: `rate_limit: { enabled: true }`; inbound handler constructs `HierarchicalRateLimiter` unless `rate_limit: false`).

### E.6.4 Offline demo — PASS

```
npx vitest run tests/demo-offline-reroute.test.ts
→ prints all nine normative observations in order and reports PASSED

bash scripts/demo-offline-reroute.sh → DEMO RESULT: PASSED
```

Nine observations observed:

1. Offline proof — outbound internet check failed (`docker run --network none`)
2. Membership — three agents (`demo.coordinator`, `demo.worker-a`, `demo.worker-b`)
3. Capability discovery — both workers advertise `org.polymesh.demo.summarize`
4. Capability dispatch — first route `demo.worker-a` without explicit target
5. Lifecycle — submit, route, accept, progress
6. Failure — worker-a mid-task; retryable
7. Re-route — `demo.worker-b`; exclusion contains worker-a; `reroute_count=1`
8. Terminal success — completed from worker-b
9. No public endpoints — no `https://` AgentCard URLs

### E.6.5 Positioning verbatim — PASS

`docs/positioning.md` contains all four Part D statements exactly:

1. "MCP gave agents tools. A2A gave agents a phone book. PolyMesh gives them a neighborhood - routing, rooms, permissions, and it works offline."
2. "A2A is the phone line between agents. PolyMesh is the switchboard, the address book, and the wires that work when the phones are offline."
3. "AgentChat is WhatsApp for agents - message @alice. PolyMesh is the factory floor - dispatch the task to whoever can do it, track it to completion, re-route when a worker fails."
4. "We don't compete with A2A. We speak it. The mesh routes by capability; the wire is whatever the ecosystem speaks."

README three-layer labels: `@latticeag/polymesh-a2a` = **WIRE (leaf dialect)**; client router = **PRODUCT**. Matrix row present:

`Interops with A2A ecosystem | YES (v6 spec; ships with M5 release)`

### E.6.6 Security and config — PASS

- Auth boundary: `packages/a2a/src/auth-boundary.ts` / `polymesh.a2a.auth_boundary`; covered by M2/M3 suites
- Redaction: `redactCredentialPatterns` exercised in outbound tests
- Inbound rate limiting default-on: verified in config + inbound handler + rate_limit tests

### E.6.7 Sign-off — PASS (with noted pending deploy/publish)

| Item | Status |
|------|--------|
| M1–M4 exit criteria | Met in prior commits (`v6 M1` … `v6 M4`) |
| Compatibility matrix §E.9 | Published at `docs/compatibility-v5-v6.md` |
| Acceptance §E.10 | Covered by M1–M5 deliverables + gates above |
| Gateway Part C deploy | **PENDING** (see below) |
| npm/PyPI publish | **PENDING** (no credentials) |

---

## Build artifacts — PASS (dry-run)

```
npm run build → broker/client/gateway/a2a all OK @0.5.0

npm pack --dry-run (per package):
  latticeag-polymesh-broker-0.5.0.tgz   (182.3 kB, 24 files)
  latticeag-polymesh-client-0.5.0.tgz   (106.3 kB, 22 files)
  latticeag-polymesh-gateway-0.5.0.tgz  (12.4 kB, 4 files)
  latticeag-polymesh-a2a-0.5.0.tgz      (39.0 kB, 36 files)

uv build:
  dist/latticeag_polymesh-0.5.0.tar.gz
  dist/latticeag_polymesh-0.5.0-py3-none-any.whl
```

---

## Gateway pass-through (Part C) — DELTA DOC ONLY

`/home/ubuntu/polymesh-gateway` was **not cloned**. Local `packages/gateway` is the loopback REST/SSE adapter (not MeshDO/D1) and correctly stays dialect-blind on the data plane.

**PR-ready delta:** [`docs/gateway-v2-delta.md`](docs/gateway-v2-delta.md)

Implements (in the separate CF Workers repo):

- Dialect pass-through in discovery only
- §C.6.6 DO hydration from D1 on wake
- §C.8.2 dialect filter semantics
- §C.9.1 `card.announce` REPLACE semantics
- §C.12.4 `envelope_log` retention (default TTL 7 days)
- No A2A parsing in worker / MeshDO

**Pending:** open PR + deploy against `LatticeAG/polymesh-gateway`.

---

## Publish status — PENDING (no auth)

```
npm whoami → ENEEDAUTH (not logged in)
uv publish --dry-run → no credentials / no OIDC trusted publishing token
```

### Exact publish commands (run when auth is available)

```bash
# npm (from repo root, after build)
npm publish --workspace=@latticeag/polymesh-broker --access public
npm publish --workspace=@latticeag/polymesh-client --access public
npm publish --workspace=@latticeag/polymesh-gateway --access public
npm publish --workspace=@latticeag/polymesh-a2a --access public
npm publish --workspace=@latticeag/create-polymesh-app --access public

# PyPI
uv build
uv publish dist/latticeag_polymesh-0.5.0.tar.gz dist/latticeag_polymesh-0.5.0-py3-none-any.whl
```

Do **not** publish without verifying `npm whoami` and PyPI credentials first.

---

## What's pending for actual ship

1. **npm publish** of the five packages above (auth required)
2. **PyPI publish** of `latticeag-polymesh==0.5.0` (auth required)
3. **Gateway deploy:** implement `docs/gateway-v2-delta.md` in `polymesh-gateway` and deploy Workers/D1
4. Optional: GitHub Release tag `v0.5.0` after publishes succeed

---

## Deferred to v7 (§E.7)

- ACP adapter (Zed)
- MCP bridge
- Agent-native payments

Not in this release.

---

## Quick re-verify commands

```bash
npm rebuild better-sqlite3   # if binding fails
npm test                     # expect 262+
uv run pytest -q             # expect 129+
npx vitest run tests/v6-a2a-outbound-m2.test.ts tests/v6-a2a-inbound-m3.test.ts
npx vitest run tests/demo-offline-reroute.test.ts
bash scripts/demo-offline-reroute.sh
```
