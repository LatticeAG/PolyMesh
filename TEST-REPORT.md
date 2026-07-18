# PolyMesh Test Report

**Generated:** 2026-07-18 15:17 UTC
**Node:** $(node --version) · **npm:** $(npm --version)
**Test runner:** Vitest 3.2.7

---

## Summary

| Metric | Value |
|--------|-------|
| **Test files** | 26 passed of 26 total |
| **Tests** | 143 passed of 143 total |
| **Status** | ✅ All passing |
| **Duration** | 4.73s total |

## Test Results

| # | File | Status | Tests | Duration |
|---|------|--------|-------|----------|
| 1 | tests/durable-store-fencing.test.ts | ✅ Passed | 12 | 33 ms |
| 2 | tests/durable-store-admission.test.ts | ✅ Passed | 12 | 48 ms |
| 3 | tests/rate-limit-compression.test.ts | ✅ Passed | 12 | 93 ms |
| 4 | tests/durable-store.test.ts | ✅ Passed | 5 | 303 ms |
| 5 | tests/durable-registry.test.ts | ✅ Passed | 3 | 76 ms |
| 6 | tests/integration.test.ts | ✅ Passed | 9 | 223 ms |
| 7 | tests/policy.test.ts | ✅ Passed | 11 | 116 ms |
| 8 | tests/websocket.test.ts | ✅ Passed | 3 | 84 ms |
| 9 | tests/broker-v2-routing.test.ts | ✅ Passed | 2 | 70 ms |
| 10 | tests/broker-admission.test.ts | ✅ Passed | 4 | 69 ms |
| 11 | tests/broker-v2-compression.test.ts | ✅ Passed | 2 | 68 ms |
| 12 | tests/transport-security.test.ts | ✅ Passed | 8 | 83 ms |
| 13 | tests/broker-v2-wire.test.ts | ✅ Passed | 3 | 58 ms |
| 14 | tests/capability-contract.test.ts | ✅ Passed | 5 | 56 ms |
| 15 | tests/client-replay-security.test.ts | ✅ Passed | 2 | 67 ms |
| 16 | tests/routed-provenance.test.ts | ✅ Passed | 4 | 38 ms |
| 17 | tests/receipt-control.test.ts | ✅ Passed | 3 | 42 ms |
| 18 | tests/deckagent-carrier.test.ts | ✅ Passed | 8 | 49 ms |
| 19 | tests/identity-security.test.ts | ✅ Passed | 4 | 25 ms |
| 20 | tests/v2-primitives-edge.test.ts | ✅ Passed | 8 | 21 ms |
| 21 | tests/cli.test.ts | ✅ Passed | 3 | 17 ms |
| 22 | tests/replay-ledger.test.ts | ✅ Passed | 4 | 18 ms |
| 23 | tests/mdns-security.test.ts | ✅ Passed | 3 | 13 ms |
| 24 | tests/routing.test.ts | ✅ Passed | 3 | 9 ms |
| 25 | tests/protocol-security.test.ts | ✅ Passed | 7 | 14 ms |
| 26 | tests/registry.test.ts | ✅ Passed | 3 | 10 ms |

## Test Categories

| Category | Files | Tests |
|----------|-------|-------|
| **Core Protocol** | registry, integration, websocket, cli, protocol-security | 26 |
| **Security** | identity-security, transport-security, policy, mdns-security, routed-provenance, receipt-control, client-replay-security, capability-contract, broker-admission | 45 |
| **Durable Store** | durable-store, durable-store-fencing, durable-store-admission, durable-registry | 32 |
| **V2 / Routing** | routing, v2-primitives-edge, broker-v2-routing, broker-v2-compression, broker-v2-wire | 18 |
| **Rate Limit** | rate-limit-compression | 12 |
| **DeckAgent** | deckagent-carrier | 8 |
| **Replay** | replay-ledger | 4 |
| **Total** | **26** | **143** |

---

*Report generated from `npm test` output. Run locally with `npm test`.*