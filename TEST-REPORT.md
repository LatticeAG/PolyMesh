# PolyMesh Test Report

**Generated:** 2026-09-07 UTC
**Test runner:** Vitest 3.2.4 (`npm test`) + Python pytest (`uv run pytest -q`)

---

## Summary

| Metric | Value |
|--------|-------|
| **TypeScript test files** | 41 passed of 41 total |
| **TypeScript tests** | 262 passed of 262 total |
| **Python tests** | 129 passed of 129 total |
| **Typecheck (`tsc --noEmit`)** | clean |
| **Status** | All passing |

## Test Results

| # | File | Status | Tests |
|---|------|--------|-------|
| 1 | tests/broker-admission.test.ts | Passed | 4 |
| 2 | tests/broker-native-v2.test.ts | Passed | 3 |
| 3 | tests/broker-v2-compression.test.ts | Passed | 2 |
| 4 | tests/broker-v2-routing.test.ts | Passed | 2 |
| 5 | tests/broker-v2-wire.test.ts | Passed | 3 |
| 6 | tests/capability-contract.test.ts | Passed | 5 |
| 7 | tests/cli-config.test.ts | Passed | 5 |
| 8 | tests/cli.test.ts | Passed | 3 |
| 9 | tests/client-replay-security.test.ts | Passed | 2 |
| 10 | tests/compat/vectors.test.ts | Passed | 9 |
| 11 | tests/deckagent-carrier.test.ts | Passed | 8 |
| 12 | tests/demo-offline-reroute.test.ts | Passed | 1 |
| 13 | tests/durable-registry.test.ts | Passed | 3 |
| 14 | tests/durable-store-admission.test.ts | Passed | 12 |
| 15 | tests/durable-store-fencing.test.ts | Passed | 12 |
| 16 | tests/durable-store-v2.test.ts | Passed | 2 |
| 17 | tests/durable-store.test.ts | Passed | 5 |
| 18 | tests/gateway-transport.test.ts | Passed | 14 |
| 19 | tests/gateway.test.ts | Passed | 4 |
| 20 | tests/identity-security.test.ts | Passed | 4 |
| 21 | tests/integration.test.ts | Passed | 9 |
| 22 | tests/mdns-security.test.ts | Passed | 3 |
| 23 | tests/native-v2-client.test.ts | Passed | 2 |
| 24 | tests/native-v2-compression.test.ts | Passed | 2 |
| 25 | tests/policy.test.ts | Passed | 11 |
| 26 | tests/protocol-security.test.ts | Passed | 7 |
| 27 | tests/rate-limit-compression.test.ts | Passed | 12 |
| 28 | tests/receipt-control.test.ts | Passed | 3 |
| 29 | tests/registry.test.ts | Passed | 3 |
| 30 | tests/replay-ledger.test.ts | Passed | 4 |
| 31 | tests/routed-provenance.test.ts | Passed | 4 |
| 32 | tests/routing.test.ts | Passed | 3 |
| 33 | tests/transport-security.test.ts | Passed | 8 |
| 34 | tests/v2-compression-protocol.test.ts | Passed | 3 |
| 35 | tests/v2-health-routing.test.ts | Passed | 4 |
| 36 | tests/v2-primitives-edge.test.ts | Passed | 8 |
| 37 | tests/v2-wire-format.test.ts | Passed | 4 |
| 38 | tests/v6-a2a-inbound-m3.test.ts | Passed | 15 |
| 39 | tests/v6-a2a-outbound-m2.test.ts | Passed | 20 |
| 40 | tests/v6-routing-m1.test.ts | Passed | 31 |
| 41 | tests/websocket.test.ts | Passed | 3 |

---

*Regenerate with `npx vitest run` (TypeScript) and `uv run pytest -q` (Python).*
