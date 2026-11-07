# Offline re-route demo

Normative spec: `PM-V6-SPEC.md` §D.3 (thesis §D.3.1, exact observations §D.3.6, executable-conformance requirement §E.4.6).

**Thesis:** three agents on a laptop, no internet. One drops mid-task. The
mesh re-routes the task to a peer with the capability. Zero config, no
public endpoints.

## Run it

```bash
./scripts/demo-offline-reroute.sh
```

This prints all nine §D.3.6 observations, in order, followed by:

```
DEMO RESULT: PASSED
```

It is also wired up as an executable conformance test:

```bash
npx vitest run tests/demo-offline-reroute.test.ts
```

which asserts every `OBSERVATION N/9` marker appears, strictly in order, and
that the run ends with `DEMO RESULT: PASSED`.

## What it does

`demo.mjs` plays all three demo roles (`demo.coordinator`, `demo.worker-a`,
`demo.worker-b`) in a single Node process, orchestrated through the **real**
M1 `CapabilityRouter` (`packages/client/dist/router.js` — the same engine
the SDK ships). Nothing here is mocked routing logic:

- A `RegistryView` is built with three mesh members. Both workers advertise
  `org.polymesh.demo.summarize` (native dialect, `same_host` locality,
  healthy). The coordinator advertises nothing.
- `router.routeTask({ capability: ..., payload, ... })` is called with **no
  explicit target** — the router picks `demo.worker-a` first (Unicode /
  round-robin ordering across the tied candidates).
- `nativeDispatch` simulates `demo.worker-a` being killed mid-task: it logs
  accept + progress, then throws an `ETIMEDOUT` error, which the router's
  real retryability classifier (`classifyRetryability`, §B.7.3) marks
  retryable.
- The router automatically excludes `demo.worker-a` and re-routes to
  `demo.worker-b` (`reroute_count: 1`), which accepts, progresses, and
  completes successfully.
- The script verifies, from its own captured output and `process.argv`, that
  no `https://` URL — i.e. no public AgentCard endpoint — ever appears.

Only loopback/in-process communication is used. No sockets are opened by the
demo itself.

## Offline-proof modes

The script reports `PROOF_LEVEL=network-namespace` when the entire demo runs
in a new network namespace, or `PROOF_LEVEL=docker-network-none` when it runs
in a Docker container with networking disabled. The Docker image
`node:24-bookworm-slim` must already be available locally.

When neither isolation method is available, `PROOF_LEVEL=simulation` and
`DEMO ISOLATION: UNVERIFIED` explicitly indicate that the host process was
not network-isolated. The routing checks still run and report their result.
The outbound connectivity probe is skipped in all modes; isolation is assessed
by the mechanism used to run the entire process.

## Files

- `demo.mjs` — the demo itself (Node ESM, imports the real router from
  `packages/client/dist/`).
- `../demo-offline-reroute.sh` — the executable entry point (offline proof +
  demo run + `DEMO RESULT: PASSED`).
- `../../tests/demo-offline-reroute.test.ts` — Vitest conformance test that
  spawns the shell script and asserts the nine ordered observations.
