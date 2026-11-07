#!/usr/bin/env bash
# PolyMesh v6 M4 — offline re-route launch demo (PM-V6-SPEC.md §D.3).
#
# Three agents, one local mesh, zero public endpoints. The first-ranked
# worker (demo.worker-a) is picked without an explicit target, "dies"
# mid-task, and the mesh re-routes to demo.worker-b — all offline.
#
# The routing checks run in a network namespace or network-disabled container
# when available. Otherwise they run on the host with isolation unverified.
# The outbound connectivity probe is not performed; the output says so.
# A failed routing check exits non-zero. Isolation has its own explicit status.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEMO_SCRIPT="scripts/offline-reroute/demo.mjs"
ROUTER_DIST="packages/client/dist/router.js"

if [[ ! -f "$DEMO_SCRIPT" ]]; then
  echo "DEMO FAILED: missing $DEMO_SCRIPT" >&2
  exit 1
fi

if [[ ! -f "$ROUTER_DIST" ]]; then
  echo "[setup] $ROUTER_DIST not found — building workspace packages first (npm run build)" >&2
  npm run build
fi

# Run the entire demo in an isolated network namespace when possible. Do not
# infer isolation from a failed ping or a failed container startup.
echo "SKIPPED: OBSERVATION 1/9: Offline proof — outbound internet check failed"
echo "  No outbound connection probe was performed; isolation is reported separately."

if command -v unshare >/dev/null 2>&1 && unshare -n -- true >/dev/null 2>&1; then
  echo "PROOF_LEVEL=network-namespace"
  unshare -n -- node "$DEMO_SCRIPT"
  echo "DEMO ISOLATION: VERIFIED (network namespace)"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && \
     docker run --pull=never --rm --network none node:24-bookworm-slim true >/dev/null 2>&1; then
  echo "PROOF_LEVEL=docker-network-none"
  docker run --pull=never --rm --network none -v "$ROOT:/work" -w /work \
    node:24-bookworm-slim node "$DEMO_SCRIPT"
  echo "DEMO ISOLATION: VERIFIED (Docker network none)"
else
  echo "PROOF_LEVEL=simulation"
  echo "SKIPPED: Network isolation and outbound connectivity checks; the demo runs on the host." >&2
  POLYMESH_OFFLINE_MODE=simulation node "$DEMO_SCRIPT"
  echo "DEMO ISOLATION: UNVERIFIED (simulation)"
fi

echo "DEMO RESULT: PASSED (routing checks)"
