#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo 'Docker is required for the Compose demo.' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo 'The Compose demo requires Docker Compose v2; see README.md.' >&2
  exit 1
fi
if docker buildx version >/dev/null 2>&1; then
  echo 'DEMO_BUILD_BACKEND=buildx'
else
  # Honest degraded path: no buildx plugin for this user or for root.
  # Compose would otherwise warn that Bake is configured but unavailable.
  export COMPOSE_BAKE=false
  echo 'DEMO_BUILD_BACKEND=classic'
  echo 'buildx plugin unavailable; building with the classic Docker builder (COMPOSE_BAKE=false).' >&2
fi
if ! output=$(docker info 2>&1); then
  echo 'Cannot connect to the Docker daemon:' >&2
  echo "$output" >&2
  if [[ "$output" == *'permission denied'* ]]; then
    echo 'Docker socket permission denied. On Linux, ask an administrator to run:' >&2
    echo '  sudo usermod -aG docker "$USER"' >&2
    echo 'Then log out and back in, or start a new session with the docker group.' >&2
    echo 'Alternatively, an administrator can grant this user access to the Docker socket.' >&2
  fi
  exit 1
fi
exec docker compose up --build --abort-on-container-exit "$@"
