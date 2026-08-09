#!/bin/bash
# PolyMesh v6 0.5.0 publish helper - reads credentials from ~/.npmrc and ~/.pypirc
set -e
cd /home/ubuntu/polymesh

PYPI_TOKEN=$(grep '^password' /home/ubuntu/.pypirc | cut -d' ' -f3)

echo "=== Publishing Python to PyPI ==="
UV_PUBLISH_TOKEN="$PYPI_TOKEN" UV_PUBLISH_URL="https://upload.pypi.org/legacy/" uv publish 2>&1 | tail -8

echo "=== Publishing npm packages ==="
for pkg in @latticeag/polymesh-broker @latticeag/polymesh-client @latticeag/polymesh-gateway @latticeag/polymesh-a2a; do
  echo "--- $pkg ---"
  npm publish --workspace="$pkg" 2>&1 | tail -3
done

echo "=== DONE ==="