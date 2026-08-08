# `polymesh` (Python SDK)

PRODUCT layer. Distributed as `latticeag-polymesh`, imported as `polymesh`.

## What's in here

- `client.py`: `PolyMeshClient`, a loop-bound async session manager. Handles the hello/card/auth/ready handshake and exposes a `call()` / handler API.
- `router.py`: the capability routing engine (PRODUCT routing). Ranks candidates by capability, health, permission, dialect preference, locality, and freshness, and dispatches by what an agent can do rather than by address. This module does not parse A2A payloads; dialect is a routing attribute only.
- `broker.py`: broker-side session and registry logic for embedding a broker in Python.
- `discovery.py`: local network discovery helpers.
- `gateway_transport.py`: optional transport for talking to `@latticeag/polymesh-gateway`.
- `a2a/`: the A2A leaf-dialect adapter (WIRE layer, separate from routing).
- `cli.py`: the `polymesh` command-line entry point.

## Install

```bash
pip install latticeag-polymesh
```

## Usage

```python
import asyncio
from polymesh import AgentCardBuilder, PolyMeshClient

async def main():
    card = AgentCardBuilder("demo.worker-a").build()
    client = PolyMeshClient(card=card, broker_url="ws://127.0.0.1:8765")
    await client.connect()

asyncio.run(main())
```

`CapabilityRouter` in `router.py` is the routing decision point. Most application code reaches it through `PolyMeshClient` rather than instantiating it directly.

## Positioning

For how capability routing compares to A2A, AgentChat, ACP, and Caspian, see [`docs/positioning.md`](../../docs/positioning.md).
