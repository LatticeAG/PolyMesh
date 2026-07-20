You are building the PolyMesh Python SDK from the full specification. Read PYTHON-SDK-SPEC.md.

TASK: Implement the complete Python SDK. Use spawn_agent internally to delegate.

SUB-AGENT 1 — Core Types & Wire Protocol
- Read PYTHON-SDK-SPEC.md §§3-5
- Create src/polymesh/__init__.py, types.py, protocol.py
- Implement ALL pydantic models: AgentCard, Capability, Envelope, DeliveryMode, TaskStatus, HandshakeFrame types
- Implement wire protocol: hello→auth→card→ready→envelopes flow, newline-delimited JSON framing
- Implement UUIDv7 generation, canonical JSON, session ID derivation
- Implement envelope construction, encoding, decoding
- These types MUST match the TypeScript reference impl byte-for-byte compatible

SUB-AGENT 2 — PolyMeshClient & Task Lifecycle
- Read PYTHON-SDK-SPEC.md §§3, 6
- Create src/polymesh/client.py with PolyMeshClient class
- Connect/disconnect lifecycle with async context manager
- await client.call(target, capability, input, timeout) — returns TaskHandle
- Handler registration: @client.handle("capability.id")
- TaskHandle with status, result property, cancel() method
- TaskContext for handlers (task_id, source, input, progress())
- Capability calling via call_with_result() awaitable
- Receipt protocol, retry guidance
- Must be fully async (asyncio)

SUB-AGENT 3 — Transport & Reconnect
- Read PYTHON-SDK-SPEC.md §7
- Create src/polymesh/transport.py
- WebSocket transport with asyncio + websockets library
- Reconnect with exponential backoff (1s→60s, 2x multiplier, 20% jitter)
- Generation fencing for race safety
- Heartbeat (30s ping, 5s pong timeout)
- Connection state machine (idle→connecting→handshaking→active→closing→closed)
- Token file management (~/.polymesh/token)

SUB-AGENT 4 — CLI & Packaging
- Read PYTHON-SDK-SPEC.md §9
- Create src/polymesh/cli.py and pyproject.toml
- CLI commands: polymesh connect, call, listen, peers, capabilities
- Config file support (TOML)
- Environment variable overrides
- Output formatting (JSON, table, plain)
- Setup pyproject.toml with dependencies: websockets, pydantic, httpx, click
- create-polymesh-app template command

SUB-AGENT 5 — Tests
- Create tests/ directory
- Unit tests: type encoding/decoding, envelope validation, UUIDv7
- Integration test: Python client ↔ Python broker (same process, in-memory transport)
- Protocol test: hello→auth→card→ready flow with mock transport
- Reconnect test: verify generation fencing, backoff, state recovery
- CLI test: parse args, output format
- Must pass with pytest

RULES:
- Wire-compatible with the TypeScript reference implementation
- Python 3.11+ required
- Asyncio throughout
- All files under src/polymesh/
- Output all files
- Run pytest after all changes
- Output "DONE" with test results summary

NO web searches. Use your training knowledge and the attached spec.
