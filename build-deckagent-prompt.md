You are building the PolyMesh DeckAgent tunnel carrier for v0.2.1 internet bridging. The full spec is at /home/ubuntu/polymesh/V2-ROADMAP.md (the updated DeckAgent section).

YOUR JOB: Build the DeckAgent Internet Carrier using spawn_agent internally.

SUB-AGENT 1 — DeckAgentCarrier adapter
- Read V2-ROADMAP.md section "DeckAgent tunnel adapter" for the full protocol spec
- Read packages/desktop-daemon/src/tunnel-client.ts from /home/ubuntu/deckagent for the real tunnel client
- Read packages/cloudflare-worker/src/types.ts from /home/ubuntu/deckagent for the message types
- Create packages/client/src/deckagent-carrier.ts implementing:
  - DeckAgentCarrier class wrapping PolyMesh envelopes in DeckAgent execute_tool messages
  - Uses reserved tool name __polymesh_envelope__
  - Virtual channel multiplexing per (mesh_id, agent_id, instance_id)
  - Fencing with fence counter and received_through replay
  - Exponential backoff reconnection (1s → 30s max)
  - Auth handshake + heartbeat management
  - Replay outbox records on reconnect
- The carrier implements the WireTransport interface from @polymesh/broker

SUB-AGENT 2 — Tests
- Create tests/deckagent-carrier.test.ts
- Test virtual channel lifecycle (open → ready → close)
- Test envelope wrapping and unwrapping
- Test reconnect with received_through replay
- Test fence enforcement (old fence frames discarded)
- Test heartbeat timeout and recovery
- Mock the DeckAgent tunnel (don't require real connection)

RULES:
- The existing 135 tests MUST still pass
- The carrier MUST implement WireTransport interface
- Run npm test after all changes
- NO web searches. Use your training knowledge and the local codebase.
- Output "DONE" with test results summary
