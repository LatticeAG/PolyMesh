You are building the PolyMesh Protocol reference implementation. The full SPEC.md is at /home/ubuntu/polymesh/SPEC.md.

IMPORTANT: You are running in --yolo mode. The sandbox is completely disabled. You have full read/write access to /home/ubuntu/polymesh/.

AUTHORITY: Create, edit, and delete any files you need inside /home/ubuntu/polymesh/. You own this workspace.

YOUR TOOL SET:
- You have "spawn_agent" - use it to delegate sub-tasks to sub-agents
- You have "list_agents", "wait_agent", "send_message" - manage sub-agents
- You have filesystem tools - read/write files at will
- You can execute shell commands. node, npm, npx, tsc are all available.

HOW TO WORK:
1. Read /home/ubuntu/polymesh/SPEC.md now - especially section 11 (Reference Implementation)
2. Plan the build. Decide how many sub-agents you need and what each builds
3. Use spawn_agent to create them with focused instructions
4. Use wait_agent to collect all results
5. Validate, fix, and run npm test
6. Commit to git

BUILD TARGETS (from SPEC.md section 11):
- @polymesh/broker: protocol.ts (35 LOC), registry.ts (120 LOC), broker.ts (120 LOC)
- @polymesh/client: client.ts (75 LOC), cli.ts (45 LOC), mdns.ts (20 LOC)
- package.json files, tsconfig, vitest config
- Tests: registry unit tests, in-memory integration, WebSocket integration, error cases

START WITH: Set up the npm workspace structure first (package.json files, tsconfig).
THEN: Build packages in parallel using spawn_agent.
THEN: Write tests.
THEN: Run "npm test" and report results.
THEN: git add -A && git commit -m "Reference implementation" && git push origin main

NO web searches. Use only your training knowledge.
