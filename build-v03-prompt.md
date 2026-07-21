You are building the PolyMesh v0.3.0 release. Read the appended V03-ROADMAP-ULTRA.md and current repo state.

TASK: Implement all v0.3.0 must-ship items. Use spawn_agent internally to delegate.

SUB-AGENT 1 — I-01: Release CI Automation
- Create .github/workflows/release.yml
- On tag push (v*) or manual dispatch:
  - TypeScript: npm ci → tsc build → npm test → npm pack (verify tarball)
  - Python: uv sync --dev → pytest → uv build → verify wheel installs clean
  - Cross-language: run a Python script that imports from published TS types via schema
  - Artifact: attach npm tarball + Python wheel to release
- Create .github/workflows/ci-full.yml:
  - On push/PR: npm ci → tsc → npm test → build → uv sync → pytest → uv build
- Update README badges to point to LatticeAG/PolyMesh CI

SUB-AGENT 2 — S-01 + S-02: Package Consistency + Cross-Language Vectors
- Fix ALL internal imports in TypeScript from @polymesh/broker to @latticeag/polymesh-broker (or add path aliases so both work)
- Create tests/compat/ with:
  - envelope-vectors.json — known inputs/outputs for envelope encoding
  - card-vectors.json — known agent cards with expected digests
  - handshake-vectors.json — hello/auth/card/ready message flows
- Python tests/compat/import these same vectors and verify encoding matches
- TypeScript tests/compat/import the vectors and verify encoding matches
- Both SDKs produce identical output from the same vector inputs

SUB-AGENT 3 — E-02: Quick-Start Template
- Create templategen/ directory with:
  - packages/create-polymesh-app/ package.json (npm init template)
  - Template content: minimal broker.js + client.js that exchange a ping/pong
  - The quick-start user experience: `npx @latticeag/create-polymesh-app my-agents`
- Create Dockerfile + docker-compose.yml:
  - Three services: broker, alice (agent), bob (agent)
  - alice calls bob's "echo" capability via PolyMesh
  - All services use the published @latticeag/polymesh-* packages
  - Dockerfile uses Node 22 slim, multi-stage
- The compose demo must be `docker compose up` → see agents talk → exit cleanly

SUB-AGENT 4 — E-01: Honest README + Documentation
- Rewrite README.md:
  - Replace all stale claims with current state
  - Add support matrix table (v0.1, v2 gateway, mDNS, remote transport)
  - Update test counts (157 TS, 60 Python)
  - Fix all package names (@latticeag/...)
  - Update CI badges to LatticeAG/PolyMesh
  - Add "Quick start" section that actually works with published packages
  - Add "Profile support" table
  - Remove any claim of deployed Worker relay or DeckAgent production use
- Create ARCHITECTURE.md:
  - High-level architecture diagram (ASCII)
  - Protocol layers: transport → framing → handshake → envelope → application
  - Package dependency graph
  - When to use broker vs client vs gateway

SUB-AGENT 5 — S-03: TypeScript CLI TOML Config
- Add TOML config file support to packages/client/src/cli.ts:
  - Default path: ~/.config/polymesh/config.toml
  - Override: POLYMESH_CONFIG env var, --config flag
  - Config sections: [broker] (host, port, token), [client] (default_timeout, reconnect), [discovery] (mdns_enabled, mdns_interval)
  - Merge order: defaults < config file < env vars < CLI flags
- Add config.ts module for reading/config validation
- Use smol-toml (zero deps) or @iarna/toml
- Add polymesh config show command
- Tests for config file parsing and merge precedence

RULES:
- All 157 TypeScript tests must still pass
- All 60 Python tests must still pass
- Output "DONE" with summary of what was built and all test results
- Do NOT modify any governed spec files (SPEC*.md, V2-SPEC*.md, PYTHON-SDK*.md)

NO web searches. Use your training knowledge and the attached roadmap + repo.
