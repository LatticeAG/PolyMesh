# PolyMesh

PolyMesh is an experimental, local-first protocol implementation for agents to declare capabilities and exchange bounded tasks. Version 0.3.0 focuses on a reproducible local evaluation path: installable packages, a runnable broker-and-agents demo, cross-language fixtures, and clear support boundaries.

[![CI](https://github.com/LatticeAG/PolyMesh/actions/workflows/ci-full.yml/badge.svg)](https://github.com/LatticeAG/PolyMesh/actions/workflows/ci-full.yml)
[![Release](https://github.com/LatticeAG/PolyMesh/actions/workflows/release.yml/badge.svg)](https://github.com/LatticeAG/PolyMesh/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Experimental software: review [SECURITY.md](SECURITY.md) before exposing a listener or allowing any side-effecting capability. PolyMesh does not provide a hosted relay in this repository.

## Quick start

After the release artifacts have been published to npm, create the maintained example project from the published generator:

```bash
npx @latticeag/create-polymesh-app my-agents
cd my-agents
npm install
npm run demo
```

The generated demo starts a local broker and client, exchanges a safe ping/pong, and exits cleanly. It uses only a numeric loopback endpoint and an ephemeral runtime token; do not reuse this development posture for LAN or Internet deployment.

For a process-boundary demonstration, run the checked-in Compose fixture:

```bash
docker compose up --build
```

It prints the broker, Alice, and Bob lifecycle and exits when Alice receives Bob's echo result. The demo is intentionally local-only and is not a production container deployment guide.

## Packages

| Package | Purpose |
| --- | --- |
| `@latticeag/polymesh-broker` | TypeScript WebSocket broker and local registry |
| `@latticeag/polymesh-client` | TypeScript client SDK, CLI, and constrained mDNS discovery |
| `@latticeag/polymesh-gateway` | Node REST/SSE gateway reference adapter |
| `@latticeag/create-polymesh-app` | Starter generator for the local ping/pong example |
| `latticeag-polymesh` | Python distribution; import it as `polymesh` |

The TypeScript CLI is provided by `@latticeag/polymesh-client`:

```bash
npx @latticeag/polymesh-client help
```

Its configuration is TOML. It reads `~/.config/polymesh/config.toml` by default; use `POLYMESH_CONFIG` or `--config FILE` to select another file, then inspect effective non-secret settings with:

```bash
npx @latticeag/polymesh-client config show
```

## Support matrix

| Capability | Status in v0.3.0 | Notes |
| --- | --- | --- |
| v0.1 local task lifecycle | Supported | TypeScript broker/client and Python SDK are covered by shared compatibility vectors. |
| v2 gateway REST/SSE adapter | Experimental | Node reference adapter only; its current scope is task submission and task-event observation. |
| v2 native SDK clients | Not supported as a release promise | The Python SDK remains a v0.1 surface; do not infer v2 support from package versioning. |
| mDNS discovery | TypeScript supported, Python not yet native | TypeScript discovery is opt-in and WSS-only; it is a hint, never enrollment or auto-connect. |
| Remote transport | Explicitly configured WSS only | Secure transport requires the exact enrolled profile. There is no deployed Worker, Durable Object, or managed relay. |
| Docker Compose demo | Supported local fixture | A repeatable development demo, not a production deployment architecture. |
| DeckAgent carrier | Client-side experimental component | No production DeckAgent service or relay deployment is claimed. |

### Profile support

| Profile | TypeScript | Python | Security boundary |
| --- | --- | --- | --- |
| Numeric-loopback development WebSocket | Supported with an explicit runtime token and `--insecure-loopback-dev` | Supported for the v0.1 SDK path | Local development only; never advertise it or bridge it across a normal container, LAN, or Internet network. The Compose fixture deliberately shares the broker network namespace to retain numeric-loopback semantics. |
| Enrolled WSS | Supported where the exact carrier and enrollment requirements are configured | Not advertised as a general secure-carrier implementation | Mutual enrollment and TLS requirements fail closed. |
| mDNS WSS discovery hints | Supported and opt-in | Optional dependency exists; no native network provider is claimed | Discovery conveys no trust and never initiates enrollment. |
| Hosted/remote relay | Not available | Not available | Planned separately; no Worker relay deployment is included. |

## What the local flow does

```text
Alice client ── task.submit ──> Local broker ── task.submit ──> Bob agent
Alice client <─ accepted/progress/completed ─ Local broker <─ lifecycle ─ Bob
```

Each agent publishes an Agent Card with its identity and capability contracts. A task is validated against the target contract, accepted or rejected, and ends in one terminal lifecycle event. The generated quick start uses a harmless ping/pong; the Compose fixture uses a harmless echo capability. Neither needs filesystem, shell, network, or third-party credentials.

For the layered view and dependency graph, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Configuration precedence

The TypeScript CLI merges settings in this order:

```text
defaults < TOML config file < environment variables < command-line flags
```

Supported TOML sections are `[broker]`, `[client]`, and `[discovery]`. Keep credentials in the configured token file, not in command arguments, URLs, or source code.

## Verification

The v0.3.0 release gate runs clean installs, TypeScript type checking/build/tests, Python tests/builds, package artifact smoke tests, and shared compatibility fixtures. The baseline suites contain 157 TypeScript tests and 60 Python tests; the release workflows also run the added conformance checks.

From a source checkout:

```bash
npm ci
npm run typecheck
npm test
npm run build

uv sync --dev
uv run pytest -q
uv build
```

## Scope and limitations

PolyMesh v0.3.0 does not claim generic end-to-end envelope signing, delegated authorization grants, continuous task-output streaming, generic pub/sub, automatic multi-hop routing, a native v2 Python client, or production hosting. Gateway SSE is task-event observation, not general streaming or a topic system.

The repository contains protocol design material governed by local repository policy. This README is intentionally a high-level implementation guide and does not publish or reproduce that material.

## Development feedback

When reporting an issue, include the package versions, selected profile, redacted command output, and a minimal reproduction. Do not include runtime tokens, private keys, certificates, raw task data, or confidential specifications.

## License

PolyMesh is released under the [MIT License](LICENSE).
