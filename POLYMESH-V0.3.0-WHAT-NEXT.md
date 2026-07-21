# PolyMesh v0.3.0 — What Next

> Internal planning document for an authorized LatticeAG checkout.
>
> Decision horizon: v0.3.0, followed by explicitly scoped v0.4+ work.
>
> Evidence reviewed: repository state, V2-SPEC-ULTRA.md,
> PYTHON-SDK-SPEC.md, SPEC.md, V2-ROADMAP.md, package metadata, source,
> tests, and CI configuration.
>
> This is a product and engineering roadmap, not a new normative wire
> specification.
>
> It must not be copied into a public repository without the applicable
> authorization and sanitization review.

## 1. Decision in one page

PolyMesh v0.3.0 should be the release that makes the project installable,
reproducible, and easy to evaluate locally.

It should not be a second protocol-expansion release.

The existing repository contains substantial useful work:

- a TypeScript broker, client, gateway, compression module, durable-store
  model, routing model, security helpers, and DeckAgent client carrier;
- a Python SDK with a well-developed v0.1 surface;
- a real REST/SSE gateway implementation and tests;
- a large set of v2 security, durability, routing, and compression design
  material;
- TypeScript and Python test suites that pass when invoked through the local
  test executables.

It also contains release-blocking gaps:

- the built TypeScript CLI cannot currently resolve its broker dependency after
  the package namespace changes;
- the TypeScript packages are at 0.2.0 while the Python distribution targets
  v0.1 wire compatibility and a differently named package;
- the v2 specification/source of truth is not singular;
- the present gateway is a Node HTTP adapter with an in-memory reference
  broker, not a deployed Worker relay;
- the CI workflow does not exercise Python, clean package installs, a release
  build, or cross-language interoperability;
- documentation commands, package names, and test counts are stale;
- there is no complete container demo, Cloudflare Worker, Durable Object,
  Dockerfile, Compose file, or public-safe documentation pipeline.

The v0.3.0 objective is therefore:

> A developer can install a versioned PolyMesh SDK, follow one verified
> local-first guide, run a broker and two agents safely, observe a complete
> task lifecycle, and understand exactly which wire profiles are supported.

That objective has more adoption value than adding another half-integrated
protocol primitive.

The release must establish a clean boundary:

- v0.3.0 owns release reliability, documentation, local evaluation,
  cross-language conformance, and bounded usability improvements;
- v0.4+ owns one carefully selected advanced wire capability at a time;
- a hosted Cloudflare relay is a separate infrastructure program, not a
  v0.3.0 checkbox;
- a public RFC or whitepaper is separate from the confidential local
  specifications governed by AGENTS.md.

## 2. Recommended release position

### 2.1 Release thesis

Name the release internally:

> PolyMesh v0.3.0: the reproducible local-first release.

The core promise is not that PolyMesh now does everything agents might need.

The core promise is:

> The documented local path works end to end, has a stable package surface,
> and does not ask users to infer unsupported security or deployment claims.

### 2.2 What v0.3.0 will ship

The committed v0.3.0 scope should contain five workstreams:

1. Resolve package identity, imports, versions, installation, and release
   automation.

2. Freeze one canonical source for the existing v2 wire contract and ship
   conformance fixtures plus an explicit v0.1/v0.2 support matrix.

3. Ship one security-correct local-first quick start:

   - broker;
   - caller agent;
   - executor agent;
   - typed capability;
   - progress;
   - completion;
   - rejection and cancellation behavior;
   - a repeatable automated smoke test.

4. Make the TypeScript CLI and operational configuration predictable enough to
   support the quick start without hidden environment assumptions.

5. Publish a maintained documentation and compatibility guide from
   sanitized, approved source material.

The only optional v0.3.0 lane is one of:

- opt-in Python mDNS discovery;
- a narrowly bounded Hermes integration pilot;
- container-image hardening required by the Compose demo.

Gateway lifecycle expansion and typed gateway clients are not v0.3.0
commitments. MCP implementation belongs in v0.4. Delegated authorization may
have an internal design artifact, but has no v0.3.0 runtime grant support.

### 2.3 What v0.3.0 will not claim

v0.3.0 will not claim:

- a generally available end-to-end signed-envelope security boundary;
- true continuous agent-to-agent output streaming;
- general pub/sub topics;
- automatic multi-hop forwarding or route migration;
- a production Cloudflare Worker deployment;
- a production durable relay;
- a general-purpose dynamic plugin system;
- full native v0.2 WebSocket client support in both SDKs;
- a publicly safe Discord agent-broker service;
- that the private specification files are public RFC material.

### 2.4 Why this is the right cut

Every omitted capability is valuable in some setting.

None is small.

Streaming needs backpressure and replay semantics.

Pub/sub needs authorization, fan-out limits, cursor semantics, and filtering.

Delegation needs a real grant verifier, revocation, audit, and policy
intersection.

Multi-hop routing needs durable per-hop ownership and loop control.

Workers need a durable relay architecture, not a wrapper around an in-memory
Node server.

Trying to ship several of those at once would make it difficult to say what
PolyMesh actually guarantees.

The already-built gateway SSE path and the existing task lifecycle give users
a better near-term long-running-task experience than inventing stream records
prematurely.

## 3. Evidence and current-state readout

### 3.1 Repository evidence

The assessment found the following verifiable facts.

| Area | Current state | Planning consequence |
|---|---|---|
| Root workspace | TypeScript monorepo version 0.2.0. | Package/version policy is required before publishing. |
| TypeScript broker | Contains v0.1 and substantial v2 code, routing, durable-store, rate-limit, compression, and security modules. | Preserve useful groundwork; do not create a third wire dialect. |
| TypeScript client | Has client, CLI, mDNS, policy, replay ledger, and DeckAgent carrier modules. | Improve usability and runtime packaging before adding a plugin host. |
| Gateway | Node HTTP REST/SSE gateway with adapter boundary and in-memory test broker. | Useful semantics exist; a Worker port remains unbuilt. |
| Python SDK | Packaged async v0.1 SDK with strict parsing, card/auth/provenance signatures, config, CLI, and tests. | Do not advertise it as native v0.2 support. |
| Python discovery | Optional mDNS dependency is declared, but discovery is a local-cache/provider stub. | mDNS is optional v0.3 work, not a completed feature. |
| CI | One Node 22 workflow builds and runs Vitest. | Add Python, package smoke, vectors, and release gates. |
| Demo assets | No Dockerfile or Compose file; the checked-in templates directory is empty. | Build one real starter/demo rather than another conceptual example. |
| Cloudflare assets | No Worker source, wrangler configuration, Durable Object, tunnel config, or deployment test. | Treat remote relay as v0.4+ infrastructure. |
| Public docs | README is useful but stale on package names and test count. | Correct it before promotion; create approved public docs separately. |

### 3.2 Validation performed during assessment

The following commands completed successfully in this checkout:

- npm test:

  - 30 TypeScript test files passed;
  - 157 TypeScript tests passed.

- npm run typecheck:

  - TypeScript source typechecked successfully.

- npm run build:

  - broker, client, and gateway build steps completed successfully.

- pytest -q:

  - 60 Python tests passed through the locally available pytest executable.

The following runtime smoke test failed:

~~~text
node packages/client/dist/cli.js help
~~~

The built CLI fails with module resolution for the old broker package name.

The current package manifests use the LatticeAG namespace while source imports
still use the historical PolyMesh namespace.

That is a release blocker even though source build and unit tests pass.

### 3.3 Important specification observations

V2-SPEC-ULTRA.md is rich design input, but it is not currently a clean,
standalone normative artifact:

- it begins mid-section;
- it contains pasted deleted-file diff material;
- it overlaps with SPEC-V2.md and older v2 source;
- it does not by itself establish one obvious generated schema source.

The code mirrors that ambiguity:

- the normative-looking protocol module places the v2 delivery identifier
  inside the delivery object;
- the legacy v2 module models an optional top-level delivery identifier;
- the gateway uses the nested representation;
- the public barrel intentionally exposes both legacy and newer v2 material.

This is not an invitation to accept both layouts forever.

It is a reason to freeze a single v2 schema bundle before adding extensions.

### 3.4 Security and governance constraints

The planning decisions below assume:

- remote endpoints remain fail-closed;
- raw OAuth tokens, client certificates, DPoP proofs, and caller-provided
  authorization blobs do not enter ordinary envelopes;
- mDNS remains a discovery hint, never an enrollment or auto-connect signal;
- plaintext WebSocket remains a numeric-loopback, explicit development
  posture only;
- a generic plugin system must not become a hidden arbitrary-code or policy
  execution system;
- package install, demo, documentation, and release changes must not weaken
  secret-handling behavior;
- AGENTS.md governs the confidential specification and review files in this
  checkout.

The public-documentation workstream therefore creates new approved material.

It does not publish, copy, or lightly edit the confidential specification and
review files.

## 4. Prioritization model

### 4.1 Scoring formula

Every roadmap item receives:

- an impact value;
- a reach value;
- an effort value.

The priority score is:

~~~text
priority = (impact × reach) / effort
~~~

The scale is intentionally coarse:

| Dimension | Low / small | Medium | High / large |
|---|---:|---:|---:|
| Impact | 1 | 2 | 3 |
| Reach | 1 | 2 | 3 |
| Effort | 1 | 2 | 3 |

Effort is a denominator.

Each scored card selects one label. When a discussion notes that implementation
could expand in scope, its score uses the conservative, larger effort value.
Benefit is represented by impact; implementation complexity is reflected in
the effort class and the required-design and failure-mode detail on each card.

This prevents an attractive large protocol program from outranking a small
release blocker merely because its theoretical impact is high.

### 4.2 How to read the score

A score is not a release authorization.

It is a sequencing aid.

An item may be deferred despite a good score when:

- it requires a prerequisite not in the release;
- it has a security-review dependency;
- it expands the support matrix faster than the team can test it;
- it creates an operating commitment;
- it would make the public message less clear.

Conversely, a low-scoring security prerequisite can be mandatory.

### 4.3 Portfolio rules

Use these rules throughout the roadmap:

1. Fix a release blocker before adding a new user-facing capability.

2. Prefer adapter packages and explicit capability handlers over new core
   protocol messages where the existing task lifecycle is sufficient.

3. Keep package version and wire-profile version independent and explicit.

4. Do not declare an implementation available because a specification or
   architecture diagram exists.

5. Do not expose a local development transport to containers or a network
   merely to make a demo easier.

6. A new remote capability is not complete until its failure, replay,
   authorization, rate-limit, logging, and recovery behavior are tested.

7. Each advanced protocol feature gets its own selected extension/profile,
   conformance vectors, and compatibility story.

8. If a proposal cannot state what happens on reconnect, cancellation,
   overload, revocation, and crash recovery, it is not ready for the wire.

### 4.4 Status labels

| Label | Meaning |
|---|---|
| Ship | Committed v0.3.0 scope. |
| Candidate | Valuable and feasible if prerequisites land. |
| Conditional | May enter only after defined gates and capacity are available. |
| Design | Produce a bounded design/vector artifact, not a general runtime promise. |
| Defer | Keep out of v0.3.0 and schedule later. |
| Do not add | Reject as a standalone feature; simplify into existing work instead. |

## 5. Current capability matrix

| Capability | Specification intent | Repository reality | v0.3.0 posture |
|---|---|---|---|
| v0.1 WebSocket tasks | Local agent task lifecycle. | Implemented by TypeScript and Python SDKs. | Maintain and document. |
| v0.2 wire profile | Durable mesh-scoped protocol. | Substantial code/spec work, but divergent legacy/new representations. | Canonicalize before expansion. |
| Card signatures | Ed25519 signed card identity. | Implemented in both languages. | Preserve; add vectors. |
| Auth proof | Enrolled profile proof. | Implemented in v0.1/v2-related code paths. | Do not weaken. |
| Broker provenance | Relay-generated attestation. | Implemented in TS/Python secure model. | Distinguish from origin signatures. |
| Generic envelope signatures | End-to-end origin integrity. | Not implemented. | Design only or defer. |
| Task progress | Coarse lifecycle updates. | Implemented. | Expose ergonomically. |
| Continuous task output | Chunks, tokens, or log stream. | Not implemented. | Defer true wire feature. |
| Gateway SSE | Task-lifecycle observation. | Implemented as Node gateway adapter. | Document scope; clientize later. |
| Pub/sub topics | General event fan-out. | Not implemented. | Defer. |
| MCP usage | Agent consumes MCP tools. | No bridge implementation. | Adapter candidate. |
| Delegated authority | Attenuated acting authority. | Gateway carries opaque delegation ID only. | Design/conditional one-hop profile. |
| Compression | Negotiated zstd v2 design/code. | No full Unix transport service. | Canonicalize; do not make Unix-only feature. |
| Local Unix transport | Secure peer-credential UDS service. | Framing support exists; end-to-end service not evidenced. | Defer. |
| mDNS in TypeScript | WSS-only hints. | Implemented and tested. | Keep constrained. |
| mDNS in Python | Optional discovery extra. | Stub/cache only. | Conditional implementation. |
| DeckAgent client carrier | Outbound virtual carrier. | Implemented TS client-side. | Not a Worker deployment claim. |
| Worker relay | Hosted remote relay. | Architecture only. | v0.4+ program. |
| Docker demo | Repeatable onboarding. | Not present. | Ship safe demo. |
| Package publishing | Consumable artifacts. | Not evidenced; runtime namespace mismatch. | Mandatory v0.3 work. |

## 6. Ranked portfolio at a glance

The detailed cards below are authoritative.

This table gives the initial rank across the portfolio.

| Priority band | Item | Group | I/R/E | Score | v0.3 decision |
|---|---|---|---:|---:|---|
| Must | Package namespace and runtime-install repair | SDK | 3/3/1 | 9.0 | Ship |
| Must | Canonical v2 schema, profile, and vectors | Protocol | 3/3/2 | 4.5 | Ship |
| Must | Release CI/CD and clean-install smoke tests | Infrastructure | 3/3/2 | 4.5 | Ship |
| Must | Two-agent quick start and secure Compose demo | Infrastructure | 3/3/2 | 4.5 | Ship |
| Must | Documentation, support matrix, and naming correction | Ecosystem | 3/3/2 | 4.5 | Ship |
| Must | Checked-in template and generator repair | Ecosystem | 3/3/2 | 4.5 | Ship |
| Must | Cross-language vectors and interoperability gate | SDK | 3/3/2 | 4.5 | Ship |
| Candidate | Release feedback loop and safe diagnostics | Ecosystem | 2/2/1 | 4.0 | Ship |
| Candidate | TypeScript TOML config and CLI parity | SDK | 2/3/2 | 3.0 | Ship narrowly |
| Defer | Gateway lifecycle completion and typed client | Protocol/SDK | 3/2/2 | 3.0 | v0.4 gateway scope |
| Defer | MCP capability bridge | Protocol/SDK | 3/2/2 | 3.0 | v0.4 integration |
| Conditional | Python mDNS discovery | SDK | 2/2/2 | 2.0 | Choose one stretch item |
| Conditional | Hermes least-privilege pilot | Ecosystem | 2/2/2 | 2.0 | Choose one stretch item |
| Design | One-hop delegated authorization | Protocol | 3/2/3 | 2.0 | Design, then defer |
| Defer | Generic EdDSA envelope signing | Protocol | 3/2/3 | 2.0 | Design, then defer |
| Defer | Native v2 SDK clients | SDK | 3/2/3 | 2.0 | Sole flagship next release |
| Defer | Worker-native durable relay | Infrastructure | 3/2/3 | 2.0 | Hosted-relay program |
| Defer | True task streaming | Protocol | 3/2/3 | 2.0 | v0.4+ |
| Defer | Pub/sub topics | Protocol | 2/2/3 | 1.3 | v0.4+ |
| Defer | Artifact-transfer companion profile | Protocol | 3/1/3 | 1.0 | v0.4+ |
| Do not add | Generic dynamic plugin host | SDK | 1/2/3 | 0.7 | Refuse |
| Do not use | Cloudflare Tunnel as shortcut | Infrastructure | 2/1/3 | 0.7 | Not an architecture |
| Do not add | Discord broker bot | Ecosystem | 1/2/3 | 0.7 | Defer indefinitely |
| Do not add | Unix-only compression dialect | Protocol | 1/1/2 | 0.5 | Keep generic |
| Defer | Multi-hop routing | Protocol | 1/1/3 | 0.3 | Defer indefinitely |

## 7. Protocol roadmap

The protocol workstream has two jobs in v0.3.0:

- make the current profile coherent enough to be implemented independently;
- resist adding features that require a second unreviewed semantics layer.

### P-01 — Canonical v2 profile, schema bundle, and conformance gate

- **Name:** Canonical v2 profile, schema bundle, and conformance gate.

- **What it is:** One selected representation of the v2 profile, one
  application-envelope shape, one delivery layout, one control-record registry,
  one compression layout, and generated or checked-in schema artifacts.

- **Current evidence:** The normative-looking protocol module and the gateway
  use a nested delivery identifier, while legacy v2 code retains an optional
  top-level delivery identifier. V2-SPEC-ULTRA.md contains mixed draft/diff
  material.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Ship in v0.3.0 before accepting any new v2 extension.

- **Release scope:** Freeze a canonical schema/vector bundle and profile
  declaration, not a full new v2 runtime; add a compatibility matrix; reject
  the alternate layout on a canonical session; provide an explicit adapter or
  selected legacy boundary only if existing users need it.

- **Required outputs:**

  - canonical envelope, card, handshake, control, compression, gateway, and
    error schemas;
  - stable extension-name registry;
  - profile-selection rules;
  - unknown-extension rejection rules;
  - v0.1/v0.2 mapping statement;
  - migration notes for legacy v2 source;
  - TypeScript and Python fixture consumers;
  - positive and negative vectors.

- **Vectors must cover:**

  - canonical JSON;
  - timestamps;
  - UUIDv7;
  - mesh and address parsing;
  - semantic and record digests;
  - card signatures;
  - auth proofs;
  - receipts;
  - compression negotiation;
  - compression bomb rejection;
  - duplicate delivery IDs;
  - replay/idempotency conflicts;
  - route fences;
  - gateway cursor behavior.

- **Non-goal:** Do not support both conflicting fields by silently accepting
  either spelling.

- **Exit condition:** A clean-install TypeScript consumer and a Python fixture
  runner produce identical accept/reject decisions for the advertised profile.

### P-02 — Extension governance

- **Name:** Extension governance and profile-selection policy.

- **What it is:** A small process and registry for adding selected optional
  protocol extensions without turning envelope parameters into an escape hatch.

- **Current evidence:** The base v2 application registry intentionally rejects
  stream, subscription, artifact, authorization, and carrier messages absent
  a selected extension, but no single release governance workflow is surfaced.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Ship as part of P-01, not as an independent product
  feature.

- **Required policy:**

  - extensions have stable names and versioned schemas;
  - extension selection happens before records use it;
  - a peer may advertise capability without selecting it;
  - unknown extensions fail closed;
  - a failed extension negotiation never downgrades transport security;
  - extensions do not redefine base task lifecycle authority;
  - every extension has vectors and a feature matrix.

- **Non-goal:** Do not create a generic extensions object inside application
  envelope parameters.

- **Exit condition:** A test demonstrates that a base-only peer rejects an
  extension record rather than interpreting it as an ordinary task parameter.

### P-03 — Generic EdDSA origin-envelope signing

- **Name:** Generic EdDSA origin-envelope signing.

- **What it is:** A future negotiated extension that lets the origin sign an
  immutable, canonical projection of a task envelope so a recipient can
  distinguish origin intent from relay-created provenance.

- **Current evidence:** Cards, v0.1 secure auth proofs, and broker provenance
  already use Ed25519. Those signatures do not constitute a generic
  end-to-end envelope signature.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** In v0.3.0, freeze a design note and vectors only if
  P-01 is complete. Do not market it as general production support. Plan
  implementation and independent security review for v0.4+.

- **Why it matters:** A relay may need to add delivery IDs, trusted route
  metadata, compression wrappers, or recipient-specific output handling
  without changing the origin-signed semantics.

- **Minimum signed projection:**

  - selected profile;
  - source mesh, agent, and instance identity;
  - target mesh, agent, and requested instance identity;
  - message ID;
  - task ID;
  - capability tuple;
  - input digest or immutable input;
  - deadline;
  - idempotency semantics;
  - explicit expiry;
  - key identifier;
  - algorithm identifier.

- **Required design decisions:**

  - domain-separated signing bytes;
  - RFC 8785-compatible canonicalization;
  - Ed25519 initial algorithm constraints;
  - enrollment binding;
  - key rotation;
  - revocation;
  - signature expiry;
  - replay relationship;
  - delegation interaction;
  - filtered-result semantics;
  - relay provenance interaction;
  - error behavior for an unverifiable signature.

- **Safety constraints:**

  - a signature never replaces authenticated transport;
  - a signature never replaces durable replay state;
  - a signature never makes an untrusted card an enrollment;
  - a relay must not re-sign an origin envelope as if it were the origin;
  - no signature field is smuggled into v0.1 parameters, metadata, or a
    closed record.

- **Non-goal:** Do not make arbitrary signature algorithms pluggable in the
  first version.

- **Exit condition for design:** Two independent implementations validate the
  same signing vectors and reject field-mutation variants.

### P-04 — MCP capability bridge

- **Name:** Configured MCP capability bridge.

- **What it is:** An agent-side adapter that projects explicitly allowed MCP
  tools as normal PolyMesh capabilities with pinned schemas and ordinary task
  lifecycle behavior.

- **Current evidence:** No bridge implementation exists. SPEC.md describes
  MCP as agent-to-tool and also contains a generic MCP execute capability
  concept, which would be too broad as an authorization boundary.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 3.0.

- **Recommendation:** Defer implementation to v0.4. In v0.3.0, record the
  decision to replace generic MCP execution with explicit capability
  projection. It is an SDK/adapter feature, not a new wire message.

- **Recommended shape:**

  - operator config declares MCP server connection;
  - operator config selects individual tools;
  - bridge maps each selected tool to an explicit PolyMesh capability;
  - bridge pins tool input/result schemas into its Agent Card;
  - bridge applies normal capability policy before invoking the MCP tool;
  - bridge returns bounded, validated task results through the normal
    lifecycle;
  - tool contract changes appear as a new card revision and do not alter an
    accepted task.

- **Explicitly reject:**

  - task-provided MCP server URLs;
  - task-provided commands or transports;
  - arbitrary tool selection;
  - raw OAuth token forwarding;
  - raw MCP session forwarding;
  - arbitrary caller-supplied authorization contexts;
  - automatic exposure of every MCP tool;
  - a single catch-all remote MCP execute capability.

- **Security controls:**

  - per-tool allowlist;
  - per-tool capability policy;
  - input schema validation;
  - result schema validation;
  - bounded timeout;
  - bounded result bytes;
  - cancellation propagation where supported;
  - controlled process/network configuration;
  - secret redaction;
  - audit record with tool identity, not raw arguments by default.

- **Non-goal:** Do not make PolyMesh a replacement protocol for MCP.

- **Exit condition:** A test MCP server demonstrates that one configured,
  allowlisted tool is callable while an unlisted tool and an arbitrary server
  target are rejected.

### P-05 — Agent-to-agent streaming

- **Name:** Task-bound continuous output streaming.

- **What it is:** A future executor-to-owner stream for incremental model
  output, logs, or structured chunks, distinct from coarse task-progress
  lifecycle updates.

- **Current evidence:** Existing progress and gateway SSE deliver lifecycle
  events. They do not supply stream IDs, chunk ordering, credits, or replay.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Defer true wire streaming to v0.4+. In v0.3.0, expose
  bounded SDK iteration over existing lifecycle events instead.

- **Why not overload progress:** Progress is advisory task state. It lacks the
  contract needed for high-volume content, ordering, replay, and consumer
  backpressure.

- **Future design requirements:**

  - stream ID bound to task, route, capability contract, and authorization;
  - monotonic chunk sequence or offset;
  - bounded chunk size;
  - bounded total stream size;
  - checksum or integrity rule;
  - producer credit window;
  - consumer acknowledgement;
  - slow-consumer policy;
  - durable versus ephemeral stream mode;
  - cursor and replay behavior;
  - stream-open and stream-close ordering;
  - task cancellation interaction;
  - task deadline interaction;
  - terminal event ordering;
  - data-filtering and authorization for every chunk;
  - rate accounting for compressed and decoded bytes.

- **Non-goal:** Do not use a stream to transport unbounded artifacts.

- **Exit condition for a future extension:** A slow consumer cannot make a
  producer or relay retain an unbounded queue, and reconnect behavior is
  demonstrated in tests.

### P-06 — Pub/sub event channels

- **Name:** Broker-mediated topic subscriptions.

- **What it is:** A future protocol for named events where publishers and
  subscribers have independent authorization and event contracts.

- **Current evidence:** Gateway SSE is an authorized task-lifecycle feed. It
  is not a generic topic protocol.

- **Effort:** Large.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 1.3.

- **Recommendation:** Defer to v0.4+ after durable task-event cursor behavior
  is proven. Do not represent an omitted task target as implicit broadcast.

- **Future design requirements:**

  - topic naming grammar;
  - topic ownership;
  - publisher authorization;
  - subscriber authorization;
  - declared event schema and version;
  - subscription identity;
  - expiration;
  - revocation;
  - wildcard restrictions;
  - fan-out quota;
  - rate limits;
  - durable or explicitly ephemeral semantics;
  - acknowledged cursor;
  - replay retention;
  - expired-cursor error;
  - per-recipient filtering;
  - audit behavior.

- **Non-goal:** Do not expose an unbounded wildcard subscription or a
  broker-wide tap.

- **Exit condition for a future extension:** A revoked subscription cannot
  recover data through a previously issued cursor.

### P-07 — Delegated authorization

- **Name:** One-hop attenuating delegated authorization.

- **What it is:** A signed, verified, short-lived authorization context that
  permits an actor to invoke a narrowly defined capability on behalf of a
  subject without carrying raw OAuth or arbitrary policy data in the envelope.

- **Current evidence:** The gateway accepts an opaque delegation identity in
  its authorization context. That is correlation metadata, not a grant format
  or a verifier.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** At most produce an internal v0.3.0 design/vector
  package. Defer all runtime grant support to v0.4+ after dedicated security
  review.

- **Initial scope, if implemented:**

  - one hop only;
  - no delegation chains;
  - one mesh;
  - exact audience;
  - exact or tightly bounded capability;
  - explicit resource constraints;
  - short expiry;
  - stable grant ID;
  - confirmation/key binding;
  - revocation epoch;
  - append-only audit reference.

- **Minimum grant claims:**

  - issuer;
  - subject;
  - actor;
  - audience;
  - mesh;
  - capability constraint;
  - resource constraint;
  - not-before time;
  - expiry;
  - grant ID;
  - confirmation;
  - parent identity only if chains are later introduced;
  - revocation epoch.

- **Executor rule:** The executor intersects the verified grant with its own
  local policy. A valid grant never bypasses target policy.

- **Gateway rule:** The gateway forwards only a minimal verified authorization
  context out of band. It never forwards bearer tokens, DPoP proofs, client
  certificates, or arbitrary caller policy objects.

- **Non-goal:** Do not treat a string delegation identity as authority.

- **Exit condition:** Tests cover expired, revoked, wrong-audience, replayed,
  widened, and resource-scope-violating grants.

### P-08 — Unix-socket compression

- **Name:** Negotiated compression for a future Unix transport binding.

- **What it is:** Completing the already designed v2 independent-record zstd
  mechanism for a real, authenticated Unix transport rather than inventing a
  Unix-only compression dialect.

- **Current evidence:** v2 compression code/design exists. Full secure Unix
  listener/connector service evidence does not.

- **Effort:** Medium.

- **Impact:** Low.

- **Reach:** Low.

- **Priority score:** 0.5.

- **Recommendation:** Do not add a standalone v0.3.0 feature. Canonicalize
  generic v2 compression in P-01, retain v0.1 prohibition, and implement
  only alongside a peer-credential-checked Unix transport.

- **Required properties:**

  - post-ready negotiation only;
  - application-envelope compression only;
  - no compression of handshake, auth, receipt, resume, heartbeat, or
    security records;
  - independent frames;
  - no shared dictionary;
  - no shared decompressor state;
  - declared compressed and uncompressed sizes;
  - expansion-ratio ceiling;
  - output cap;
  - CPU/fuel budget;
  - wire and decoded byte charging.

- **Non-goal:** Do not turn on implicit WebSocket compression or per-message
  compression.

- **Exit condition:** A decompression-bomb test proves rejection before
  unbounded allocation.

### P-09 — Multi-hop routing

- **Name:** Explicit A-to-B-to-C application routing.

- **What it is:** A future routed-delivery feature in which B forwards an
  application task toward C while preserving origin identity and avoiding
  duplicate execution.

- **Current evidence:** Existing brokers and carriers forward within their
  own constrained routes. v2 deliberately pins accepted work to one executor.
  No general hop model is defined.

- **Effort:** Large.

- **Impact:** Low.

- **Reach:** Low.

- **Priority score:** 0.3.

- **Recommendation:** Defer indefinitely beyond v0.4. Use a trusted relay or
  a distinct, explicitly delegated B-to-C task instead.

- **Future design requirements:**

  - hop limit;
  - loop detection;
  - immutable origin identity;
  - acting/delegate identity;
  - per-hop delivery ID;
  - per-hop durable receipt;
  - per-hop outbox;
  - per-hop quota;
  - per-hop fence;
  - forwarder policy;
  - no sender-supplied arbitrary URLs;
  - target policy over origin and delegate;
  - deadline partitioning;
  - privacy and filtering rules;
  - audit chain;
  - no implicit route migration.

- **Non-goal:** Do not recast the DeckAgent carrier as application-level
  multi-hop routing.

- **Exit condition for a future design:** A hop failure cannot cause a sibling
  executor to run the same side effect.

### P-10 — Gateway lifecycle completion

- **Name:** Complete the existing task gateway lifecycle.

- **What it is:** Close the gap between a submit-plus-SSE gateway and a usable
  client-facing task surface by defining and implementing status and
  cancellation behavior consistent with the durable route model.

- **Current evidence:** The gateway implements task submission and SSE events.
  The roadmap/spec material anticipates status and lifecycle behavior beyond
  the minimal current routes.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 3.0.

- **Recommendation:** Defer to a separately scoped v0.4 gateway release with
  a typed SDK client and durable broker adapter. Do not invent status from a
  process-local map.

- **Required behavior:**

  - status response has durable ownership semantics;
  - cancellation is authorized against owner/delegation state;
  - status does not claim terminality before the lifecycle ledger does;
  - cancellation does not bypass executor policy;
  - SSE uses durable event IDs and cursor semantics;
  - expired cursor returns a stable error;
  - slow consumers resume from cursor rather than losing lifecycle data.

- **Non-goal:** Do not treat an HTTP request return as a durable receipt.

- **Exit condition:** Restart/failure tests distinguish stored, accepted,
  running, terminal, expired, and recovery-required states.

### P-11 — Artifact descriptors and transfer boundaries

- **Name:** Bounded artifact descriptor companion profile.

- **What it is:** A future way to refer to large results/artifacts with a
  content hash, size, expiry, authorization, and retrieval policy rather than
  expanding task envelopes or streams without limit.

- **Current evidence:** The base protocol has strict record limits. No
  artifact profile is implemented.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Low.

- **Priority score:** 1.0.

- **Recommendation:** Defer to a v0.4+ companion to streaming. It is not
  necessary for a credible local-first v0.3.0 release.

- **Required elements:**

  - immutable content digest;
  - bounded byte length;
  - media type;
  - expiry;
  - recipient authorization;
  - retrieval transport policy;
  - integrity validation;
  - retention and purge behavior;
  - audit metadata;
  - no credential in descriptor.

- **Non-goal:** Do not place arbitrary URLs or presigned credentials in a
  general task parameter and call that artifact support.

- **Exit condition:** A recipient cannot retrieve an artifact after its
  authorization or expiry is invalidated.

## 8. SDK roadmap

The SDK workstream should make existing semantics easy to use and hard to
misrepresent.

It should not add a new wire capability just to improve an API.

### S-01 — Package namespace, runtime imports, and artifact identity

- **Name:** Package namespace, runtime imports, and artifact identity repair.

- **What it is:** Choose the canonical npm/PyPI naming policy, make all
  imports and generated templates match it, and prove built artifacts run
  outside the source checkout.

- **Current evidence:** Package manifests use the LatticeAG namespace;
  TypeScript source still imports the historical PolyMesh namespace; the built
  CLI fails to resolve the latter. The Python distribution is named
  latticeag-polymesh, while the scaffold writes a different dependency name.

- **Effort:** Small.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 9.0.

- **Recommendation:** Mandatory v0.3.0 release blocker. Resolve before
  publishing, documenting install commands, or calling a demo reproducible.

- **Decision required:**

  - retain the historical npm namespace;
  - move fully to the LatticeAG namespace;
  - publish compatibility shims under an old namespace;
  - rename the Python distribution;
  - retain the Python import module as polymesh;
  - document the relationship between distribution name and import name.

- **Required checks:**

  - no stale source import;
  - no stale README command;
  - no stale generated starter dependency;
  - npm package archive succeeds;
  - tarball installs in a clean temporary project;
  - installed CLI executes;
  - wheel builds;
  - wheel installs in a clean environment;
  - installed Python import and CLI execute;
  - SBOM/provenance names match published artifacts.

- **Non-goal:** Do not hide an unresolved rename behind workspace-only package
  resolution.

- **Exit condition:** A clean environment can install and run the exact
  package name shown in the README.

### S-02 — Cross-language vectors and interoperability gate

- **Name:** Shared protocol fixtures and interoperability gate.

- **What it is:** A small checked-in vector corpus and process-level tests
  that prove the advertised TypeScript/Python profile combinations interoperate.

- **Current evidence:** Both SDKs have substantial parsing/crypto behavior,
  but CI does not run a cross-language suite and Python remains v0.1-oriented.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Mandatory v0.3.0 gate for all advertised profiles.

- **Required matrix:**

  | Client/runtime | Broker/runtime | Profile | Expected status |
  |---|---|---|---|
  | TypeScript | TypeScript | v0.1 local loopback | Supported |
  | Python | TypeScript | v0.1 local loopback | Supported if integration passes |
  | Python | Python | v0.1 local loopback | Supported if broker is documented |
  | TypeScript | TypeScript | v0.2 | Supported only after P-01 freeze |
  | Python | TypeScript | v0.2 | Explicitly unsupported until a native v2 client exists |
  | Any | Any | secure WSS | Supported only where exact carrier requirements are met |

- **Fixture families:**

  - parser acceptance/rejection;
  - canonical JSON;
  - cards;
  - signatures;
  - handshake;
  - task submission;
  - lifecycle ordering;
  - receipt behavior;
  - deadline behavior;
  - cancellation;
  - reconnect behavior;
  - error mapping;
  - profile mismatch;
  - credential redaction.

- **Non-goal:** Do not assert v0.2 Python support because its package version
  changes.

- **Exit condition:** CI runs at least one real TypeScript-to-Python task
  exchange for every documented supported pairing.

### S-03 — TypeScript operational CLI and strict TOML configuration

- **Name:** TypeScript CLI reliability and TOML configuration parity.

- **What it is:** Bring the TypeScript CLI up to a small, predictable
  operational surface modeled on the existing Python SDK configuration rules.

- **Current evidence:** The TypeScript CLI offers basic commands. It lacks a
  typed config reader, documented precedence, stable output modes, structured
  exit categories, and complete TLS/identity plumbing. Python already has a
  strict TOML configuration model.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** High.

- **Priority score:** 3.0.

- **Recommendation:** Ship a deliberately narrow v0.3.0 version after S-01.
  Use TOML only; avoid a second YAML parser unless an actual user requirement
  appears.

- **Required behavior:**

  - explicit config path;
  - project and user config discovery rules;
  - flags override environment;
  - environment overrides config;
  - config overrides built-ins;
  - unknown keys fail;
  - raw token/private-key values in flags or environment fail;
  - file path fields are validated;
  - URL parsing rejects query, fragment, and userinfo;
  - JSON, table, and plain output are deterministic;
  - stable documented exit codes;
  - errors go to stderr;
  - results go to stdout.

- **Recommended command set:**

  - start;
  - connect;
  - call;
  - peers;
  - capabilities;
  - init or a pointer to the generated starter.

- **Non-goal:** Do not add a general plugin command or runtime code loader.

- **Exit condition:** The same command run from config, environment, and
  explicit flags resolves to the documented precedence outcome.

### S-04 — Typed REST/SSE gateway clients

- **Name:** Typed SDK gateway client adapters.

- **What it is:** An optional client surface for gateway task submission and
  durable SSE consumption using cursors, deduplication, and stable error
  handling.

- **Current evidence:** The server-side gateway exists. Neither SDK exposes a
  complete typed gateway client with cursor recovery or cursor-expiration
  behavior.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 3.0.

- **Recommendation:** Defer to the v0.4 gateway release with P-10. It remains
  a better long-running-task API than adding stream records, but should not
  widen the v0.3.0 local-first cut.

- **Required API shape:**

  - submit a validated task request;
  - supply an idempotency key;
  - receive a stable task handle;
  - open an authenticated event iterator;
  - resume with Last-Event-ID or an explicit cursor;
  - deduplicate events by durable event ID;
  - surface cursor expiration distinctly;
  - stop cleanly;
  - never expose raw bearer tokens in logs or events.

- **Required behavior:**

  - typed request/response validation;
  - bounded reconnect;
  - visibility filtering delegated to the gateway;
  - no client-side claim that an HTTP return means executor admission;
  - explicit task/lifecycle result mapping.

- **Non-goal:** Do not embed a full Worker relay client into the SDK.

- **Exit condition:** A test client reconnects after a forced SSE disconnect,
  deduplicates a repeated event, and handles an expired cursor.

### S-05 — Task handles and bounded lifecycle iteration

- **Name:** Task-handle ergonomics and lifecycle iteration.

- **What it is:** Improve SDK ergonomics around existing task events without
  adding new stream wire records.

- **Current evidence:** Python provides TaskHandle-like behavior, progress
  callbacks, and an envelope iterator. TypeScript primarily resolves calls at
  terminal result.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Candidate v0.3.0 API parity work after the release
  blockers. Keep it entirely within current lifecycle semantics.

- **Recommended surface:**

  - task ID;
  - submit message ID;
  - current local observation;
  - last event sequence;
  - receipt observation;
  - progress callback;
  - async event iterator;
  - cancellation request;
  - terminal result;
  - recovery-required outcome.

- **Required safety behavior:**

  - no automatic resend of uncertain work after a new session;
  - terminal completion happens once;
  - conflicting event sequences fail loudly;
  - bounded queue;
  - callback failures are isolated;
  - deadline wins correctly;
  - cancellation/terminal races are deterministic.

- **Non-goal:** Do not label lifecycle iteration as streaming.

- **Exit condition:** SDK examples can show progress and completion through
  this API without changing a protocol record.

### S-06 — Python opt-in mDNS discovery

- **Name:** Python WSS-only mDNS discovery provider.

- **What it is:** An optional discovery provider that emits bounded,
  non-authoritative private-LAN endpoint hints matching the TypeScript security
  posture.

- **Current evidence:** The optional Python mDNS dependency is declared, but
  the actual discovery module is a local cache/static provider and the client
  has no network provider.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Conditional v0.3.0. Ship only if it does not delay the
  release gates. Otherwise retain explicit endpoints and TypeScript discovery
  for the first public demo.

- **Required constraints:**

  - explicit opt-in;
  - WSS only;
  - no plaintext LAN advertisement;
  - minimal TXT data;
  - no card or capability in TXT;
  - no secret in TXT;
  - private-LAN literal addresses only;
  - no automatic connect;
  - no enrollment from discovery;
  - bounded candidates;
  - bounded addresses;
  - rate-limited callbacks;
  - candidate expiry;
  - test doubles for deterministic tests.

- **Non-goal:** Do not implement zero-config trust.

- **Exit condition:** A spoofed or public-address advertisement cannot cause a
  connection or enrollment.

### S-07 — Native Unix transport

- **Name:** Secure Unix-domain transport and registry service.

- **What it is:** A complete Unix listener/connector/registry path with safe
  runtime directories, peer credential verification, leases, and policy
  identity.

- **Current evidence:** Both codebases have framing-related pieces, but a
  complete peer-credential-checked, restart-safe service is not evidenced.

- **Effort:** Large.

- **Impact:** High strategically.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Defer to v0.4+. It is too security-sensitive to use as
  a demo shortcut.

- **Required properties:**

  - verified runtime directory;
  - no unsafe fallback to temporary directories;
  - no symlink path traversal;
  - verified socket ownership;
  - kernel peer credentials;
  - UID principal policy;
  - lease identity;
  - safe cleanup using inode/device comparison;
  - bounded framing;
  - restart behavior;
  - test coverage across supported platforms.

- **Non-goal:** Do not claim Unix peer identity merely from an agent ID.

- **Exit condition:** A same-UID but untrusted claimed agent identity does not
  gain agent-specific authority.

### S-08 — Python secure WSS carrier

- **Name:** Python secure WSS carrier with exact channel binding.

- **What it is:** A carrier that can expose the exact TLS exporter/channel
  binding required by the secure profile, rather than an approximation.

- **Current evidence:** The Python specification intentionally states that
  normal WebSocket stacks may not expose the required exporter. The SDK fails
  closed rather than inventing a substitute.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Defer to v0.4+. Preserve the current fail-closed
  position.

- **Non-goal:** Do not substitute a certificate fingerprint, a TLS unique
  binding, a finished-message hash, or an invented hash for the specified
  binding.

- **Exit condition:** An integration test verifies exact compatibility with a
  trusted reference peer.

### S-09 — TypeScript dynamic plugin system

- **Name:** General dynamic plugin host.

- **What it is:** A runtime mechanism for loading third-party code into the
  TypeScript client/broker process.

- **Current evidence:** No plugin host exists. Existing programmatic handlers,
  policy code, and adapter exports cover explicit integration points.

- **Effort:** Large.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 1.3.

- **Recommendation:** Do not ship as a v0.3.0 feature. Prefer separate
  integration packages, documented handler registration, and process
  isolation.

- **Why:** A generic loader is a supply-chain and arbitrary-code surface. It
  must not be conflated with sandboxed data filtering or authorization policy.

- **Future prerequisites:**

  - trust/install model;
  - package resolution policy;
  - sandbox or process boundary;
  - capability manifest;
  - versioning;
  - permission model;
  - audit;
  - updates/revocation;
  - test isolation.

- **Non-goal:** Do not load JavaScript from an Agent Card, policy field, or
  remote message.

### S-10 — Full native v2 SDK support

- **Name:** Native v2 client implementations.

- **What it is:** A dedicated TypeScript and Python SDK surface that speaks
  the canonical v2 handshake, mesh addresses, durable receipts, replay
  cursors, compression, fences, and gateway semantics.

- **Current evidence:** TypeScript contains v2 code; the general client and
  Python SDK are primarily v0.1 user surfaces. Python package version is not
  v2 wire support.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Do not quietly fold it into v0.3.0. Either make it the
  sole flagship v0.4 release or maintain a clear v0.1-only Python declaration.

- **Non-goal:** Do not add optional v2 fields to v0.1 models.

- **Exit condition:** The SDK advertises a selected v2 profile only after
  canonical vectors and full lifecycle/recovery tests pass.

## 9. Infrastructure and deployment roadmap

The infrastructure work should make the existing local-first product
repeatable before it turns PolyMesh into a hosted service. A release pipeline,
installation smoke tests, and a secure runnable demo have greater adoption
value today than a nominal Workers deployment.

### I-01 — Release CI, package verification, and publication automation

- **Name:** Release CI, package verification, and publication automation.

- **What it is:** Expand the current Node-only GitHub Actions workflow into a
  reproducible release pipeline. It must test both language distributions,
  run TypeScript type checks, build packages, create tarballs and wheels,
  install those artifacts in clean environments, run a minimal interoperability
  test, and publish only after explicit protected release approval.

- **Current evidence:** The repository has one Node 22 workflow which runs
  install, build, and tests. It has no Python test job, no clean wheel/tarball
  install check, no type-check step, no package-publish path, and no cross-SDK
  release gate. The checked-in package namespace changed from at-polymesh to
  at-latticeag while runtime imports remain inconsistent.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Commit to v0.3.0. This is the highest-return
  infrastructure item and is a release blocker, not release polish.

- **Minimum design:** Separate pull-request verification from protected tag
  publication. Pin action revisions, use least-privilege credentials, and
  retain test reports and package metadata as artifacts. Publish from a clean
  checkout rather than a developer laptop.

- **Required jobs:**

  1. Node install using the committed lockfile.
  2. TypeScript type check, build, and unit/integration tests.
  3. Python environment setup from declared project metadata, lint/type check
     if adopted, and the test command documented for users.
  4. Build npm tarballs and Python wheel/source distribution.
  5. Install each artifact into an empty temporary project and run an import
     and CLI smoke test.
  6. Run one TypeScript-to-Python and one Python-to-TypeScript compatible
     profile fixture, once both sides expose the same supported profile.
  7. Scan generated package contents for unintended source maps, credentials,
     local specifications, and ignored development files.

- **Exit condition:** A release candidate cannot be tagged when its published
  artifact name, import name, CLI command, version, or clean-install smoke
  test disagrees with the documentation.

### I-02 — Secure Docker Compose reference demo

- **Name:** Secure Docker Compose reference demo.

- **What it is:** A checked-in, one-command demonstration with a broker,
  caller agent, and executor agent that exchange a real task and report a
  terminal lifecycle event. It is a teaching and CI fixture, not a claim that
  containers are the deployment architecture.

- **Current evidence:** There is no Dockerfile or Compose file. The existing
  local development WebSocket profile intentionally permits plain WebSocket
  only on a numeric loopback address. A normal Compose service hostname is not
  loopback, so copying that profile into a container network would contradict
  the transport policy.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Commit to v0.3.0, provided the demo uses a safe topology
  and becomes a CI smoke test.

- **Required design:** Use one of two explicit modes:

  1. A development-only single network namespace where numeric loopback and a
     runtime token remain meaningful; or
  2. A multi-container topology using WSS with generated development CA,
     server certificate, client certificates, enrollment material, and
     non-production identities.

  The first is simpler but less representative. The second is preferred if it
  can be made short and reliable. Neither mode may commit reusable secrets or
  present plaintext cross-container traffic as secure.

- **Demo acceptance path:**

  1. Build immutable images.
  2. Start the broker and two named demo agents.
  3. Wait for health checks rather than fixed sleeps.
  4. Submit a harmless standard capability.
  5. Observe accepted and completed lifecycle records.
  6. Tear down without retaining task input, runtime credentials, or generated
     private material in the repository.

- **Exit condition:** CI runs the demo from a clean checkout and fails if task
  routing, authentication, lifecycle ordering, or cleanup stops working.

### I-03 — Minimal supported container images

- **Name:** Minimal supported container images.

- **What it is:** Versioned images for the broker and, if appropriate, the
  gateway adapter, with documented architecture, non-root execution, immutable
  dependency installation, health endpoint behavior, and configuration mounts.

- **Current evidence:** No Docker image definition or image-publishing setup
  exists. The gateway is currently a Node HTTP adapter rather than a portable
  Worker runtime.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Include the broker image only if it is needed by the
  Compose demo. Do not create a broad image matrix in v0.3.0.

- **Security requirements:** Run as a non-root user; use multi-stage builds;
  pin base-image digest in CI policy where practical; expose no runtime token
  through image layers or environment dumps; mount credentials read-only; and
  document the persistent volume needed for any durable profile.

- **Non-goal:** Do not market an image as a production remote relay until the
  remote persistence, authentication, audit, and operational requirements have
  an implementation.

- **Exit condition:** The image is built from the release artifact, not
  arbitrary working-tree files, and the Compose test consumes that same image.

### I-04 — Worker-native REST/SSE edge adapter and Wrangler configuration

- **Name:** Worker-native REST/SSE edge adapter and Wrangler configuration.

- **What it is:** A deliberate port of the gateway HTTP semantics to the
  Cloudflare Workers Fetch API, followed by a small Wrangler configuration
  that binds the Worker to the appropriate Durable Objects, secrets, routes,
  environments, and migrations.

- **Current evidence:** The repository has a functional REST/SSE gateway
  package with tests, but it uses Node-specific HTTP, crypto, Buffer, and
  in-memory state patterns. No Wrangler configuration, Worker entry point, or
  Durable Object implementation exists. The in-memory broker is useful for
  tests but cannot be the durable service authority.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Defer to v0.4 or a separately funded hosted-relay
  project. Do not add a Wrangler file to v0.3.0 merely to imply deployability.

- **Correct sequence:**

  1. Extract transport-independent gateway command and event semantics.
  2. Replace Node-only HTTP and stream assumptions with an adapter boundary.
  3. Define the authoritative durable store and transactional boundaries.
  4. Implement Worker request parsing, authentication, bounded SSE writes,
     and operational error mapping.
  5. Implement Durable Object coordination and migrations.
  6. Add Wrangler configuration only once the runtime has concrete bindings.

- **Exit condition:** A deployed staging Worker survives reconnects and
  hibernation without changing idempotency, visibility, cursor, or audit
  semantics.

### I-05 — Authoritative remote durability backplane

- **Name:** Authoritative remote durability backplane.

- **What it is:** The durable relational or equivalent state layer for
  ingress idempotency, route pins, outbox, replay ledger, task lifecycle,
  authorization facts, audit events, retention, and recovery.

- **Current evidence:** The v2 material specifies strong transactional and
  fencing properties. The Worker planning notes describe a relational store
  alongside Durable Objects, but the repository does not contain the remote
  implementation. Durable Object memory and a test in-memory broker are not
  substitutes for the full transactional record set.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Defer beyond v0.3.0 and treat it as the prerequisite for
  any hosted durability or delivery guarantee.

- **Design rule:** Durable Objects coordinate ownership and bounded live
  behavior; the authoritative store owns facts that must survive hibernation,
  failover, auditing, retention, and cross-object recovery.

- **Non-goal:** Do not collapse route selection, audit, replay detection, and
  mailbox retention into best-effort Worker memory because it is convenient.

- **Exit condition:** Crash, retry, duplicate-delivery, expired cursor, and
  stale-fence integration tests pass against the selected production-grade
  store.

### I-06 — SessionDO

- **Name:** SessionDO for connector ownership and fencing.

- **What it is:** A Durable Object keyed to an enrolled connector or physical
  agent instance that serializes live attachment, session replacement,
  credential-epoch checks, session fence allocation, and bounded outbound
  session queues.

- **Current evidence:** v2 requires a durable session fence, and the Workers
  design notes identify SessionDO as a component. No implementation exists.

- **Effort:** Large.

- **Impact:** High.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Design alongside the hosted-relay work, not v0.3.0.

- **Required invariants:** A replaced connection gets a higher fence; an old
  callback cannot close or mutate the replacement; credential rotation
  invalidates old sessions; and session hibernation does not become permission
  to forget replay or route facts.

- **Boundary:** SessionDO must not decide capability authorization or become
  the sole source of task state.

- **Exit condition:** A forced reconnect and Durable Object hibernation test
  demonstrate that stale-channel frames have no effect.

### I-07 — MailboxDO

- **Name:** MailboxDO for mailbox coordination and wakeups.

- **What it is:** A Durable Object that coordinates notification, bounded
  queue wakeups, subscription attachment, and mailbox ownership for a target
  partition while the durable delivery record remains in the authoritative
  store.

- **Current evidence:** The planning material names MailboxDO, but there is no
  implementation. V2 requires pinning, receipts, expiry, and retention that
  are broader than an in-memory queue.

- **Effort:** Large.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 1.3.

- **Recommendation:** Defer with the remote durability backplane. Build only
  after an end-to-end task path needs it.

- **Required behavior:** Enforce mailbox and subscription quotas before
  allocation, preserve a durable cursor, notify reconnecting consumers without
  inventing a terminal outcome, and never silently discard a durable lifecycle
  event because a WebSocket or SSE client is slow.

- **Boundary:** Do not use MailboxDO as a general pub/sub implementation; that
  would conflate task delivery with a later topic-subscription feature.

- **Exit condition:** Offline delivery, slow-consumer disconnect, resume, and
  retention-expiry tests all produce deterministic outcomes.

### I-08 — Broker to Worker connectivity and Cloudflare Tunnel

- **Name:** Broker-to-Worker connectivity and Cloudflare Tunnel policy.

- **What it is:** A constrained connectivity design for an optional local
  connector or origin bridge, including outbound authentication, enrollment,
  routing ownership, health reporting, and failure semantics.

- **Current evidence:** There is no cloudflared configuration or server-side
  tunnel implementation. The TypeScript client contains a DeckAgent carrier
  client-side component, but not a Worker-side tunnel service.

- **Effort:** Large.

- **Impact:** Medium.

- **Reach:** Low.

- **Priority score:** 0.7.

- **Recommendation:** Defer. Do not position Cloudflare Tunnel as the way to
  bypass the relay's enrollment, provenance, route pinning, or authorization
  requirements.

- **Preferred architecture:** A local connector makes an authenticated
  outbound connection to the relay. A tunnel, if used for development or an
  explicit origin bridge, is a transport detail with its own identity and
  restrictions; it is not transparent direct access to an arbitrary local
  broker.

- **Non-goal:** Do not expose a developer laptop broker to the public Internet
  through a convenient tunnel and call it PolyMesh remote deployment.

- **Exit condition:** The design has explicit enrollment and revocation,
  per-connector rate limits, route/fence behavior, and a threat-model review.

### I-09 — Hosting cost, quota, and reliability model

- **Name:** Hosting cost, quota, and reliability model.

- **What it is:** A deployment worksheet and enforceable quotas for a future
  hosted relay: Worker requests and CPU, concurrent connections, Durable
  Object operations/storage/alarms, durable database transactions and backups,
  SSE duration, egress, logs, secrets, monitoring, and any connector/tunnel
  service.

- **Current evidence:** There is no deployment or billing implementation.
  Exact provider prices are deliberately not asserted in this document because
  this assessment did not use web research and pricing changes over time.

- **Effort:** Small.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 4.0.

- **Recommendation:** Add the planning worksheet before hosted beta, but do
  not spend v0.3.0 engineering effort on paid-hosting machinery.

- **Free-tier position:** A free allowance can be suitable for a personal
  smoke test or an intentionally short-lived demo only. It must not promise
  durable retention, multi-tenant isolation, support response, availability,
  backup recovery, or predictable long-lived SSE behavior.

- **Paid-tier position:** Budget for the full stateful system, not just
  request count. Set per-tenant quotas, global admission limits, retention
  windows, spend alerts, load-test ceilings, and a shutdown path before
  inviting external users.

- **Exit condition:** A hosted beta has an approved monthly budget, an
  overload policy, an incident owner, backup/restore test evidence, and
  current provider pricing verified at procurement time.

## 10. Ecosystem and adoption roadmap

Adoption should start with a clear local problem and a proof that two real
agents can solve it. Framework integrations, bots, and promotional material
only help after the installation path is dependable.

### E-01 — Documentation source and honest support matrix

- **Name:** Documentation source and honest support matrix.

- **What it is:** Maintained documentation source that separates released
  behavior, experimental code, planned protocol profiles, and security
  assumptions. It includes installation, quick start, capability authoring,
  transport selection, configuration, troubleshooting, and a
  TypeScript/Python compatibility table. A public site is a separate,
  approval-gated publication target.

- **Current evidence:** The README retains old package commands and test
  counts, and refers to bridge and deployment work more broadly than the
  repository currently implements. There is no documentation site.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Commit the documentation source and support matrix to
  v0.3.0. Publish a public site only after authorization and sanitization
  review.

- **Required pages:** Start here, secure local demo, SDK comparison,
  configuration reference, transport and trust matrix, gateway status,
  protocol version matrix, known limitations, migration notes, and a
  troubleshooting guide for package/import mismatches.

- **Governance constraint:** Do not publish local SPEC files or review files
  governed by AGENTS.md. Any public RFC or technical overview must be a
  separately reviewed and sanitized artifact.

- **Exit condition:** Every command and package name on the site is exercised
  by documentation tests or the Compose demo.

### E-02 — Checked-in quick-start template and generator repair

- **Name:** Checked-in quick-start template and generator repair.

- **What it is:** A minimal project template showing an agent card, one safe
  capability handler, one caller, configuration, tests, and a task exchange.
  The CLI generator should derive from this maintained source rather than
  constructing a drifting example only in code.

- **Current evidence:** Python includes a create-project scaffold command, but
  there is no maintained template directory. Its generated dependency name is
  inconsistent with the current Python distribution naming.

- **Effort:** Medium.

- **Impact:** High.

- **Reach:** High.

- **Priority score:** 4.5.

- **Recommendation:** Commit to v0.3.0. It complements the Compose demo: the
  template teaches application code, while Compose proves the process boundary.

- **Design rule:** Keep the example intentionally boring: a pure echo or
  transform capability, strict input/result schemas, no raw secrets, and no
  privileged shell/filesystem capability. Include one failure case and one
  cancellation or timeout observation only if the current supported profile
  can demonstrate it faithfully.

- **Exit condition:** The generator and the checked-in template generate
  equivalent projects, install the released package artifact, and pass their
  own smoke test.

### E-03 — Hermes Agent integration pilot

- **Name:** Hermes Agent integration pilot.

- **What it is:** A small maintained integration that lets Hermes use a
  PolyMesh client or exposes a narrow PolyMesh capability to Hermes, with
  explicit permissions, input schemas, and observability.

- **Current evidence:** Hermes is named as a target in the project narrative,
  but no integration package, skill, or compatibility test exists.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 2.0.

- **Recommendation:** Make this a conditional v0.3.0 stretch item only after
  package, quick-start, and CI gates are green. It is a useful flagship
  adoption proof, but not a substitute for the underlying release quality.

- **Scope limit:** Start with one bidirectional, low-risk capability flow. Do
  not couple Hermes to unstable v2 extensions, custom generic plugins, remote
  relay behavior, or unsafe privilege escalation.

- **Exit condition:** A compatibility fixture proves task invocation,
  cancellation/error handling, and permission denial without requiring an
  interactive human session.

### E-04 — LangChain and CrewAI adapters

- **Name:** LangChain and CrewAI tool adapters.

- **What it is:** Separate optional adapters that turn allowlisted PolyMesh
  capabilities into framework tools and map framework calls to a stable
  PolyMesh task interface.

- **Current evidence:** No adapter packages or integration tests exist.
  Frameworks evolve independently, and their generic tool abstractions can
  hide cancellation, idempotency, result schema, authorization, and lifecycle
  details that PolyMesh needs to preserve.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** High.

- **Priority score:** 3.0.

- **Recommendation:** Defer to v0.4. Build one adapter first, based on
  developer demand, and keep framework dependencies optional.

- **Design rule:** Generate or declare a tool only for an authorized,
  stable capability contract. Preserve deadline, idempotency key, structured
  errors, and cancellation as far as the framework allows. Never expose a
  catch-all remote invocation tool with arbitrary target/capability/input.

- **Exit condition:** The first adapter passes a no-network integration suite
  against a pinned framework version and has a clear compatibility policy.

### E-05 — Discord experimentation bot

- **Name:** Discord experimentation bot.

- **What it is:** A community sandbox bot that triggers a narrow set of
  demonstration tasks through an isolated broker environment.

- **Current evidence:** No bot, moderation model, tenant isolation, abuse
  controls, credential model, or hosted relay exists.

- **Effort:** Large.

- **Impact:** Low.

- **Reach:** Medium.

- **Priority score:** 0.7.

- **Recommendation:** Defer indefinitely. It is attractive for discovery but
  would force public multi-tenant security, moderation, quota, and incident
  work before the protocol has a stable deployment base.

- **Non-goal:** Do not use a Discord bot as a substitute for a secure gateway
  beta or a developer quick start.

- **Exit condition:** Reconsider only after hosted relay controls, explicit
  tenant isolation, abuse response, and a sustainable moderation owner exist.

### E-06 — Public RFC, whitepaper, and technical narrative

- **Name:** Public RFC, whitepaper, and technical narrative.

- **What it is:** A short, carefully reviewed public explanation of the
  problem PolyMesh solves, its local-first model, the division between agent
  messaging and MCP, threat-model boundaries, and how to experiment safely.

- **Current evidence:** The current detailed protocol material is locally
  governed as confidential. A public document must therefore be independently
  authored and approved rather than copied from existing specifications.

- **Effort:** Medium.

- **Impact:** Medium.

- **Reach:** High.

- **Priority score:** 3.0.

- **Recommendation:** Prepare an outline during v0.3.0, but publish only with
  explicit LatticeAG authorization and legal/security review.

- **Required content:** Problem statement, vocabulary, simple local flow,
  non-goals, security posture, supported-version matrix, and future research
  topics. Avoid unimplemented guarantees, security-sensitive implementation
  detail, proprietary review findings, and claims of universal interoperability.

- **Exit condition:** Governance approval confirms that the material is
  sanitized, accurate, and permitted for public distribution.

### E-07 — Reference adoption evidence

- **Name:** Reference adoption evidence and feedback loop.

- **What it is:** A small set of reproducible examples, issue templates,
  compatibility fixtures, and structured feedback questions that reveal where
  developers actually fail: install, identity setup, discovery, capability
  modeling, or task lifecycle use.

- **Current evidence:** The repository has good unit-test coverage in its
  existing TypeScript suite, but no end-to-end published onboarding artifact or
  user feedback loop.

- **Effort:** Small.

- **Impact:** Medium.

- **Reach:** Medium.

- **Priority score:** 4.0.

- **Recommendation:** Include in v0.3.0 alongside docs and the template.

- **Success signals:** A new user can run the demo without hand-editing source;
  an integrator can identify the selected wire profile; and a report can
  include versions, safe redacted diagnostics, and a minimal reproduction.

- **Exit condition:** At least one feedback channel is documented and every
  example references a maintained compatibility test.

## 11. Ranked roadmap by release area

The following is the decision-oriented roadmap. The score is a prioritization
aid, not a mechanical promise: security prerequisites and dependency order can
override a superficially high score.

| Order | Area | Item | Score | Recommended release | Decision |
|---:|---|---|---:|---|---|
| 1 | SDK | S-01 package namespace and runtime imports | 9.0 | v0.3.0 | Commit |
| 2 | Protocol | P-01 canonical v2 contract and conformance gate | 4.5 | v0.3.0 | Commit |
| 3 | Protocol | P-02 extension governance | 4.5 | v0.3.0 | Commit with P-01 |
| 4 | SDK | S-02 cross-language vectors | 4.5 | v0.3.0 | Commit |
| 5 | Infrastructure | I-01 release CI and package verification | 4.5 | v0.3.0 | Commit |
| 6 | Infrastructure | I-02 secure Compose demo | 4.5 | v0.3.0 | Commit |
| 7 | Ecosystem | E-01 documentation and support matrix | 4.5 | v0.3.0 | Commit |
| 8 | Ecosystem | E-02 template and generator repair | 4.5 | v0.3.0 | Commit |
| 9 | Ecosystem | E-07 reference adoption evidence | 4.0 | v0.3.0 | Commit |
| 10 | Infrastructure | I-09 hosting cost plan | 4.0 | planning now | Document only |
| 11 | Protocol | P-04 MCP bridge | 3.0 | v0.4.0 | Defer |
| 12 | Protocol | P-10 gateway lifecycle completion | 3.0 | v0.4.0 | Pair with durable semantics |
| 13 | SDK | S-03 TypeScript CLI/config parity | 3.0 | v0.3.0 | Commit narrowly |
| 14 | SDK | S-04 typed gateway clients | 3.0 | v0.4.0 | Only with P-10 |
| 15 | Ecosystem | E-04 framework adapter | 3.0 | v0.4.0 | Defer |
| 16 | Ecosystem | E-06 public RFC/whitepaper | 3.0 | conditional | Approval required |
| 17 | Protocol | P-03 generic signing | 2.0 | v0.4.0+ | Design first |
| 18 | Protocol | P-05 true streaming | 2.0 | v0.4.0+ | Defer |
| 19 | Protocol | P-07 delegated authorization | 2.0 | v0.4.0+ | Design first |
| 20 | SDK | S-05 lifecycle iteration | 2.0 | v0.3.0 | Convenience only |
| 21 | SDK | S-06 Python mDNS | 2.0 | v0.3.0 conditional | Choose one stretch item |
| 22 | SDK | S-07 native Unix transport | 2.0 | v0.4.0+ | Defer |
| 23 | SDK | S-08 Python secure WSS carrier | 2.0 | v0.4.0+ | Defer |
| 24 | SDK | S-10 native v2 SDK | 2.0 | v0.4.0+ | Flagship release |
| 25 | Infrastructure | I-03 minimal images | 2.0 | v0.3.0 conditional | Only with Compose |
| 26 | Infrastructure | I-04 Worker adapter | 2.0 | v0.4.0+ | Defer |
| 27 | Infrastructure | I-05 remote durability | 2.0 | v0.4.0+ | Prerequisite |
| 28 | Infrastructure | I-06 SessionDO | 2.0 | v0.4.0+ | With hosted relay |
| 29 | Ecosystem | E-03 Hermes pilot | 2.0 | v0.3.0 conditional | Choose one stretch item |
| 30 | Protocol | P-06 pub/sub | 1.3 | v0.4.0+ | Defer |
| 31 | SDK | S-09 dynamic plugins | 1.3 | indefinite | Do not build |
| 32 | Infrastructure | I-07 MailboxDO | 1.3 | v0.4.0+ | With durability |
| 33 | Protocol | P-11 artifact descriptors | 1.0 | v0.4.0+ | Defer |
| 34 | Infrastructure | I-08 tunnel policy | 0.7 | v0.4.0+ | Do not use as shortcut |
| 35 | Ecosystem | E-05 Discord bot | 0.7 | indefinite | Do not build |
| 36 | Protocol | P-08 Unix-only compression | 0.5 | later | Do not split out |
| 37 | Protocol | P-09 multi-hop routing | 0.3 | v0.5.0+ | Do not start |

### 11.1 Protocol group

The protocol deliverable for v0.3.0 is discipline, not feature breadth:
canonicalize the source of truth, declare extension rules, publish vectors,
and prevent code from advertising unsupported messages. This makes later
signing, delegation, streaming, and subscriptions safer to introduce.

### 11.2 SDK group

The SDK deliverable is dependable installation and a pleasant local path:
consistent package identities, config parity, documented gateway boundaries,
clear lifecycle iteration, and a template that runs against the released
artifact.

### 11.3 Infrastructure group

The infrastructure deliverable is a release gate and runnable demo. It is not
a managed relay. Cloudflare work begins only after gateway semantics have an
authoritative remote persistence design.

### 11.4 Ecosystem group

The ecosystem deliverable is proof rather than surface area: clear docs,
examples, and perhaps one carefully bounded Hermes pilot. Framework adapters
and public bots follow evidence of real usage.

## 12. v0.3.0 release plan

### 12.1 Candidate scope

v0.3.0 should be a trustworthy developer-release rather than a protocol
expansion. The release commits to the following outcomes:

1. A user can install the correctly named TypeScript and Python artifacts.
2. A user can follow a quick start or template to exchange one safe task.
3. CI proves that built artifacts, not just the source tree, work.
4. The documentation states exactly which protocol profiles and deployment
   modes are supported.
5. The protocol has one canonical v2 contract path and vectors that expose
   divergence early.
6. The gateway's present REST/SSE limits are documented without implying a
   hosted relay or a complete typed-client surface.

### 12.2 Must-ship workstreams

| Workstream | Included items | Owner outcome |
|---|---|---|
| Release integrity | I-01, S-01, S-02 | Installable verified artifacts |
| Local developer experience | E-02, I-02, S-05 | A runnable, securely described quick start |
| Protocol clarity | P-01, P-02 | One contract and extension boundary |
| CLI and configuration | S-03 | Predictable local operations |
| Documentation and feedback | E-01, E-07 | Accurate support matrix and reproducible reports |

### 12.3 Conditional lane

Only one conditional item should enter v0.3.0 after all must-ship gates pass:

- **Option A:** S-06 Python mDNS, if it can retain the existing strict
  discovery posture and a clean optional-install path.

- **Option B:** E-03 Hermes pilot, if a real adopter needs it and it can be
  tested without unstable protocol additions.

- **Option C:** I-03 container image hardening, if the Compose demo requires a
  separately distributable broker image.

Do not take more than one without reducing must-ship scope. MCP and gateway
client work remain v0.4 items even if they are popular or score well.

### 12.4 Explicit v0.3.0 exclusions

The release must not claim any of the following:

- generic end-to-end envelope signing;
- delegated authorization grants;
- native v2 support in both SDKs;
- true byte/token streaming;
- remote pub/sub topics;
- automatic multi-hop forwarding;
- a public or production Cloudflare Workers relay;
- a generic dynamic plugin host;
- a public Discord service;
- security equivalence between the local development profile and a remote
  enrolled deployment.

### 12.5 Milestones and dependency order

#### Milestone 0 — Stabilize identity

Resolve npm package names, runtime imports, Python distribution naming,
generated scaffold dependencies, documentation commands, and release version
policy. No feature work should merge while a clean installed CLI cannot load.

#### Milestone 1 — Make quality observable

Add reproducible Node and Python CI jobs, type checks, package artifact
creation, clean-install tests, and the first compatibility vectors. Use this
milestone to state which profile each SDK actually supports.

#### Milestone 2 — Make the local story runnable

Land the maintained template/generator, safe Compose demo, minimal config
parity, and bounded local lifecycle iteration. Keep the demo harmless and
deterministic.

#### Milestone 3 — Make the promise legible

Publish the documentation/support matrix, troubleshoot packaging and local
transport, audit all README claims, and add feedback/reporting guidance.
Create the release candidate only after its examples use the built artifacts.

#### Milestone 4 — Optional adoption proof

Choose one conditional lane. If it causes any release-gate regression, remove
it rather than delaying the core release indefinitely.

## 13. Release gates and acceptance criteria

Every v0.3.0 candidate should meet the following gates before publication.

| Gate | Evidence required | Failure outcome |
|---|---|---|
| Namespace consistency | Package metadata, runtime imports, docs, scaffold, and lockfiles agree | Block release |
| TypeScript quality | Clean install, type check, build, and full test suite | Block release |
| Python reproducibility | Documented isolated-environment test command and package artifact smoke | Block release |
| Artifact install | npm tarball and Python wheel install into empty projects | Block release |
| Interoperability | Selected profile vectors and a minimal cross-SDK exchange where supported | Block release for advertised interoperability |
| Compose security | No committed secret; no insecure cross-container WS presented as secure | Block release |
| Docs accuracy | Commands and versions tested; support matrix matches code | Block release |
| Gateway scope | REST/SSE retention, auth, and cursor limitations documented | Block release for gateway claim |
| Confidential material | No governed local SPEC or review file enters public package/site | Block release |

### 13.1 Suggested measurable release signals

- A fresh environment completes the template quick start in one documented
  sequence.

- The Compose demo produces one accepted and one terminal lifecycle record in
  CI.

- The artifact smoke tests invoke the packaged CLI rather than repository
  source paths.

- Documentation has no obsolete at-polymesh command, stale test count, or
  claim of a deployed Worker relay.

- A profile support table identifies v0.1, v2 draft code, gateway, mDNS, and
  remote transport states as released, experimental, or planned.

- At least one issue report can be reproduced from a safe diagnostic bundle
  without a developer sharing raw credentials or private task data.

## 14. v0.4.0 and later sequencing

The next release should take one hard systems problem at a time. Combining
native v2 SDKs, hosted relay, delegation, generic signing, and streaming would
make failures difficult to attribute and audits difficult to complete.

### 14.1 Recommended v0.4.0 decision

Choose one flagship direction:

1. **Integration direction:** Ship the constrained MCP bridge and one
   framework adapter on top of proven v0.1/local gateway behavior.

2. **Protocol direction:** Ship native selected-v2 support in one SDK with
   vectors, then complete the other SDK in the same release train.

3. **Hosted direction:** Build the Worker-native gateway, authoritative store,
   SessionDO/MailboxDO coordination, and a private hosted-relay beta.

The strongest recommendation is the protocol direction if v2 is meant to be
the long-term protocol. The integration direction is appropriate if real
users are blocked by tool interoperability now. The hosted direction needs
dedicated operational ownership and should not be smuggled into an SDK release.

### 14.2 v0.4.0 candidate ordering

1. P-04 constrained MCP bridge, if a test partner owns the connector setup.
2. S-10 native v2 SDK, with a published support matrix and conformance suite.
3. P-03 generic signing design and external security review.
4. P-07 delegation schema and verifier design, possibly a narrow
   single-hop implementation after review.
5. I-04 through I-07 as one hosted-relay workstream, not scattered files.
6. E-04 one framework adapter, only after stable capability mapping exists.

### 14.3 v0.5.0 and horizon

True streaming, pub/sub, artifact transfer, multi-hop routing, broad native
Unix transport, and any public community bot belong on a later horizon. Each
changes resource ownership, authorization, recovery, or external attack
surface. None should be bundled as a convenience feature.

## 15. What to deprecate, simplify, or refuse

The fastest way to improve PolyMesh is to reduce ambiguous surfaces. The
following decisions prevent the roadmap from expanding around every good idea.

### D-01 — Retire the duplicate v2 delivery identifier representation

- **Name:** Retire the duplicate v2 delivery identifier representation.

- **What it is:** Select the nested delivery identifier shape used by the
  canonical path, provide an explicit compatibility adapter only where
  required, and stop maintaining an optional top-level alternative in active
  protocol models.

- **Effort:** Medium.

- **Impact:** High.

- **Recommendation:** Include in v0.3.0 as part of P-01. Ambiguity in a
  durable identifier is not benign compatibility.

### D-02 — Replace broad README claims with a support matrix

- **Name:** Replace broad README claims with a support matrix.

- **What it is:** Remove stale package names, test totals, and language that
  implies a deployed Cloudflare relay or complete DeckAgent deployment where
  only code or planning exists.

- **Effort:** Small.

- **Impact:** High.

- **Recommendation:** Include in v0.3.0. Honest documentation is cheaper than
  supporting users who adopt an unavailable feature.

### D-03 — Replace generic MCP execution with explicit capability projection

- **Name:** Replace generic MCP execution with explicit capability projection.

- **What it is:** Treat the existing broad standard capability concept as an
  integration convenience to be deprecated in favor of configured,
  allowlisted MCP tool projections with pinned schemas and policy.

- **Effort:** Medium.

- **Impact:** High.

- **Recommendation:** Design in v0.3.0 and implement only when P-04 is ready.
  A generic remote MCP command is a security and compatibility trap.

### D-04 — Do not create a generic dynamic plugin host

- **Name:** Do not create a generic dynamic plugin host.

- **What it is:** Keep SDK extension points explicit and deployment-owned
  rather than loading arbitrary packages with protocol authority.

- **Effort:** Small.

- **Impact:** Medium.

- **Recommendation:** Refuse for the foreseeable roadmap. Use integrations,
  configuration-owned adapters, or a future signed extension registry if a
  demonstrated need persists.

### D-05 — Do not fork compression by transport

- **Name:** Do not fork compression by transport.

- **What it is:** Keep one negotiated compression record/profile across
  transports instead of creating Unix-only semantics.

- **Effort:** Small.

- **Impact:** Medium.

- **Recommendation:** Include as a design decision in v0.3.0. Finish the
  existing generic behavior later only if measured local workloads need it.

### D-06 — Do not call SSE task observation streaming or pub/sub

- **Name:** Preserve task-event terminology.

- **What it is:** Describe current SSE as durable task event observation with
  cursors and visibility checks, not arbitrary output streaming or topic
  subscription.

- **Effort:** Small.

- **Impact:** Medium.

- **Recommendation:** Include in v0.3.0 documentation. Clear
  terminology prevents consumers from assuming replay, credit, fan-out, and
  authorization behavior that has not been implemented.

### D-07 — Preserve no-automatic-reroute semantics

- **Name:** Preserve no-automatic-reroute semantics.

- **What it is:** Keep accepted durable work pinned to its selected executor
  unless a separately specified fenced handoff exists.

- **Effort:** Small.

- **Impact:** High.

- **Recommendation:** Reaffirm in v0.3.0. Multi-hop routing, health changes,
  and reconnect convenience must not become accidental duplicate execution.

### D-08 — Keep public technical material separate from governed specs

- **Name:** Separate public technical material from governed specifications.

- **What it is:** Treat the current local specification corpus as private
  according to repository governance and author public material separately.

- **Effort:** Small.

- **Impact:** High.

- **Recommendation:** Include as a release-process requirement. It is both a
  governance obligation and a way to make public docs clearer and shorter.

## 16. Final recommendation

Ship v0.3.0 when PolyMesh can be installed, understood, and exercised
reliably by a new developer in a local-first setting. The valuable work is
release integrity, a correct package story, a maintained quick start,
cross-language contract discipline, and honest documentation.

Do not trade that outcome for a visually impressive but unproven hosted relay,
generic plugins, a Discord bot, multi-hop routing, or a broad new protocol
surface. Those ideas can be valuable later. Today they would obscure the more
important answer to the question every potential adopter asks first:

> Can I use this safely, reproduce the result, and know exactly what is
> supported?

v0.3.0 should make the answer yes for the local-first core, and no ambiguity
for everything else.
