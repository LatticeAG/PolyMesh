# PolyMesh v0.4.0 — Native v2 SDK Specification

> Internal implementation and release specification for an authorized
> LatticeAG PolyMesh checkout.
>
> Status: proposed v0.4.0 release contract.
>
> This document selects one existing protocol direction and defines the work
> needed to make it a supported product surface.
>
> It is not approved for public distribution.
>
> Repository governance in `AGENTS.md` applies to this document and to the
> confidential protocol material from which implementation requirements are
> derived.

## 1. Decision record

### 1.1 Selected direction

PolyMesh v0.4.0 SHALL ship native support for one canonical
`polymesh.0.2` profile in both the TypeScript and Python SDKs.

The release is called the **native v2 SDK release**.

Its product promise is:

> An application using either supported SDK can explicitly select the same
> canonical v2 profile, establish the v2 handshake, validate mesh-scoped
> records, exchange the bounded task lifecycle, and participate in the
> documented receipt, resume, and optional compression semantics.

The package release version is `0.4.0`.

The selected wire profile remains `polymesh.0.2`.

The package version MUST NOT be used as a wire-profile selector.

### 1.2 Direction score

The decision uses the v0.3 planning formula:

```text
priority = (impact × reach) / effort
```

Each dimension uses the coarse scale one through three.

| Direction | Impact | Reach | Effort | Score | v0.4.0 decision |
|---|---:|---:|---:|---:|---|
| Native v2 SDKs | 3 | 3 | 3 | 3.0 | **Ship** |
| MCP bridge plus framework adapter | 3 | 2 | 3 | 2.0 | Defer |
| Cloudflare Workers hosted relay | 3 | 2 | 3 | 2.0 | Defer |

Reach is scored from the current supported product surface and supplied
roadmap, not from unprovided user telemetry.

### 1.3 Why the protocol direction wins

The current README explicitly says native v2 SDK clients are not a release
promise.

It also identifies the Python SDK as a v0.1 surface.

The TypeScript broker already exposes substantial v2 declarations:

- selected v2 protocol, handshake, and card constants;
- mesh-scoped addresses;
- v2 application envelopes;
- v2 card and control-record schemas;
- durable receipts and resume records;
- routing, health, durable-store, rate-limit, and compression primitives.

Those declarations are in:

- `packages/broker/src/protocol.ts`;
- `packages/broker/src/routing.ts`;
- `packages/broker/src/durable-store.ts`;
- `packages/broker/src/rate-limit.ts`;
- `packages/broker/src/compression.ts`.

The TypeScript client remains a v0.1 session client.

Its currently active handshake constructs a `v: "0.1"` initiator hello.

The Python models and client likewise define:

- `PROTOCOL_VERSION = "polymesh.0.1"`;
- `HANDSHAKE_VERSION = "0.1"`;
- `CARD_VERSION = "1.0"`.

The Python broker explicitly states that it does not claim v0.2 behavior.

Therefore the most direct core-product gap is not more protocol design.

It is making the already selected v2 model usable from both SDKs.

### 1.4 Why integration is not the selected direction

The checkout contains no MCP bridge package.

It contains no LangChain adapter package.

It contains no CrewAI adapter package.

It contains no framework-specific test suite or pinned framework dependency.

The v0.3 roadmap correctly treats an MCP bridge as a constrained,
configuration-owned capability projection.

Such a bridge would need:

- per-server operator configuration;
- per-tool allowlists;
- pinned input and result schemas;
- policy evaluation;
- bounded execution;
- secret handling;
- cancellation mapping;
- process or network containment;
- adapter compatibility testing.

That is a separately valuable integration release.

It is not a thin wrapper that should be combined with the v2 convergence
work.

### 1.5 Why hosted relay is not the selected direction

The gateway package is a Node HTTP implementation.

It imports Node `http`, `crypto`, `Buffer`, and Node stream-adjacent
types.

Its broker boundary states that durable ingress, idempotency, routing, outbox,
and audit facts must be committed atomically by the underlying adapter.

The checkout has no:

- Worker entry point;
- Wrangler configuration;
- Durable Object implementation;
- SessionDO implementation;
- MailboxDO implementation;
- authoritative hosted durability backplane;
- tunnel service implementation.

The current REST/SSE gateway remains useful as a Node reference adapter.

It is not evidence of a deployed hosted relay.

Moving it to Workers would be a large infrastructure program whose durable
ownership rules must be designed before a deployment configuration exists.

### 1.6 Decision constraints

The protocol decision is deliberately narrow.

v0.4.0 MUST converge the existing divergent v2 paths before it declares
native SDK support.

v0.4.0 MUST NOT create a third v2 wire dialect.

v0.4.0 MUST NOT silently make v0.1 fields optional v2 fields.

v0.4.0 MUST NOT claim hosted deployment merely because v2 SDKs can speak to a
broker.

v0.4.0 MUST NOT use an adapter, gateway, or carrier as a reason to weaken
profile selection.

## 2. Conformance language and document scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **MAY**, and **OPTIONAL** in this document are
normative.

An **implementation** is a TypeScript package, Python package, broker path,
gateway adapter change, or test harness that claims a v0.4.0 capability.

A **peer** is one endpoint of a selected PolyMesh session.

An **initiator** sends the first v2 `hello`.

A **responder** accepts that `hello` and emits the responder `hello`.

A **canonical v2 session** is a session that:

1. selected `polymesh.0.2` before accepting a protocol record;
2. uses the canonical nested-delivery application envelope;
3. uses the full v2 hello, auth, card, and ready records;
4. binds all remote addresses to one authenticated mesh;
5. rejects legacy v2 shapes rather than translating them on the wire.

A **legacy v2 shape** is a record representation from
`packages/broker/src/v2.ts` that differs from the canonical declarations in
`packages/broker/src/protocol.ts`.

The most important legacy difference is a top-level `delivery_id`.

The canonical shape puts `delivery_id` inside `delivery`.

A **base v2 record** is a canonical v2 application or control record that
does not require an optional extension.

An **extension** is an explicitly advertised and later selected bounded
feature.

The only extension in this release is `compression/zstd`.

Advertising an extension is not selecting it.

Selecting an extension does not extend the base envelope grammar.

## 3. Evidence baseline

### 3.1 Repository state used for this specification

This specification is grounded in the checkout state observed while preparing
it.

| Area | Observed state | Consequence for v0.4.0 |
|---|---|---|
| Root release version | Root `package.json` is at `0.3.0`. | All shipped artifacts move together to `0.4.0`. |
| TypeScript broker | Contains both canonical v2 declarations and older v2 runtime helpers. | Canonical convergence is a release blocker. |
| TypeScript client | Is a v0.1 client session implementation. | Add an explicit v2 client family rather than mutating the v0.1 default. |
| Python SDK | Is a v0.1 model, protocol, transport, and client surface. | Add a separate `polymesh.v2` namespace. |
| Gateway | Emits a v2-like REST task envelope but has independent validation shapes. | Align its v2 builder to the canonical schema without expanding gateway scope. |
| Shared vectors | Existing cross-language vectors declare `polymesh.0.1` only. | Preserve them byte-for-byte and add a separate v2 corpus. |
| Release workflows | Release workflow builds artifacts, runs both suites, and invokes shared vector verification. | Add native-v2 artifact and process interop gates. |
| Hosted artifacts | No Worker, Wrangler, Durable Object, or tunnel implementation exists. | Hosted relay remains deferred. |

### 3.2 Current validation observation

The following commands completed successfully in this checkout during
planning:

```text
npm test
pytest -q
```

The TypeScript suite reported:

- 32 test files passed;
- 171 tests passed.

The Python suite reported:

- 69 tests passed.

These observed totals supersede older documentation totals for this planning
document only.

The v0.4.0 release gate MUST avoid depending on a test count alone.

It MUST instead require the relevant positive and negative suites to pass.

### 3.3 Canonical-versus-legacy v2 evidence

`packages/broker/src/protocol.ts` declares the canonical v2 profile:

- `V2_PROTOCOL_VERSION = "polymesh.0.2"`;
- `V2_HANDSHAKE_VERSION = "0.2"`;
- `V2_CARD_VERSION = "2.0"`;
- a canonical `msh_` mesh identifier grammar;
- `V2ApplicationEnvelope`;
- nested `delivery.delivery_id`;
- v2 hello/auth/card/ready structures;
- v2 receipt and resume structures;
- Draft 2020-12 schemas.

`packages/broker/src/v2.ts` contains an older implementation path.

That path has:

- an optional top-level `delivery_id`;
- a simpler hello shape;
- a legacy session-ID derivation without the canonical channel-binding input;
- older compression records.

`packages/broker/src/index.ts` already labels the former path as legacy in
comments and exposes deliberate legacy aliases.

`packages/broker/src/broker.ts` still imports the older v2 path for live
broker processing.

This is the central implementation risk of the release.

### 3.4 Source-of-truth rule

For v0.4.0, the normative TypeScript source of truth SHALL be:

```text
packages/broker/src/protocol.ts
```

For compression record definitions and state transitions, the normative
TypeScript source of truth SHALL be:

```text
packages/broker/src/compression.ts
```

`packages/broker/src/v2.ts` SHALL be treated as a compatibility-only legacy
module.

It SHALL NOT define what a v0.4.0 canonical session sends or accepts.

The Python v2 implementation SHALL conform to the canonical TypeScript
schemas and cross-language vectors.

It SHALL NOT implement the older `v2.ts` shape as a second accepted wire
profile.

### 3.5 Release ownership boundary

The broker owns:

- profile selection;
- authenticated session admission;
- mesh binding;
- durable ingress;
- route selection;
- route pinning;
- outbox state;
- receipt settlement;
- replay and fence checks;
- rate limits.

An SDK owns:

- explicit profile selection;
- local record construction;
- handshake state;
- local card and capability validation;
- receipt and replay observation;
- local task-handle behavior;
- safe reconnection behavior;
- application handler admission where it is an executor.

The SDK MUST NOT manufacture broker-owned durable facts.

The broker MUST NOT infer executor admission from a client socket write.

## 4. v0.4.0 release scope

### 4.1 Must-ship outcomes

v0.4.0 MUST ship all of the following:

1. One canonical `polymesh.0.2` profile selection path.

2. A canonical broker v2 path using the declarations in
   `packages/broker/src/protocol.ts`.

3. An explicit TypeScript v2 client family.

4. An explicit Python `polymesh.v2` SDK family.

5. Canonical v2 mesh, card, envelope, receipt, resume, and compression
   validation in both languages.

6. A full v2 hello/auth/card/ready session state machine in both languages.

7. Positive and negative cross-language v2 vectors.

8. Real TypeScript-to-Python and Python-to-TypeScript v2 interoperability
   tests.

9. Artifact-install tests that execute the v2 public APIs from packed
   artifacts.

10. Documentation that distinguishes v2 core support from the deferred
    integration and hosted programs.

### 4.2 Explicitly supported v2 release profiles

The released profile matrix is intentionally smaller than the vocabulary
reserved by the canonical v2 types.

| v2 transport profile | TypeScript SDK | Python SDK | v0.4.0 status |
|---|---|---|---|
| `enrolled-wss/1` through an exporter-capable secure transport | Required | Required through an exporter-capable adapter | Core supported profile |
| Deterministic injected test transport with a fixed authenticated binding | Required | Required | Conformance-only test fixture |
| Numeric-loopback development transport | May be implemented only with an explicit profile-specific authenticated binding | May be implemented only with the same binding rules | Not a remote security claim |
| `local-unix/1` production transport service | Not required | Not required | Deferred |
| `remote-relay/1` | Not required | Not required | Deferred with hosted relay |
| `deckagent-carrier/1` as a native v2 SDK path | Not required | Not required | Existing TS component remains experimental |

The Python default WebSocket adapter MUST NOT claim
`enrolled-wss/1` unless it exposes the exact required channel-binding value.

If it cannot expose that value, it MUST fail closed with a stable
unsupported-carrier error.

An injected or separately implemented adapter MAY support the profile only
after it passes the same v2 vectors and handshake tests.

### 4.3 In-scope convergence for the Node gateway

The Node gateway package remains an experimental adapter.

It remains limited to its existing task submission and task-event observation
scope.

Within that limit, v0.4.0 MUST:

- validate gateway-generated v2 envelopes against the canonical v2 schema;
- use the canonical mesh grammar;
- use nested `delivery.delivery_id`;
- use canonical `task.submit.params.capability` and `input` names;
- not accept the older `method` / `params` v0.1 task shape as a v2
  gateway request;
- preserve sanitized, non-secret gateway authorization context.

v0.4.0 MUST NOT add:

- a Worker handler;
- additional gateway routes;
- public tenancy;
- a delegation verifier;
- generic streaming;
- generic pub/sub.

### 4.4 Explicit exclusions

The following are not v0.4.0 deliverables:

- MCP bridge implementation;
- generic MCP execution capability;
- LangChain adapter;
- CrewAI adapter;
- generic dynamic plugin host;
- delegated authorization grants;
- origin-envelope signing extension;
- continuous token or chunk streaming;
- pub/sub topics;
- artifact transfer;
- multi-hop application routing;
- native Unix listener and peer-credential service;
- hosted Cloudflare Worker relay;
- SessionDO;
- MailboxDO;
- authoritative hosted backplane;
- Cloudflare Tunnel rollout;
- public disclosure of governed specifications.

## 5. Version and profile model

### 5.1 Independent version axes

v0.4.0 has three independent version axes.

| Axis | v0.4.0 value | Meaning |
|---|---|---|
| Package release | `0.4.0` | Published SDK and broker artifact version. |
| Wire protocol | `polymesh.0.2` | Selected v2 application-envelope profile. |
| Handshake version | `0.2` | Version on v2 control records. |
| Card version | `2.0` | Version of the signed mesh-scoped v2 Agent Card. |
| Compression extension epoch | `1` | Epoch used after the compression extension is actively selected. |

No component MAY infer one axis from another.

For example:

- installing package `0.4.0` does not select v2;
- seeing a `mesh_id` does not select v2;
- receiving a gateway URL does not select v2;
- advertising `compression/zstd` does not select compression;
- a v2 card does not authorize an unselected v2 session.

### 5.2 Selected profile tuple

The canonical selected profile tuple is:

```json
{
  "protocol": "polymesh.0.2",
  "handshake_version": "0.2",
  "card_version": "2.0"
}
```

An implementation SHALL expose this tuple as immutable public metadata.

The TypeScript broker already models this as
`PROTOCOL_PROFILE_SELECTIONS.v0_2`.

The Python v2 package SHALL expose the same values without changing the v0.1
constants in `polymesh.types`.

### 5.3 Selection before parsing

For direct WebSocket sessions, the initiator SHALL offer exactly one chosen
PolyMesh subprotocol.

For canonical v2, it is:

```text
Sec-WebSocket-Protocol: polymesh.0.2
```

The responder SHALL either:

1. select `polymesh.0.2`; or
2. reject the upgrade or close before application processing.

The responder MUST NOT select `polymesh.0.1` after a v2 offer fails.

The initiator MUST NOT retry the same application operation as v0.1 merely
because a v2 handshake failed.

Any fallback is a separate application decision using an explicit retry policy
and a fresh, correctly scoped v0.1 operation.

### 5.4 Session immutability

Once a session selects `polymesh.0.2`:

- its first PolyMesh record MUST be a canonical v2 initiator `hello`;
- all following handshake records MUST use `v: "0.2"`;
- all application envelopes MUST use `protocol: "polymesh.0.2"`;
- v0.1 `hello`, `card`, `auth`, `ready`, `receipt`, `ping`, and
  application envelope shapes MUST be rejected;
- legacy v2 top-level `delivery_id` records MUST be rejected;
- a profile mismatch MUST terminate the session;
- the session MUST NOT downgrade in place.

Once a session selects `polymesh.0.1`, it retains the inverse boundary.

It MUST NOT accept a mesh-scoped v2 envelope or v2 control record.

### 5.5 API selection policy

The v0.1 and v2 SDK APIs SHALL be distinct.

An application cannot select v2 by placing optional fields into a v0.1
`PolyMeshClient` constructor.

An application cannot select v1 by omitting fields from a v2 constructor.

The selected profile SHALL be explicit in:

- the client class or namespace;
- endpoint configuration;
- transport adapter capability declaration;
- public diagnostics;
- test fixture metadata;
- documentation examples.

### 5.6 Legacy migration policy

`packages/broker/src/v2.ts` remains importable in v0.4.0 for source
compatibility.

Its exported types and helper aliases SHALL be documented as legacy.

They SHALL NOT be used by:

- the canonical broker session state machine;
- the new TypeScript v2 client;
- the Python v2 implementation;
- new v2 vectors;
- gateway canonical envelope construction;
- v0.4.0 interoperability tests.

The legacy module MAY be removed only in a separately announced future major
or pre-1.0 breaking release.

v0.4.0 MUST NOT silently translate a legacy record into a canonical record
after it crosses a transport boundary.

If migration tooling is later necessary, it SHALL be an explicit offline or
application-owned adapter.

It SHALL NOT create a wire-level permissive parser.

## 6. Canonical data model

### 6.1 General parsing rules

Every v2 record is one complete UTF-8 JSON object.

An implementation MUST apply structural limits before constructing a typed
record.

The existing v0.1 parser already demonstrates the required baseline:

- frame byte limit;
- UTF-8 validation;
- duplicate-member rejection;
- non-finite number rejection;
- Unicode scalar validation;
- JSON depth limit;
- JSON node limit;
- object-member limit;
- array-item limit;
- string-byte limit;
- closed-object validation.

v0.4.0 SHALL apply the same strict parsing posture to all v2 records in both
languages.

The TypeScript implementation SHALL reuse or extend the strict parser in
`packages/broker/src/protocol.ts`.

The Python implementation SHALL reuse the safety properties of
`polymesh.protocol.parse_strict_json` without making the v0.1 model classes
accept v2 records.

JSON Schema validation alone is insufficient.

Session phase, authenticated mesh binding, receipt state, route fence, and
resource limits are semantic checks outside a JSON Schema document.

### 6.2 Canonical JSON

All v2 digest inputs SHALL use RFC 8785-style canonical JSON.

The canonicalization rules are:

1. Parse exactly one strict JSON value.

2. Reject duplicate members before canonicalization.

3. Reject non-finite numeric values.

4. Reject invalid Unicode scalar sequences.

5. Reject values beyond structural resource limits.

6. Sort object member names according to the existing canonical JSON helper.

7. Encode without insignificant whitespace.

8. Preserve arrays in wire order.

9. Never canonicalize an unvalidated raw byte string by reparsing permissively.

The TypeScript reference helper is `canonicalize`.

The Python reference helper is `canonical_json`.

v0.4.0 SHALL add v2 vectors that prove both implementations produce the same
canonical bytes for:

- a v2 card;
- a v2 initiator hello;
- a v2 responder hello;
- a v2 auth record;
- a v2 ready record;
- a v2 application envelope;
- a v2 delivery receipt;
- a v2 compression proposal;
- a v2 compressed wrapper metadata record.

### 6.3 Identifier grammar

The following canonical grammar applies to v2.

| Identifier | Canonical form | Notes |
|---|---|---|
| `mesh_id` | `msh_` plus 26 upper-case Crockford Base32 characters | Administrative routing scope. |
| `agent_id` | Lower-case dotted identifier accepted by the v2 validator | Logical agent identity inside a mesh. |
| `instance_id` | 22 unpadded base64url characters encoding 16 bytes | One running agent instance. |
| `sid` | 43 unpadded base64url characters encoding 32 bytes | Session correlation, not a credential. |
| `message_id` | Lower-case UUIDv7 | One transmitted application record. |
| `delivery_id` | Lower-case UUIDv7 | One durable delivery correlation. |
| `task_id` | Lower-case UUIDv7 | One logical task. |
| `proposal_id` | Lower-case UUIDv7 | One compression negotiation proposal. |
| digest | 43 unpadded base64url characters encoding 32 bytes | SHA-256 output on the v2 wire. |
| fence/cursor | Canonical decimal unsigned-64 string | Never a JavaScript number on the wire. |

The v2 mesh grammar SHALL be:

```text
^msh_[0-9A-HJKMNP-TV-Z]{26}$
```

The canonical mesh grammar in this document is intentionally stricter than
the broader historical mesh regex used by the legacy `v2.ts` and gateway
paths.

A canonical v2 session MUST reject a mesh identifier that passes only the
legacy grammar.

### 6.4 Timestamp grammar

Every v2 timestamp SHALL be RFC 3339 UTC with exactly milliseconds.

The canonical syntax is:

```text
YYYY-MM-DDTHH:MM:SS.mmmZ
```

A timestamp is diagnostic and causal metadata.

It is not a substitute for:

- a monotonic deadline calculation;
- a durable event sequence;
- a route fence;
- a session fence;
- an authorization epoch;
- a replay cursor.

The authenticated receiver's trusted clock and stored deadline facts govern
admission and expiry.

### 6.5 Digest functions

The v2 wire uses base64url-encoded SHA-256 digests.

The following domain-separated functions are required:

```text
record_digest =
  base64url(SHA-256(
    UTF8("PMX-RECORD/0.2\0") ||
    UTF8(JCS(normalized_complete_record))
  ))

semantic_digest =
  base64url(SHA-256(
    UTF8("PMX-SEMANTIC/0.2\0") ||
    UTF8(JCS(immutable_semantic_projection))
  ))

card_digest =
  base64url(SHA-256(
    UTF8("PMX-CARD-DIGEST/0.2\0") ||
    UTF8(JCS(full_signed_card))
  ))

handshake_transcript_hash =
  base64url(SHA-256(
    UTF8("PMX-HANDSHAKE/0.2\0") ||
    UTF8(JCS(initiator_hello)) ||
    UTF8(JCS(responder_hello)) ||
    channel_binding_bytes
  ))

auth_digest =
  base64url(SHA-256(
    UTF8("PMX-AUTH-PAIR/0.2\0") ||
    UTF8(JCS(initiator_auth)) ||
    UTF8(JCS(responder_auth))
  ))
```

The current canonical TypeScript declarations already reserve:

- `V2_CARD_DIGEST_DOMAIN`;
- `V2_SEMANTIC_DIGEST_DOMAIN`;
- `V2_HANDSHAKE_TRANSCRIPT_DOMAIN`;
- `V2_AUTH_PAIR_DOMAIN`;
- `V2_SID_DOMAIN`.

v0.4.0 MUST implement and test the corresponding v2 helper functions.

The previous v0.1 hex digests and v0.1 digest domains MUST remain unchanged.

### 6.6 Normalized complete record

For `record_digest`, a normalized complete record is the fully validated,
canonical v2 application envelope exactly as received after:

- strict parsing;
- session mesh validation;
- authenticated source/target binding;
- application-schema validation;
- any successful decompression;
- rejection of unknown fields.

The normalized complete record includes:

- `message_id`;
- `timestamp`;
- `source`;
- `target`;
- full `delivery`, including `delivery_id`;
- `in_reply_to`, when present;
- exact type-specific `params`.

It excludes:

- outer WebSocket framing;
- HTTP headers;
- TLS details;
- raw authentication credentials;
- broker process-local socket handles;
- a compression wrapper;
- transient dispatch attempt counters;
- a sender-supplied route hint;
- any field not accepted by the closed schema.

### 6.7 Immutable semantic projection

For `semantic_digest`, the projection includes the fields that determine
logical idempotency.

For a `task.submit`, it includes:

- protocol;
- application type;
- source logical address;
- target logical address, including an explicitly requested instance;
- delivery mode;
- idempotency key;
- deadline;
- task ID;
- capability;
- capability version;
- capability contract digest;
- exact task input.

It excludes:

- message ID;
- delivery ID;
- timestamp;
- `in_reply_to`;
- receipt state;
- outbox attempt count;
- compression wrapper;
- connection SID;
- route record identifier;
- routing or session fence;
- socket, carrier, or HTTP metadata.

For lifecycle records, the projection includes:

- task ID;
- event sequence;
- capability tuple where required;
- state/progress/terminal content;
- causal relationship required by the type.

An implementation MUST NOT treat two messages with the same idempotency key
but different semantic projections as a retry.

It MUST record and surface an idempotency conflict.

### 6.8 V2 common JSON Schema fragment

The following fragment is the normative shape of the core reusable values.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/v2/common.json",
  "$defs": {
    "UuidV7": {
      "type": "string",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    },
    "Digest": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{43}$"
    },
    "MeshId": {
      "type": "string",
      "pattern": "^msh_[0-9A-HJKMNP-TV-Z]{26}$"
    },
    "InstanceId": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{22}$"
    },
    "DateTimeMs": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    },
    "UInt64": {
      "type": "string",
      "pattern": "^(0|[1-9][0-9]{0,19})$"
    },
    "IdempotencyKey": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "pattern": "^[A-Za-z0-9._~:-]+$"
    }
  }
}
```

Schema acceptance is necessary but not sufficient.

A `UInt64` string that exceeds a particular durable-store implementation's
safe storage bound MUST be rejected before that implementation writes it.

### 6.9 Mesh-scoped address model

The canonical v2 source address is:

```json
{
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "agent_id": "org.example.owner",
  "instance_id": "AAAAAAAAAAAAAAAAAAAAAA"
}
```

The canonical v2 target address is:

```json
{
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "agent_id": "org.example.executor"
}
```

An exact target instance is optional:

```json
{
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "agent_id": "org.example.executor",
  "instance_id": "EBESExQVFhcYGRobHB0eHw"
}
```

For every remote canonical session:

1. both source and target MUST serialize `mesh_id`;

2. both serialized mesh IDs MUST equal each other;

3. both serialized mesh IDs MUST equal the authenticated session mesh;

4. the source identity MUST match the authenticated principal and card;

5. the target MUST name an agent, not a URL, relay, route, or wildcard.

The paired omission of both mesh IDs is reserved only for a separately
selected authenticated local profile.

That local profile is not a way to accept a partially mesh-scoped remote
envelope.

### 6.10 V2 Agent Card

A canonical v2 Agent Card is mesh-scoped and signed.

Its required members are:

```text
card_version
mesh_id
agent_id
instance_id
issued_at
expires_at
revision
identity
capabilities
signature
```

Its optional members are:

```text
display_name
endpoints
limits
metadata
```

The card version MUST equal `"2.0"`.

The card mesh, agent, and instance identity MUST match:

- the authenticated hello;
- the authenticated `auth` record;
- the established session mesh;
- the enclosing card record.

A peer MUST verify the card signature before using:

- a capability;
- a capability schema;
- an endpoint;
- a claimed limit;
- metadata;
- a key identifier.

A card signature never creates enrollment.

A card signature never replaces transport authentication.

A card signature never grants the card holder capability access.

### 6.11 V2 capability contract

Each v2 capability SHALL contain:

```text
id
version
contract_digest
input_schema
result_schema
idempotency
side_effects
approval
cancellation
timeout_ceiling_seconds
```

The `contract_digest` SHALL cover the canonical capability contract:

- ID;
- semantic version;
- input schema;
- result schema;
- idempotency classification;
- side-effect classification;
- approval requirement;
- cancellation semantics;
- timeout ceiling.

A task owner pins the exact tuple:

```json
{
  "capability": "org.example.echo",
  "capability_version": "1.0.0",
  "capability_contract_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

An executor MUST compare that tuple to the authenticated current card before
admission.

An executor MUST validate task input against the pinned input schema before
admission.

An owner MUST validate a successful terminal result against the pinned result
schema before it presents it as a successful task result.

### 6.12 Card schema fragment

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/v2/card.json",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "card_version",
    "mesh_id",
    "agent_id",
    "instance_id",
    "issued_at",
    "expires_at",
    "revision",
    "identity",
    "capabilities",
    "signature"
  ],
  "properties": {
    "card_version": { "const": "2.0" },
    "mesh_id": { "$ref": "common.json#/$defs/MeshId" },
    "agent_id": { "type": "string", "minLength": 1, "maxLength": 128 },
    "instance_id": { "$ref": "common.json#/$defs/InstanceId" },
    "issued_at": { "$ref": "common.json#/$defs/DateTimeMs" },
    "expires_at": { "$ref": "common.json#/$defs/DateTimeMs" },
    "revision": { "type": "integer", "minimum": 1 },
    "identity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "key_id", "public_key"],
      "properties": {
        "alg": { "const": "Ed25519" },
        "key_id": { "$ref": "common.json#/$defs/Digest" },
        "public_key": { "$ref": "common.json#/$defs/Digest" }
      }
    },
    "signature": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{86}$"
    }
  }
}
```

The TypeScript implementation SHALL publish this schema under the existing
v2 schema identifier.

The Python v2 package SHALL package an equivalent checked-in JSON Schema
artifact.

### 6.13 Card signing

The card signature uses Ed25519.

The signing payload is:

```text
UTF8("PMX-CARD/0.2\0") ||
UTF8(JCS(card_without_signature))
```

The `identity.public_key` is the canonical unpadded base64url encoding of a
32-byte Ed25519 public key.

The `identity.key_id` is the canonical base64url SHA-256 identifier of the
raw public key.

The signature is the canonical base64url encoding of the 64-byte Ed25519
signature.

The v0.1 `PMX-CARD/0.1` signing domain MUST remain untouched.

## 7. Canonical v2 application envelope

### 7.1 Envelope shape

Every v2 application record has this closed top-level shape:

```text
protocol
type
message_id
timestamp
source
target
delivery
in_reply_to (optional)
params
```

No other top-level member is permitted.

The canonical envelope schema is:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/v2/envelope.json",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "protocol",
    "type",
    "message_id",
    "timestamp",
    "source",
    "target",
    "delivery",
    "params"
  ],
  "properties": {
    "protocol": { "const": "polymesh.0.2" },
    "type": {
      "enum": [
        "task.submit",
        "task.accepted",
        "task.rejected",
        "task.progress",
        "task.completed",
        "task.cancel",
        "task.status",
        "error"
      ]
    },
    "message_id": { "$ref": "common.json#/$defs/UuidV7" },
    "timestamp": { "$ref": "common.json#/$defs/DateTimeMs" },
    "source": { "$ref": "remote-addresses.json#/$defs/RemoteSourceAddress" },
    "target": { "$ref": "remote-addresses.json#/$defs/RemoteTargetAddress" },
    "delivery": {
      "type": "object",
      "additionalProperties": false,
      "required": ["delivery_id", "mode", "idempotency_key", "deadline"],
      "properties": {
        "delivery_id": { "$ref": "common.json#/$defs/UuidV7" },
        "mode": { "const": "at_least_once" },
        "idempotency_key": { "$ref": "common.json#/$defs/IdempotencyKey" },
        "deadline": { "$ref": "common.json#/$defs/DateTimeMs" }
      }
    },
    "in_reply_to": { "$ref": "common.json#/$defs/UuidV7" },
    "params": { "type": "object" }
  }
}
```

### 7.2 Delivery rules

`delivery.delivery_id` is REQUIRED.

It is nested inside `delivery`.

It is never a top-level canonical envelope member.

It is unique to one physical durable delivery correlation.

An exact retransmission of an unacknowledged record MUST retain:

- the same logical record;
- the same message ID;
- the same delivery ID;
- the same semantic digest;
- the same deadline.

A logical retry after an uncertain receipt MAY allocate a new message ID and
delivery ID only if its semantic projection is unchanged.

An implementation MUST NOT use a new delivery ID to bypass:

- idempotency;
- a prior permanent rejection;
- a route pin;
- a deadline;
- a cancellation tombstone;
- a replay ledger.

### 7.3 Application type registry

| Type | Direction | Authority |
|---|---|---|
| `task.submit` | Owner to selected executor | Requests admission. |
| `task.accepted` | Executor to owner | Sole durable positive admission event. |
| `task.rejected` | Executor to owner | Sole durable pre-admission negative event. |
| `task.progress` | Executor to owner | Optional non-terminal lifecycle observation. |
| `task.completed` | Executor to owner | Sole post-acceptance terminal event. |
| `task.cancel` | Authorized owner to pinned executor | Requests cancellation. |
| `task.status` | Owner query or executor snapshot | Does not mutate task state. |
| `error` | Correlated peer diagnostic | Does not replace a lifecycle record. |

The v2 base profile does not define:

- broadcast;
- wildcard targeting;
- raw card application messages;
- raw receipt application messages;
- raw resume application messages;
- direct route mutation;
- stream records;
- subscription records;
- artifact records;
- authorization records;
- carrier records;
- arbitrary extension objects.

A base-only peer MUST reject those records.

### 7.4 Task submission parameters

A canonical `task.submit` `params` object has exactly:

```text
task_id
capability
capability_version
capability_contract_digest
input
deadline
```

The submission deadline MUST equal `delivery.deadline` byte-for-byte.

The submission capability tuple MUST equal a capability on the authenticated
target card.

The target MUST validate `input` before admission.

The target MUST reject a past deadline or a deadline beyond its effective
policy ceiling.

The target MUST make authorization, capability validation, input validation,
and durable admission decisions before starting a side-effecting handler.

### 7.5 Lifecycle rules

`task.accepted` and `task.rejected` both use `event_seq = 1`.

`task.progress` uses a contiguous `event_seq >= 2`.

`task.completed` uses a contiguous `event_seq >= 2`.

`task.completed` is the only post-acceptance terminal record.

The terminal outcome is exactly one of:

- `succeeded`;
- `failed`;
- `cancelled`.

Lifecycle records that require a capability tuple MUST echo the exact tuple
pinned by the submission.

An owner MUST reject a lifecycle record whose tuple differs from its pinned
submission tuple.

An owner MUST deduplicate lifecycle events by `(task_id, event_seq)` and
event digest.

A different event at an existing sequence is a permanent conflict.

### 7.6 Task cancellation and status

`task.cancel` does not itself establish that a task is cancelled.

It requests a cancellation decision from the pinned executor.

The executor's fenced durable lifecycle transition determines the result.

A cancellation request MUST NOT cause a route to move to a sibling executor.

`task.status` is either:

- a `query` naming a task ID; or
- a `snapshot` describing a durable observed state.

A status response MUST NOT claim a terminal outcome that the durable lifecycle
ledger has not recorded.

### 7.7 Example canonical task submission

```json
{
  "protocol": "polymesh.0.2",
  "type": "task.submit",
  "message_id": "0197a1b0-0000-7000-8000-000000000001",
  "timestamp": "2026-07-21T10:00:00.000Z",
  "source": {
    "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
    "agent_id": "org.example.owner",
    "instance_id": "AAAAAAAAAAAAAAAAAAAAAA"
  },
  "target": {
    "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
    "agent_id": "org.example.executor"
  },
  "delivery": {
    "delivery_id": "0197a1b0-0000-7000-8000-000000000002",
    "mode": "at_least_once",
    "idempotency_key": "submit:example:1",
    "deadline": "2026-07-21T10:05:00.000Z"
  },
  "params": {
    "task_id": "0197a1b0-0000-7000-8000-000000000003",
    "capability": "org.example.echo",
    "capability_version": "1.0.0",
    "capability_contract_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "input": {
      "message": "hello"
    },
    "deadline": "2026-07-21T10:05:00.000Z"
  }
}
```

The example is syntactic.

It is not an authorization grant.

It is not a proof that the capability is eligible.

It is not a durable receipt.

It is not task acceptance.

### 7.8 Receipt semantics

`delivery.receipt` is a v2 transport-control record.

It is not an application envelope.

It is never routed as a task.

It is never acknowledged by another receipt.

It is never compressed.

The receipt has:

```text
type
v
sid
mesh_id
delivery_id
message_id
record_digest
semantic_digest
state
code (only for rejected)
```

The permitted states are:

| State | Meaning |
|---|---|
| `stored` | Receiver durably stored a new delivery or committed a durable ingress/outbox fact. |
| `duplicate` | Receiver found a matching durable prior record and created no new logical side effect. |
| `rejected` | Receiver durably recorded a delivery-level refusal; `code` is required. |

A successful socket write is not a `stored` receipt.

A relay route lookup is not a `stored` receipt.

Task handler start is not a `stored` receipt.

Task acceptance is not a `stored` receipt.

An outbox reaches its delivered state only after a matching receipt with
`stored` or `duplicate` is durably processed.

### 7.9 Resume semantics

After a new session becomes active, either peer MAY send
`delivery.resume`.

Each entry names:

```text
partition_id
fence
received_through
```

`received_through` is the highest contiguous durable position.

It is not the largest position a receiver happened to observe.

The peer replies with `delivery.resume.ack`.

Each acknowledgement entry states:

- the partition;
- the fence;
- `available`, `unavailable`, or `stale_fence`;
- replay bounds where available;
- a bounded error code when needed.

Resume does not:

- prove task acceptance;
- prove handler execution;
- permit a new route selection;
- permit a stale fence mutation;
- permit a blind automatic resend;
- recover records that durable retention has removed.

## 8. Broker canonicalization requirements

### 8.1 Broker migration objective

The broker v2 path MUST move from the legacy `v2.ts` record model to the
canonical model in `protocol.ts`.

This includes:

- canonical v2 subprotocol selection;
- full canonical hello;
- channel-binding-aware session IDs;
- canonical auth records;
- canonical mesh-scoped cards;
- nested delivery IDs;
- canonical delivery receipts;
- resume records;
- canonical compression state machine.

The broker MUST make this migration before native clients are advertised.

### 8.2 Durable ingress order

For a new canonical submission, the broker MUST:

1. authenticate the session;

2. validate profile, phase, mesh, and record shape;

3. apply admission and rate checks;

4. consult replay and idempotency state;

5. select an eligible executor where selection is required;

6. persist the ingress record, idempotency fact, route pin, and outbox work in
   one transaction;

7. commit;

8. only then emit or schedule a `stored` receipt.

For an exact duplicate, the broker MUST preserve the prior durable semantic
decision.

For a conflicting duplicate, it MUST fail closed.

### 8.3 Route pinning

Once a task is accepted into a durable route:

- the selected executor identity remains pinned;
- the immutable route fingerprint remains unchanged;
- a health change does not authorize rerouting accepted work;
- a reconnect does not authorize rerouting accepted work;
- a resume exchange does not authorize rerouting accepted work;
- an SDK retry does not authorize rerouting accepted work.

The existing routing and durable-store modules already model these ownership
concepts.

v0.4.0 client work MUST consume them rather than bypass them.

### 8.4 Gateway alignment requirement

The gateway's `GatewayTaskEnvelope` currently resembles the canonical
nested-delivery model.

However, its mesh grammar and validation are independently declared.

v0.4.0 MUST replace independent gateway wire-shape assumptions with imports
or generated equivalents of the canonical v2 schema.

The gateway MUST use:

- canonical `msh_` grammar;
- canonical address validation;
- canonical task submit parameter names;
- canonical UUIDv7 requirements;
- canonical deadline equality rule;
- canonical receipt meaning.

The gateway MUST continue to keep raw bearer tokens outside envelopes and
events.

## 9. V2 session handshake

### 9.1 Handshake phases

Each native v2 implementation SHALL expose these conceptual phases:

| Phase | Allowed inbound record | Allowed outbound record |
|---|---|---|
| `idle` | None | Transport open only. |
| `await_hello` | Initiator hello for responder; responder hello for initiator | Initiator hello or responder hello. |
| `await_auth` | Peer auth | Local auth. |
| `await_card` | Peer card | Local card. |
| `await_ready` | Peer ready | Local ready. |
| `active_plain` | Base control or application record | Base control or application record. |
| `compression_negotiating` | Valid compression control record | Valid compression control record. |
| `active_compressed` | Base control, application, or valid wrapper | Base control, application, or valid wrapper. |
| `closed` | None | Close only. |

The exact implementation may use finer internal states.

It MUST preserve these externally meaningful phase boundaries.

No application envelope is accepted before both `ready` records validate.

No compression control record is accepted before both ordinary `ready`
records validate.

No compressed wrapper is accepted before both compression-ready records
validate.

### 9.2 Canonical handshake sequence

The canonical sequence is:

```text
Initiator                                      Responder
    |                                               |
    | --- hello(role=initiator) ------------------> |
    | <--- hello(role=responder, echo, sid) ------- |
    |                                               |
    | --- auth(role=initiator) -------------------> |
    | <--- auth(role=responder) ------------------- |
    |                                               |
    | --- card(role=initiator) -------------------> |
    | <--- card(role=responder) ------------------- |
    |                                               |
    | --- ready(role=initiator) ------------------> |
    | <--- ready(role=responder) ------------------ |
    |                                               |
    | ==== ACTIVE PLAIN ========================== |
```

The initiator is the only peer that sends the first `hello`.

The responder is the only peer that derives and supplies `sid`.

The responder hello MUST echo the exact initiator nonce.

Roles are fixed for the lifetime of the session.

The order of role-specific records in all digests is always initiator first,
responder second.

An implementation MUST NOT sort records by arrival time, agent name, or
lexicographic representation.

### 9.3 Initiator hello

The initiator hello has this closed shape:

```json
{
  "type": "hello",
  "v": "0.2",
  "profile": "polymesh.0.2",
  "role": "initiator",
  "agent_id": "org.example.owner",
  "instance_id": "AAAAAAAAAAAAAAAAAAAAAA",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  "transport_profile": "enrolled-wss/1",
  "receive_limits": {
    "max_wire_bytes": 1048576,
    "max_json_bytes": 1048576,
    "max_uncompressed_bytes": 1048576,
    "max_expansion_ratio": 32
  },
  "extensions": ["compression/zstd"]
}
```

The initiator MUST create a fresh 32-byte CSPRNG nonce per connection.

The initiator MUST NOT log a complete nonce at normal log level.

The initiator MUST NOT treat hello identity fields as authenticated before
auth and card verification finish.

The initiator extensions list expresses capability only.

It does not select an extension.

### 9.4 Responder hello

The responder hello has the initiator fields plus:

```json
{
  "type": "hello",
  "v": "0.2",
  "profile": "polymesh.0.2",
  "role": "responder",
  "agent_id": "org.example.broker",
  "instance_id": "EBESExQVFhcYGRobHB0eHw",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "nonce": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
  "echo": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "transport_profile": "enrolled-wss/1",
  "receive_limits": {
    "max_wire_bytes": 1048576,
    "max_json_bytes": 1048576,
    "max_uncompressed_bytes": 1048576,
    "max_expansion_ratio": 32
  },
  "extensions": ["compression/zstd"]
}
```

The responder transport profile MUST reflect the locally authenticated
transport classification.

It MUST NOT be copied blindly from the initiator.

Each peer MUST obey the peer's declared receive limits.

Receive limits are not authorization to send unlimited work.

### 9.5 Session correlation derivation

The responder calculates:

```text
sid = base64url(SHA-256(
  UTF8("PMX-SID/0.2\0") ||
  initiator_nonce_bytes ||
  responder_nonce_bytes ||
  UTF8("polymesh.0.2") ||
  channel_binding_hash_bytes
))
```

`sid` is correlation material.

It is not a secret.

It is not an enrollment credential.

It is not a route fence.

It is not an authorization grant.

Every post-hello control record MUST contain the exact current `sid`.

The channel-binding value MUST originate from the selected authenticated
transport.

It MUST NOT be derived from:

- a hostname supplied by a peer;
- a card endpoint;
- an unverified certificate name;
- an HTTP request URL;
- a user-controlled task field.

### 9.6 Auth record

The canonical auth shape is:

```json
{
  "type": "auth",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "role": "initiator",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "transcript_hash": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "authentication": {
    "method": "mtls-enrolled",
    "principal_id": "principal_01",
    "credential_id": "credential_01",
    "key_id": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "auth_epoch": "1",
    "channel_binding": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
  },
  "proof": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
}
```

`principal_id` and `credential_id` are opaque correlation values.

They are not bearer credentials.

The auth record MUST NOT contain:

- an OAuth access token;
- a refresh token;
- a DPoP proof;
- a client certificate;
- a private key;
- a cookie;
- a raw runtime token;
- arbitrary caller policy;
- a delegation grant.

### 9.7 Selected authentication rule

The v0.4.0 core supported secure transport is
`enrolled-wss/1`.

For this profile:

1. `authentication.method` MUST be `mtls-enrolled`.

2. `proof` is REQUIRED even though the general structural type permits
   profile-specific optionality.

3. The transport adapter MUST supply the authenticated principal,
   credential identifier, credential epoch, and channel-binding hash.

4. The SDK MUST verify that the stated auth members equal those trusted
   transport values.

5. The SDK MUST verify the peer's enrolled Ed25519 key binding.

6. The SDK MUST verify that the key, mesh, and claimed agent identity are
   permitted by local enrollment.

7. The SDK MUST reject an expired or revoked credential epoch.

8. The SDK MUST reject a missing, malformed, or mismatched proof.

v0.4.0 introduces this canonical proof payload for the enrolled profile:

```text
proof_payload =
  UTF8("PMX-AUTH/0.2\0") ||
  UTF8(JCS({
    sid,
    role,
    mesh_id,
    transcript_hash,
    authentication
  }))
```

`proof` is the canonical base64url Ed25519 signature over
`proof_payload` by the enrolled key named by `authentication.key_id`.

The TypeScript and Python implementations MUST expose vector-tested
`create_v2_auth_proof` and `verify_v2_auth_proof` equivalents.

The implementation MUST use the identical bytes in both languages.

### 9.8 Card records

After both auth records validate, each peer sends exactly one card record:

```json
{
  "type": "card",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "role": "initiator",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "card_digest": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  "card": {}
}
```

The receiver MUST verify:

- `sid`;
- role;
- mesh ID;
- card digest;
- card signature;
- card expiry;
- card identity;
- card mesh/agent/instance identity;
- enrollment binding.

The receiver MUST reject a card that mismatches hello or auth identity.

It MUST NOT trust an endpoint or capability before card verification.

### 9.9 Ready records

Each peer sends one ready record:

```json
{
  "type": "ready",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "role": "initiator",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "transcript_hash": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "auth_digest": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
  "self_card_digest": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
  "peer_card_digest": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "receive_limits": {
    "max_wire_bytes": 1048576,
    "max_json_bytes": 1048576,
    "max_uncompressed_bytes": 1048576,
    "max_expansion_ratio": 32
  },
  "extensions": ["compression/zstd"]
}
```

The initiating peer's self-card digest is the initiator card.

The responding peer's self-card digest is the responder card.

The transcript hash, auth digest, mesh, role, and local card digests MUST
exactly match local computation.

A valid ready record establishes only an active protocol session.

It does not establish:

- task storage;
- task admission;
- task execution;
- task completion;
- a route;
- a receipt;
- an authorization grant.

### 9.10 Post-ready control records

After ordinary ready:

- `card.update` MAY publish a verified higher card revision;
- `delivery.resume` and `delivery.resume.ack` MAY reconcile durable
  positions;
- `delivery.receipt` MAY settle durable delivery;
- `ping` and `pong` MAY manage liveness;
- `session.error` MAY deliver a bounded non-authoritative diagnostic;
- compression negotiation MAY begin only when both peers advertised
  `compression/zstd`.

`card.update` MUST include the immediately prior accepted card digest.

It MUST NOT change mesh, agent, instance, or identity key.

It MUST NOT decrease revision.

It MUST NOT alter the contract used by an already accepted task.

## 10. Compression extension

### 10.1 Scope

`compression/zstd` is optional.

`none` is the mandatory interoperable baseline.

Both SDKs MUST implement the compression state machine and rejection rules.

An SDK MUST advertise `compression/zstd` only when it has a bounded,
tested codec implementation.

A peer that does not advertise it MUST remain fully interoperable using
`none`.

### 10.2 Canonical record family

The canonical v0.4.0 compression records are:

```text
compression.proposal
compression.accept
compression.ready
compression.zstd
```

`compression.offer` is a legacy spelling.

It MUST NOT be emitted or accepted on a canonical v0.4.0 session.

The initiator alone sends `compression.proposal`.

The responder alone sends `compression.accept`.

Each peer sends one `compression.ready` only after a zstd acceptance.

### 10.3 Negotiation sequence

```text
ACTIVE PLAIN
  |
  | initiator: compression.proposal
  v
PROPOSAL SENT / RECEIVED
  |
  | responder: compression.accept
  v
ACCEPTED
  |
  | initiator: compression.ready
  | responder: compression.ready
  v
ACTIVE COMPRESSED
```

If the responder selects `none`, both peers remain `ACTIVE PLAIN`.

No peer may propose compression twice during one session.

An invalid role, SID, mesh, proposal ID, state transition, or limit widening
MUST close the compression state machine and fail the session or extension
according to the stable error policy.

### 10.4 Proposal schema

```json
{
  "type": "compression.proposal",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "proposal_id": "0197a1b0-0000-7000-8000-000000000010",
  "algorithms": ["zstd"],
  "zstd": {
    "max_compressed_bytes": 1048576,
    "max_uncompressed_bytes": 1048576,
    "max_expansion_ratio": 32
  }
}
```

### 10.5 Acceptance schema

```json
{
  "type": "compression.accept",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "proposal_id": "0197a1b0-0000-7000-8000-000000000010",
  "algorithm": "zstd",
  "zstd": {
    "max_compressed_bytes": 524288,
    "max_uncompressed_bytes": 1048576,
    "max_expansion_ratio": 16
  }
}
```

When `algorithm` is `none`, `zstd` MUST be absent.

When `algorithm` is `zstd`, `zstd` MUST be present.

The selected values MUST be an intersection of:

- initiator proposal;
- initiator declared receive limits;
- responder declared receive limits;
- responder local policy limits;
- implementation hard ceilings.

### 10.6 Activation schema

```json
{
  "type": "compression.ready",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "proposal_id": "0197a1b0-0000-7000-8000-000000000010",
  "algorithm": "zstd",
  "epoch": "1"
}
```

`compression.zstd` is invalid until both ready records validate.

### 10.7 Wrapper schema

```json
{
  "type": "compression.zstd",
  "v": "0.2",
  "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "mesh_id": "msh_01J9YJP3QXA73AGWT2J71D8TQR",
  "epoch": "1",
  "content_type": "application/polymesh-envelope+json",
  "uncompressed_bytes": 1234,
  "compressed_bytes": 456,
  "payload": "BASE64URL_ZSTD_BYTES"
}
```

The wrapper contains exactly one UTF-8 serialized canonical v2 application
envelope.

It contains no dictionary identifier.

It contains no stream identifier.

It contains no shared decompressor state.

It contains no nested compression wrapper.

### 10.8 Compression safety rules

Compression MUST NOT apply to:

- hello;
- auth;
- card;
- ready;
- card update;
- delivery receipt;
- resume;
- resume acknowledgement;
- ping;
- pong;
- session error;
- compression proposal;
- compression acceptance;
- compression ready.

Before allocating unbounded output, a receiver MUST validate:

- wrapper schema;
- active state;
- SID;
- mesh ID;
- epoch;
- content type;
- compressed byte count;
- declared uncompressed byte count;
- selected limits;
- expansion ratio;
- transport wire-byte ceiling.

The receiver MUST pass a hard output ceiling to the decompressor.

The receiver MUST verify actual output length equals
`uncompressed_bytes`.

The receiver MUST strictly parse and validate the resulting application
envelope before it routes or exposes it.

The receiver MUST charge both wire and decoded bytes to applicable limits.

The receiver MUST disable WebSocket `permessage-deflate`.

## 11. TypeScript SDK and broker implementation contract

### 11.1 New TypeScript module surface

v0.4.0 SHALL add a distinct v2 public entry point:

```text
@latticeag/polymesh-client/v2
```

The root package MAY re-export selected v2 names.

The existing root default export MUST remain `PolyMeshClient`.

The existing `./client` entry point MUST remain the v0.1 client surface.

The new entry point SHALL export:

```ts
export const V2_PROFILE: {
  protocol: "polymesh.0.2";
  handshake_version: "0.2";
  card_version: "2.0";
};

export interface V2ClientOptions {
  card: V2AgentCard;
  meshId: V2MeshId;
  endpoint: URL | string;
  transportProfile: "enrolled-wss/1";
  transport?: V2WireTransport;
  identity: V2IdentityOptions;
  receiveLimits?: Partial<V2ReceiveLimits>;
  extensions?: readonly V2Extension[];
  handlers?: Readonly<Record<string, V2TaskHandler>>;
  replayLedger?: ReplayLedger;
  policyEngine?: PolicyEngine;
}

export class PolyMeshV2Client {
  connect(): Promise<this>;
  disconnect(code?: number, reason?: string): Promise<void>;
  submitTask(request: V2SubmitTaskRequest): Promise<V2TaskHandle>;
  cancelTask(taskId: V2TaskId, reason?: string): Promise<void>;
  queryTask(taskId: V2TaskId): Promise<V2TaskStatusSnapshot>;
  setHandler(capability: string, handler: V2TaskHandler): void;
  removeHandler(capability: string): void;
}
```

`V2WireTransport` MUST expose:

- bounded send;
- bounded receive;
- close;
- selected subprotocol;
- transport profile;
- exact 32-byte channel-binding hash;
- authenticated peer context;
- no implicit compression.

The client MUST reject an adapter whose declared profile or binding does not
match its configured `V2ClientOptions`.

### 11.2 TypeScript task API

```ts
export interface V2SubmitTaskRequest {
  target: V2AgentRef;
  capability: string;
  capabilityVersion: string;
  capabilityContractDigest: V2Digest;
  input: JsonValue;
  deadline: string;
  idempotencyKey: string;
  taskId?: V2TaskId;
}

export interface V2TaskHandle extends AsyncIterable<V2LifecycleEvent> {
  readonly taskId: V2TaskId;
  readonly submissionMessageId: V2MessageId;
  readonly deliveryId: V2DeliveryId;
  cancel(reason?: string): Promise<void>;
  result(): Promise<JsonValue>;
  status(): V2TaskStatusSnapshot | undefined;
}
```

A v2 task handle MUST:

- surface durable receipt separately from task acceptance;
- surface lifecycle events in event sequence order;
- reject conflicting duplicate events;
- never call an event iterator token streaming;
- bound its local queue;
- expose recovery-required uncertainty rather than silently resending work;
- validate terminal results against the pinned contract;
- preserve deadline and idempotency semantics.

### 11.3 TypeScript broker changes

The TypeScript broker MUST:

- replace live legacy v2 handshake dispatch with canonical v2 dispatch;
- use the full channel-binding-aware SID derivation;
- emit full canonical hello/auth/card/ready records;
- use nested `delivery.delivery_id`;
- use canonical v2 digest helpers;
- validate canonical receipts and resume records;
- use the canonical compression state machine;
- preserve existing durable routing, fence, replay, and rate-limit semantics;
- expose a canonical v2 test listener that rejects legacy forms.

The broker MAY retain legacy code behind an explicit non-default test adapter.

It MUST NOT bind that adapter to the canonical v2 listener.

## 12. Python SDK implementation contract

### 12.1 New Python package surface

v0.4.0 SHALL add:

```text
src/polymesh/v2/
    __init__.py
    types.py
    protocol.py
    transport.py
    client.py
    compression.py
```

The public import shape SHALL be:

```python
from polymesh.v2 import (
    V2Client,
    V2ClientOptions,
    V2AgentCard,
    V2Envelope,
    V2TaskHandle,
)
```

The root `polymesh` imports remain v0.1-compatible.

The new package SHALL not monkey-patch v2 fields into `polymesh.Envelope`,
`polymesh.AgentCard`, or `polymesh.PolyMeshClient`.

### 12.2 Python v2 API

```python
class V2Client:
    async def connect(self) -> "V2Client": ...
    async def disconnect(self, code: int = 1000, reason: str = "client closed") -> None: ...
    async def submit_task(self, request: V2SubmitTaskRequest) -> V2TaskHandle: ...
    async def cancel_task(self, task_id: V2TaskId, reason: str | None = None) -> None: ...
    async def query_task(self, task_id: V2TaskId) -> V2TaskStatusSnapshot: ...
    def register_handler(self, capability: str, handler: V2TaskHandler) -> None: ...
    def unregister_handler(self, capability: str) -> None: ...

class V2TaskHandle:
    task_id: V2TaskId
    submission_message_id: V2MessageId
    delivery_id: V2DeliveryId
    async def result(self) -> JsonValue: ...
    async def cancel(self, reason: str | None = None) -> None: ...
    def __aiter__(self) -> AsyncIterator[V2LifecycleEvent]: ...
```

Python v2 models SHALL be strict Pydantic models or equivalent strict models.

They MUST reject unknown fields and invalid wire nulls.

They MUST consume the same JSON vector corpus as TypeScript.

### 12.3 Python secure transport boundary

The current Python transport intentionally fails closed when the selected
secure profile cannot expose the required TLS exporter/channel binding.

v0.4.0 preserves that posture.

The new Python `V2WireTransport` protocol SHALL require:

```python
class V2WireTransport(Protocol):
    transport_profile: Literal["enrolled-wss/1"]
    selected_subprotocol: Literal["polymesh.0.2"]
    authenticated_context: V2AuthenticatedTransportContext
    def channel_binding_hash(self) -> bytes: ...
    async def send(self, record: str) -> None: ...
    async def recv(self) -> str: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...
```

`channel_binding_hash()` MUST return exactly 32 bytes.

If an adapter cannot meet that requirement, it MUST raise
`SECURE_PROFILE_UNSUPPORTED` or the v2 equivalent before it sends an
application record.

It MUST NOT substitute:

- a certificate fingerprint;
- a TLS unique value;
- a completed-handshake hash;
- a hostname hash;
- an invented random value.

### 12.4 Python compression posture

Python MUST always implement:

- `none` baseline semantics;
- compression record parsing;
- negotiation validation;
- wrapper limits;
- decompression rejection behavior.

Python MAY advertise `compression/zstd` only when a bounded codec is
installed and selected.

If v0.4.0 documents Python zstd support, the package metadata MUST declare
the exact dependency or optional extra, lock it for CI, and run unskipped
cross-language codec tests.

If that gate does not pass, Python MUST advertise no compression extension.

## 13. Scope guardrail and release plan

### 13.1 Surfaces that stay the same

v0.4.0 MUST preserve:

- all existing npm package names;
- the `latticeag-polymesh` distribution name;
- the `polymesh` Python import name;
- existing CLI command names;
- existing v0.1 public imports;
- existing v0.1 vector bytes and decisions;
- `polymesh.0.1` subprotocol;
- `/polymesh` transport path;
- strict parser limits;
- numeric-loopback-only plaintext restrictions;
- fail-closed WSS behavior;
- token-file secret handling;
- TOML precedence;
- mDNS's hint-only, no-enrollment posture;
- existing broker routing, health, fence, durable-store, and rate-limit
  authority;
- gateway non-hosted status;
- Python broker v0.1-only status;
- local v0.1 quick-start and Compose fixture semantics.

### 13.2 Must-ship work table

| ID | Work | Effort | Impact |
|---|---|---:|---:|
| P40-01 | Freeze canonical v2 schemas and legacy disposition. | Large | High |
| P40-02 | Migrate TypeScript broker v2 session path to canonical records. | Large | High |
| P40-03 | Ship TypeScript v2 SDK namespace and client. | Large | High |
| P40-04 | Ship Python `polymesh.v2` namespace and client. | Large | High |
| P40-05 | Add v2 vectors and four-pair process interop. | Large | High |
| P40-06 | Ship mandatory `none`; ship zstd only when cross-language tested. | Medium | High |
| P40-07 | Preserve v0.1 profile separation and no-downgrade behavior. | Medium | High |
| P40-08 | Extend artifact, CI, docs, template-version, and migration gates. | Medium | High |

### 13.3 Milestone order

```text
M0 profile contract
        |
        v
M1 canonical schema + vectors + legacy cut line
        |
        v
M2 canonical TypeScript reference broker
      /   \
     v     v
M3 TS SDK  M3 Python SDK
      \   /
        v
M4 packaged-artifact interop and compression hardening
        |
        v
M5 docs, examples, release candidate
        |
        v
M6 GA
```

M1 must complete before SDK wire behavior merges.

M2 must complete before process interoperability is called evidence.

M3 TypeScript and Python work may proceed in parallel only against frozen
M1 vectors.

M4 must complete before a beta claims native support.

### 13.4 Release gates

| Gate | Required evidence |
|---|---|
| Namespace consistency | All npm, Python, generator, template, docs, and scaffold dependency versions agree on `0.4.0`. |
| TypeScript quality | Clean install, type check, clean build, full tests, packed-tarball consumer test. |
| Python reproducibility | Locked environment, tests, wheel/sdist build, isolated wheel import, v2 API smoke test. |
| Artifact install | Packed npm and wheel v2 examples run outside the source tree. |
| Canonical convergence | Canonical listener rejects top-level delivery ID, broad legacy mesh ID, legacy hello, and `compression.offer`. |
| v0.1 regression | Existing v0.1 vectors and local quick start remain unchanged and green. |
| Interoperability | All four TypeScript/Python caller-executor pairings complete through a TypeScript durable broker. |
| Compression | `none` always passes; any zstd support has unskipped TS/Python codec tests. |
| Documentation | Support matrix and examples describe only actually tested v2 carrier/security scope. |
| Governance | Release artifact scan excludes governed specifications, review files, credentials, and internal planning documents. |

### 13.5 v0.5+ deferrals

v0.5+ may consider:

- MCP bridge;
- LangChain adapter;
- CrewAI adapter;
- Worker relay;
- Wrangler configuration;
- SessionDO;
- MailboxDO;
- tunnel policy and connector service;
- gateway status/cancel expansion;
- typed gateway clients;
- Python v2 broker;
- generic delegation;
- generic signing;
- streaming;
- pub/sub;
- artifact transfer;
- multi-hop routing.

None of those is a release blocker for native v2 SDK completion.

None may be implied by v0.4.0 documentation.

## 14. Final acceptance statement

v0.4.0 is complete only when an installed TypeScript SDK and an installed
Python SDK can each explicitly select canonical `polymesh.0.2`, connect to
the canonical TypeScript durable broker, and complete a bounded task lifecycle
without a legacy-layout fallback or a v0.1 downgrade.

It is not complete when:

- only types exist;
- only parser vectors pass;
- only a workspace import works;
- Python can parse but cannot complete a task;
- a secure transport is claimed without an exact binding;
- zstd is claimed with skipped tests;
- legacy and canonical v2 layouts are both silently accepted;
- v0.1 compatibility regresses;
- documentation implies MCP, framework, hosted, or Worker delivery.

The release leaves PolyMesh with one clear statement:

> v0.4.0 adds a native, explicitly selected, canonical v2 SDK path in both
> languages while preserving the reproducible v0.1 local-first path and
> deferring integration and hosted-relay programs.
