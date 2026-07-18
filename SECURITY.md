# Security at PolyMesh

PolyMesh is a local-first agent-to-agent protocol and reference implementation.

This page explains how to evaluate, deploy, operate, and report security issues
for PolyMesh. It is written for maintainers, deployers, integrators, and people
whose agents may handle sensitive data or execute privileged work.

Security is a property of the complete deployment: the host, operating-system
account, transport, credentials, policy, handlers, dependencies, and operations
matter as much as the protocol library.

## Read this first

PolyMesh is under active development.

The reference implementation is useful for development, interoperability work,
and controlled experiments. Treat it as experimental unless a particular release
explicitly documents a supported production security profile and you have
verified that your deployment meets that profile.

This document describes the security posture we expect from a careful deployment.

It is not a claim that every checkout, example, adapter, plugin, network path,
or future integration enforces every safeguard described here.

Do not expose a development listener to a LAN, the internet, a shared workstation,
or an untrusted browser merely because it appears to work locally.

Do not give an agent broad filesystem, shell, cloud, email, database, or credential
access because another agent claims a familiar name.

When in doubt, use a single trusted machine, an owner-only operating-system
account, a loopback-only listener, narrowly scoped capabilities, and a separate
low-privilege worker for every action with side effects.

## Security status and intended use

PolyMesh is designed to help agents exchange structured messages and coordinate
work.

It is not designed to make untrusted code safe, turn a shared user account into
a strong security boundary, or replace host hardening and organizational access
controls.

The project uses a staged security posture:

| Deployment class | Appropriate use | Minimum expectation |
| --- | --- | --- |
| Local development | One developer on a trusted machine | Loopback or in-memory transport; synthetic data; no privileged handlers |
| Controlled integration | Trusted services in a managed environment | Explicit allow policy; isolated workers; secret management; monitoring |
| Sensitive production | Data or actions with material impact | Independently reviewed secure profile; strong identity; encrypted transport; durable audit and incident response |
| Public or multi-tenant service | Unrelated users or internet-exposed agents | Not a default deployment model; requires a dedicated threat model and external security review |

Examples in README files, tests, and demos are not production deployment recipes.

Examples may omit TLS, persistent storage, policy enforcement, credential rotation,
resource isolation, monitoring, or other controls required in a real environment.

Before relying on PolyMesh for an important workflow, make an explicit decision
about the data, authority, users, networks, and recovery obligations in scope.

## How to report a vulnerability

Please report suspected vulnerabilities privately.

Use the repository's private GitHub vulnerability-reporting flow:

<https://github.com/mosesman831/polymesh/security/advisories/new>

If private reporting is unavailable, use a maintainer contact listed on the
repository to request a private channel. Do not include exploit details in a
public issue, pull request, discussion, chat room, or social-media post.

Please include enough information for maintainers to reproduce and assess the
issue:

- A concise description of the security impact.

- The affected package, version, commit, deployment mode, and operating system.

- Clear reproduction steps, a proof of concept, or a minimal test case.

- Preconditions, such as access level, network position, configuration, or
  required capability grants.

- The expected behavior and the observed behavior.

- Whether the issue may expose credentials, personal data, task results, or
  allow execution of a privileged operation.

- Any suggested mitigation, if you have one.

- A safe contact method and preferred attribution, if you want attribution.

Please avoid accessing other users' data, causing persistent changes, disrupting
services, or escalating privileges beyond what is needed to demonstrate impact.

If an issue is actively exploited or creates immediate material risk, say so in
the first line of the report so that triage can prioritize containment.

We aim to acknowledge credible reports promptly, validate the issue, communicate
status privately, coordinate a fix and release where appropriate, and publish a
security advisory when disclosure is safe.

We do not promise a bounty, a response-time SLA, or support for versions outside
the project’s documented support window.

## Threat model

PolyMesh deployments should begin with a written threat model.

The following table captures common threats and the primary controls a deployer
should use. It is a planning aid, not a guarantee that a particular configuration
implements every control.

| Threat | Example | Primary controls | Residual risk |
| --- | --- | --- | --- |
| Untrusted network peer | A remote client sends crafted frames or task requests | Do not expose development listeners; require authenticated encrypted transport; restrict network ingress | A valid but malicious peer can still request permitted work |
| Identity spoofing | A process claims another agent’s logical ID | Bind authorization to a verified principal or enrolled key, not a self-declared name | Credential compromise can still impersonate that principal |
| Credential theft | A token is copied from a URL, log, shell history, or weakly protected file | Keep secrets out of URLs and logs; use owner-only storage; rotate and revoke | A compromised host or account can read accessible credentials |
| Same-user compromise | Malware runs under the same OS account as an agent | Separate privileged work into different accounts, containers, or hosts | Same-UID isolation is weak without a stronger boundary |
| Replay | A captured submit is delivered again | Stable-principal idempotency, durable replay records, bounded retention, task state checks | Storage loss or expiry may limit replay detection |
| Confused deputy | A low-trust caller asks a privileged agent to read a secret or use cloud credentials | Per-capability allow policy, resource scopes, approval gates, isolated adapters | Bugs in adapters or overly broad policy can still over-authorize |
| Resource exhaustion | An attacker opens many connections, sends large JSON, or causes long tasks | Admission limits, size and time limits, queue bounds, worker quotas | A local privileged attacker can still exhaust host-wide resources |
| Endpoint redirection | Discovery data directs a client toward an internal service | Treat discovery and cards as hints; pin identity; restrict address ranges; forbid automatic fallback | Misconfigured allowlists can still permit unsafe endpoints |
| Data exfiltration | Sensitive task output appears in progress, errors, logs, or a third-party summary service | Minimize data at source; recipient-specific filtering; structured redaction; log hygiene | Any recipient allowed to receive data can mishandle it |
| Supply-chain compromise | A dependency or release artifact is malicious | Lockfiles, dependency review, CI, provenance, SBOMs, signed release process | A trusted publisher or build environment can be compromised |
| Operator mistake | A listener is bound too broadly or a wildcard policy is added | Safe defaults, configuration review, least privilege, staging, change audit | Human error remains possible |
| Privileged handler compromise | A handler executes commands or accesses a production API | OS-enforced sandboxing, service accounts, egress rules, approvals | A permitted action may still have business impact |

### Trust zones

Use explicit trust zones instead of treating “local” as automatically trusted.

| Zone | Typical contents | Default trust decision |
| --- | --- | --- |
| Untrusted input | Network frames, discovery records, cards, task parameters, tool output | Validate, bound, authenticate, and authorize before use |
| Session boundary | A connected peer with transport credentials | Trust only the verified principal and negotiated session state |
| Policy boundary | Authorization service, policy database, approval process | Fail closed when unavailable or malformed |
| Resource boundary | Files, databases, shell, cloud APIs, browser automation, tools | Access only through a scoped adapter or low-privilege service identity |
| Worker boundary | Handler process or sandbox | Treat as potentially compromised; give minimal privileges |
| Audit boundary | Append-only events and security telemetry | Limit writers, protect integrity, and avoid sensitive payloads |
| Operator boundary | Deployment account, CI, key manager, incident responders | Use MFA, least privilege, and separate duties where possible |

## Security boundaries and non-goals

The following are important boundaries for anyone deploying PolyMesh.

PolyMesh does not make arbitrary agent code trustworthy.

PolyMesh does not make a process running under the same operating-system user a
separate security principal without additional host controls.

PolyMesh does not grant authority based on an Agent Card, a display name, a DNS
record, an mDNS advertisement, an IP address, or a claimed `agent_id` alone.

PolyMesh does not safely execute shell commands, scripts, templates, or arbitrary
policy expressions supplied by a peer.

PolyMesh does not replace TLS certificate validation, identity enrollment, key
storage, endpoint allowlists, firewall policy, or network segmentation.

PolyMesh does not guarantee exactly-once effects across crashes, partitions, or
loss of durable state.

PolyMesh does not guarantee that an approved recipient will keep data private
after it receives that data.

PolyMesh does not provide a general browser security model; browser-originated
connections need a separately designed and reviewed profile.

PolyMesh does not provide payment, billing, legal authorization, consent capture,
content safety, malware detection, or business-logic validation.

PolyMesh does not protect against a hostile administrator, kernel compromise, or
physical compromise of a host that can read process memory and secrets.

PolyMesh does not make an external large-language model a suitable authorization,
redaction, policy, or confidential-computing boundary.

Security-sensitive deployments must add controls above and below the protocol.

## Secure defaults

Use these defaults unless you have a documented reason to do otherwise.

- Bind development listeners to a numeric loopback address only.

- Keep LAN, remote, automatic discovery, and browser access disabled by default.

- Start from deny-by-default authorization policy.

- Grant one capability at a time to one verified principal at a time.

- Treat write, network, shell, process, MCP, approval, and credential-bearing
  capabilities as high risk.

- Require a target instance for sensitive work when multiple instances could
  satisfy an agent identity.

- Use short task deadlines, small input limits, small result limits, and bounded
  concurrency.

- Separate broker, policy store, worker, and privileged resource identities.

- Store runtime credentials in owner-only files or an operating-system key store;
  never in source code, environment dumps, command lines, or URLs.

- Require encrypted transport and verified peer identity before enabling a LAN
  or remote endpoint.

- Disable compression, redirect following, and speculative endpoint dialing in
  security-sensitive transports.

- Log security-relevant metadata, but do not log raw secrets or task payloads.

- Rotate credentials and test revocation before a real incident requires them.

## Deployment security checklist

Complete and record this checklist before putting an agent near real data or
privileged operations.

### Host and account checklist

- [ ] The host has current operating-system security updates.

- [ ] The service runs under a dedicated non-administrator account.

- [ ] The account has no interactive shell unless genuinely needed.

- [ ] Home directories, runtime directories, and secret directories are not
  group- or world-readable.

- [ ] Parent directories of sockets, tokens, and certificates are owned by the
  expected service account and are not symlinks.

- [ ] Production services have a defined user, group, working directory, and
  umask.

- [ ] The process has a restrictive file-creation mask such as `077`.

- [ ] The service receives only the filesystem mounts it needs.

- [ ] Writable project directories are not also trusted executable search paths.

- [ ] The service does not inherit developer SSH agents, cloud credentials,
  browser profiles, or broad environment variables.

- [ ] Core dumps are disabled or protected so they cannot expose credentials or
  task data.

- [ ] Process inspection and debug interfaces are restricted to administrators.

- [ ] Production and development accounts are separated.

### Network checklist

- [ ] A development listener is bound to a numeric loopback address, not a
  wildcard address.

- [ ] Firewall rules permit only intended source networks and ports.

- [ ] No development endpoint is published through DNS, mDNS, a proxy, tunnel,
  port-forward, or container port mapping.

- [ ] LAN and remote endpoints use encrypted transport with current certificate
  validation and identity verification.

- [ ] The deployment does not downgrade from encrypted transport to plaintext
  after an error.

- [ ] Reverse proxies, if used, are explicitly trusted and have a clear source
  network boundary.

- [ ] The proxy strips or rejects client-supplied forwarding headers unless it
  is responsible for setting them.

- [ ] WebSocket upgrade requests have bounded header size, count, URI length,
  and completion time.

- [ ] WebSocket extensions are disabled unless specifically reviewed and needed.

- [ ] Outbound access from workers is blocked by default and allowlisted by
  destination and protocol.

- [ ] Metadata services, loopback, link-local, and private-network destinations
  are blocked from untrusted network-capable handlers unless explicitly required.

### Identity and credential checklist

- [ ] Each production agent has a non-reused identity enrollment record.

- [ ] Policy grants reference verified principals, credentials, or enrolled keys;
  they do not rely only on names supplied in envelopes.

- [ ] Runtime tokens are generated with an operating-system CSPRNG.

- [ ] Tokens are fixed-length, high-entropy values and are not human passwords.

- [ ] Tokens never appear in URLs, query strings, fragments, command lines,
  cards, discovery records, telemetry, or logs.

- [ ] Token files are owner-only and are created without following symlinks.

- [ ] Credential rotation is serialized and tested.

- [ ] Revoked credentials and hard rotations terminate affected sessions.

- [ ] Certificate and key material has an inventory, owner, expiration date, and
  rotation plan.

- [ ] Private keys are protected by a suitable secret manager, keychain, HSM, or
  owner-only file with backup and recovery procedures.

### Policy and capability checklist

- [ ] Authorization defaults to deny.

- [ ] A malformed, missing, timed-out, or failed policy decision denies access.

- [ ] Capability rules use exact identifiers or a deliberately limited wildcard
  syntax.

- [ ] Any matching explicit deny takes precedence over allow rules.

- [ ] Every data-disclosing or side-effecting operation passes through one
  central authorization gate.

- [ ] Scoped grants have a capability-specific scope adapter, not generic JSON
  comparison.

- [ ] Scope adapters enforce limits at the actual filesystem, database, cloud,
  or tool access point.

- [ ] Maximum results, maximum bytes, pagination, runtime, and egress limits
  are enforced by the resource adapter.

- [ ] Sensitive actions require local confirmation or an equivalent independent
  approval step where appropriate.

- [ ] Unknown capabilities are treated as sensitive until explicitly classified.

- [ ] Each policy change is reviewed, versioned, and audited.

### Handler and data checklist

- [ ] Handler input is parsed, validated, and copied before execution.

- [ ] Untrusted or third-party handlers run in an OS-enforced low-privilege
  worker, container, VM, or separate host.

- [ ] Worker threads alone are not treated as a privilege boundary.

- [ ] Workers have CPU, memory, wall-time, process, filesystem, and network
  restrictions appropriate to the capability.

- [ ] Side-effecting handlers are idempotent where practical.

- [ ] Deadline expiry cancels work and prevents late results from being released.

- [ ] Progress messages cannot disclose raw sensitive data or bypass output
  filtering.

- [ ] Errors, status responses, caches, replays, and audit records are reviewed
  as data-bearing outputs.

- [ ] A filtering failure fails closed and does not release an unfiltered result.

- [ ] External summarization or AI processing receives only data that has already
  been deterministically minimized and redacted as needed.

### Operational checklist

- [ ] Alerts exist for authentication failures, policy denials, rate limiting,
  unusual task volume, queue saturation, and credential rotation failures.

- [ ] Logs have retention, access-control, and deletion policies.

- [ ] Audit records are protected from alteration by the normal application
  runtime identity.

- [ ] Backups of policy, enrollment, and audit material are encrypted and their
  restoration procedure is tested.

- [ ] An incident owner, escalation channel, and revoke/rotate procedure are
  documented.

- [ ] A staging environment is used to test upgrades and policy changes.

- [ ] The release and dependency inventory is retained for each deployment.

## Configuration hardening guide

Configuration must be treated as security-sensitive code.

Store it in version control or a managed configuration system, review changes,
and apply production configuration through a controlled deployment path.

Never accept policy, transport, endpoint, or secret configuration directly from
a peer-provided message, card, URL, or discovery advertisement.

### Listener binding

For local development, prefer an explicitly configured numeric loopback address.

Examples include `127.0.0.1` for IPv4 and `::1` for IPv6 when IPv6 loopback is
intentional and covered by the same host policy.

Avoid wildcard binds such as `0.0.0.0` and `::` for development services.

Do not infer that a listener is local because its advertised name contains
`localhost`; verify the actual bind address and firewall behavior.

In containers, a loopback bind is local to the container namespace. Review port
publishing, host networking, service meshes, and sidecars separately.

If a service needs LAN access, use a dedicated listener configuration rather than
loosening a development listener in place.

### Transport encryption

For LAN or remote deployments, require a modern encrypted WebSocket transport.

Use TLS 1.3 or newer when the runtime and peer support it.

Reject old TLS versions, certificate-verification bypasses, insecure test roots,
and silent fallback to plaintext after an encryption or identity failure.

Validate the certificate chain, expiration, key usage, and expected server name.

For a high-assurance deployment, also bind the peer to an enrollment record or
pin the expected subject public-key information using a carefully managed rotation
process.

Mutual TLS or a separately enrolled pairwise credential may be appropriate when
both peers need strong identity assurance.

A shared bearer token is not a substitute for per-agent identity enrollment.

Do not reuse a single deployment-wide shared secret as authorization proof for
many different agent identities.

Do not permit TLS 0-RTT application records for side-effecting protocol actions
unless a separately reviewed design makes replay safe.

### Runtime token handling

Treat a runtime token like a password with machine-grade entropy.

Generate it with the operating system’s cryptographically secure random source.

Decode and validate the expected fixed byte length before comparison.

Compare fixed-length decoded secret values using a constant-time primitive.

Reject absent, empty, malformed, default, or wrong-length values.

Send a loopback token only through the dedicated authentication mechanism defined
by the approved local transport profile.

Never put a token in:

- A WebSocket URL, query parameter, URL fragment, or redirect target.

- A command-line argument or shell history entry.

- An Agent Card, service advertisement, mDNS TXT record, or discovery document.

- An exception, client-visible error, analytics event, support bundle, or log.

- Source code, package metadata, test fixture intended for release, or image
  layer.

Prefer a securely opened token file, inherited file descriptor, platform keychain,
or a purpose-built secret manager integration over a raw environment variable.

If environment variables must be used temporarily, ensure they are not copied to
child processes, crash reports, diagnostics, or service-manager status output.

Rotate tokens on a schedule and immediately after suspected disclosure.

Use an overlap period only when it is short, monotonic-clock bounded, and the
previous credential is auditable and revocable.

### Agent identity

Logical agent names are routing labels, not credentials.

Authorize a peer only after its claimed identity is bound to a verified transport
principal, enrolled public key, client certificate, or trusted operating-system
credential suitable for the deployment.

Keep enrollment records separate from untrusted cards and discovery data.

An enrollment record should at minimum define:

- The approved logical agent identity.

- The credential or public-key identifier.

- The permitted authentication strength and transport profile.

- The status, creation date, rotation history, and revocation state.

- Any expected certificate names, pinning material, or network scope.

- The policy principal that authorization rules should reference.

Treat an unexpected key for an existing logical identity as a security event, not
a routine restart.

Treat a new instance identifier as freshness information, not as proof of identity.

Require explicit policy for concurrent instances of an identity, especially when
they may receive write, approval, or execution-capable tasks.

### Authorization policy

Use a policy language and storage model that can be audited and evaluated
deterministically.

An authorization decision should be a validated discriminated value with an
explicit `allow` or `deny` effect.

Do not use language truthiness, implicit defaults, exception behavior, or missing
fields as authorization signals.

An invalid decision, policy timeout, database failure, cancellation, or unknown
principal must deny access.

Start with no grants, then add narrowly scoped rules after testing them.

Prefer one explicit rule such as “this verified build agent may read these paths”
over a broad rule such as “all local agents may invoke any file capability.”

Review wildcard grants carefully. A wildcard that is safe for read-only known
capabilities may be unsafe for future write, network, approval, or execution
capabilities.

Require a separate explicit grant for high-impact capabilities even if a wildcard
would otherwise match them.

### Resource scopes

Resource scopes must be interpreted by the component that actually accesses the
resource.

For a file capability, canonicalize the requested path, enforce permitted roots,
and apply an explicit symlink policy before opening the file.

For a database capability, inject tenant and object constraints into a parameterized
query or a database row-level-security policy rather than filtering records after
fetching them.

For a calendar, email, or messaging capability, validate account, mailbox,
calendar, folder, recipient, and pagination constraints before calling the API.

For a shell capability, use an allowlisted program with fixed argument validation,
a low-privilege working directory, bounded runtime, and no inherited credentials.

For a network capability, validate scheme, hostname, resolved address, redirects,
proxy behavior, and destination class before each outbound connection.

Missing, ambiguous, dynamic, or unprovable selectors should deny a scoped request.

Never treat a generic JSON field match as proof that a resource request is safe.

### Policy storage

Use parameterized SQL or an equivalent safe query API for every value.

Never construct SQL, JSON paths, regular expressions, table names, columns, sort
orders, or query fragments from an envelope, card, task parameter, filter, or
untrusted policy field.

Validate and canonicalize resource-scope documents at policy-write time.

Bound policy rule count, scope size, priority range, wildcard complexity, and
evaluation time.

Use indexes or a compiled policy cache so that a flood of requests cannot turn
policy evaluation into an unbounded scan and sort operation.

Record policy generation with each decision so that operators can trace which
rules authorized a task.

### Authorization leases and revocation

For sensitive operations, make authorization, task admission, audit recording,
and issuance of an authorization lease one atomic decision.

The resource adapter should verify that lease before each sensitive access and
before releasing an unsent result.

Revocation should prevent queued work from starting and prevent a stale result
from being released after policy changes.

Re-authorize and re-filter replayed artifacts under current policy unless the
artifact is already recipient-specific and protected by a still-valid lease.

Recheck deadline and cancellation state after delayed authorization and before
starting the handler.

## Data protection and privacy

Assume task data may be sensitive even when the protocol metadata appears benign.

An agent might receive personal data, source code, credentials, customer records,
operational details, or regulated information through input, output, progress,
errors, caches, and logs.

Apply data minimization at the source resource adapter whenever possible.

Fetch only the records, fields, bytes, and time range that the authorized request
needs.

Create recipient-specific outputs before they enter outboxes, caches, retries,
replay storage, status endpoints, or external processing services.

Do not rely on an LLM as the sole privacy filter or authorization mechanism.

If an external model is permitted to summarize data, structurally minimize and
redact the data first, verify the provider agreement and data residency, then
validate and filter returned text again before release.

### Deterministic filters

Use a small, implementation-owned set of deterministic, versioned output filters.

Examples include field omission, fixed structural redaction, recipient-specific
projection, count limiting, and bounded summary templates.

Do not accept JavaScript, JSONata, shell, templates, URLs, SQL, or other executable
filter source from policy records or peers.

Language-level sandboxes are not a sufficient boundary for arbitrary filtering
code that can access process state, filesystem data, environment variables, or
network resources.

If custom filters are ever necessary, place them in an independently managed,
OS-enforced sandbox with no ambient credentials, no network, no process creation,
minimal read-only input, bounded memory, bounded CPU, bounded output, and hard
wall-time termination.

### Logging and privacy

Logs are part of the attack surface.

Log enough structured metadata to investigate security events without copying
raw task inputs, outputs, tokens, credentials, private keys, cookies, or full
third-party responses into logs.

Recommended security event fields include:

- Timestamp from a trusted local clock.

- Deployment and service identity.

- Verified principal identifier and authentication strength.

- Policy generation, rule identifier, capability identifier, and decision.

- A task or message correlation identifier that does not expose secret contents.

- Result category, error code, rate-limit outcome, duration, and byte counts.

- A hash or privacy-safe reference to an approved scope where useful.

Sanitize error messages before exposing them to peers or operators with broad log
access.

Do not expose stack traces, filesystem paths, provider response bodies, URLs with
credentials, tokens, or raw exception text to an untrusted peer.

Restrict access to logs, set retention limits, encrypt backups, and test deletion
and incident-preservation procedures.

## Known attack surface

The following interfaces should receive deliberate review in every deployment.

| Surface | What can go wrong | Deployment guidance |
| --- | --- | --- |
| WebSocket listener | Upgrade smuggling, cross-site WebSocket access, malformed frames, connection floods | Bind narrowly; enforce strict upgrade validation; reject unsolicited browser origins; set limits before allocation |
| HTTP discovery endpoint | Endpoint enumeration, redirect abuse, cache poisoning, metadata leakage | Keep optional; return minimal non-secret hints; use HTTPS; do not follow redirects automatically |
| mDNS and DNS-SD | Spoofed advertisements, cache floods, cross-interface routing | Treat as non-authoritative discovery only; require explicit approval and verified encrypted identity before connection |
| Unix-domain socket path | Symlinks, unsafe runtime directory, wrong UID, stale cleanup | Use owner-only verified directories, descriptor-relative operations, and peer credential checks where available |
| Runtime token | URL leakage, accidental logging, weak files, comparison side channels | Never place it in a URL; use fixed-length secret handling, owner-only storage, rotation, and constant-time comparison |
| Agent Card | Oversized schemas, duplicate capabilities, untrusted endpoints, misleading labels | Parse with strict size/depth limits; validate identity separately; never let a card grant authority |
| Task envelope | Duplicate keys, unknown fields, replay, target confusion, deadline manipulation | Use strict bounded parsing, closed schemas, verified route context, durable replay controls, and monotonic expiry |
| Capability schema | Incomplete validation, unsafe regular expressions, remote references | Use a complete bounded validator or a clearly restricted profile; reject unsupported constructs |
| Policy API and database | SQL injection, wildcard bypass, fail-open results, TOCTOU | Use parameterized queries, explicit decisions, deny precedence, leases, transactions, and least-privilege database roles |
| Resource adapter | Path traversal, tenant escape, pagination bypass, SSRF | Canonicalize selectors and enforce scope at the point of resource access |
| Handler process | Command injection, secret access, hangs, late effects | Use separate low-privilege workers with wall-time and resource limits |
| Output filtering | Exfiltration through result, progress, status, replay, or errors | Apply recipient-specific filtering to every data-bearing artifact; fail closed on filter failure |
| Outbound queue | Slow consumer memory growth, retry storms, terminal-message loss | Bound bytes and messages; reserve control capacity; close slow peers; preserve durable terminal state |
| Audit log | Tampering, deletion, data leakage, misleading history | Restrict writers; use append-only chained integrity records and separate sealing where needed |
| CI and release pipeline | Malicious dependency, compromised build agent, secret leak | Isolate CI, pin dependencies, protect release credentials, produce provenance and review artifacts |

### WebSocket upgrade hardening

For an HTTP/1.1 WebSocket listener, accept only a canonical upgrade request.

Require `GET`, the exact configured path, one valid host, a valid WebSocket upgrade
token, a valid connection upgrade token, one valid key, version 13, and exactly
one supported PolyMesh subprotocol.

Reject request bodies, transfer encodings, nonzero content lengths, obsolete
header folding, duplicate security-sensitive headers, unexpected extensions, and
ambiguous proxy framing before allocating an application session.

Cap header bytes, header count, URI length, header completion time, request time,
keep-alive time, backlog, and simultaneous upgrades.

Reject browser `Origin` headers unless a separately reviewed browser profile
explicitly allows an exact origin. Origin checks are defense in depth, not
authentication.

Do not enable compression by default for security-sensitive protocol messages.

### Frame and JSON hardening

Set an upper bound on the complete serialized frame, not just the result object.

Use strict UTF-8 decoding and reject binary frames unless a separately specified
binary profile exists.

Use a parser that rejects duplicate object member names before application objects
are constructed.

Enforce depth, total node count, object member count, array length, string length,
identifier length, schema length, card size, endpoint count, and capability count.

Avoid recursive operations over untrusted JSON unless their depth and work budget
are independently bounded.

Treat parser, canonicalization, schema-validation, and filter budget exhaustion
as a controlled resource error, never a process crash.

### Discovery and endpoint selection

Discovery records are endpoint hints, not authority.

They must never create, rotate, replace, or authorize an agent identity,
certificate pin, permission, or transport-security profile.

Do not automatically connect merely because an advertisement was received.

Require an explicit local enrollment or operator-approved policy before first use.

Resolve a discovered hostname in a bounded, interface-aware way, validate selected
literal addresses against the intended network scope, and connect to the validated
literal address without an unconstrained second resolution.

Reject destinations that are not explicitly allowed, including unwanted loopback,
link-local, metadata-service, public, private, or cross-interface addresses.

Reject endpoint URLs with userinfo, fragments, unsupported schemes, unexpected
query fields, path escapes, or credentials.

Never send a loopback credential to a discovered, card-derived, LAN, or remote
endpoint.

## Security testing

Security testing should be continuous and should exercise the deployed transport,
policy store, worker environment, and resource adapters—not only in-memory mocks.

### Required test categories

- Unit tests for parsing, authorization, scope enforcement, policy precedence,
  filtering, lifecycle validation, replay handling, and audit-chain verification.

- Integration tests with a real database account using least-privilege grants.

- Integration tests with actual TLS configuration, certificate validation, pin
  mismatch, expired certificates, wrong names, and downgrade attempts.

- Tests of operating-system permissions, unsafe runtime directories, symlink
  races, peer credential failures, and container network exposure.

- Deterministic race tests for credential rotation, revocation, cancellation,
  timeout, replay, policy changes, result release, and audit ordering.

- Load and soak tests that measure heap, CPU, file descriptors, queue length,
  timers, database rows, and worker processes under hostile traffic.

- End-to-end tests that verify a recipient cannot receive unfiltered data through
  progress, errors, status, cached results, or replay.

### Security invariants

Maintain property tests or equivalent regression tests for these invariants.

- Only a valid explicit allow decision can invoke a handler.

- An unverified identity claim cannot receive a privileged per-agent grant.

- A matching deny rule always wins over an allow rule.

- A narrower scope or lower limit cannot disclose more resources or bytes.

- An unrelated principal cannot settle, cancel, replay, or alter a task.

- A duplicate message with the same semantic digest does not re-execute work.

- Reuse of a message or idempotency key with changed semantics conflicts.

- No task begins after monotonic expiry.

- No task has more than one terminal transition.

- A parser, schema, filter, or queue input cannot exceed its configured budget.

- A filter failure never releases an unfiltered artifact.

- Revocation prevents new sensitive access and unsent result release.

- Audit verification detects deletion, mutation, insertion, or reordering.

When a security defect is fixed, add a permanent regression test before closing
the issue.

## Dependency, build, and release security

Dependencies are part of PolyMesh’s security boundary.

Pin and review dependency changes, including transitive dependencies that parse
network data, implement cryptography, handle WebSockets, discover services,
validate schemas, or package release artifacts.

Use lockfiles in CI and production builds.

Run vulnerability scanning as one input to review, but do not treat a clean scan
as proof that a dependency is safe.

Maintain an SBOM or equivalent dependency inventory for released artifacts.

Review licenses, maintenance status, provenance, and known security posture of
critical dependencies.

Protect CI secrets and release credentials with least privilege, short-lived
tokens where possible, MFA, protected branches, and separate environments.

Build releases from reviewed commits in a controlled environment.

Produce checksums and, where the release process supports it, signed provenance
or attestations that users can verify.

Do not publish local credentials, test certificates, private configuration,
internal threat-model material, or developer runtime files in source archives,
packages, container images, examples, or release notes.

Before a release, review the diff for accidental secret exposure, new network
listeners, changed defaults, changed wildcard behavior, new dependencies, and
changes to high-risk handlers.

## Audit and accountability

For sensitive deployments, audit records should cover authorization decisions,
policy mutations, scope violations, filter failures, handler starts, terminal
outcomes, cancellations, enrollment changes, credential rotation, and
administrative actions.

Use append-only structured events with a monotonic sequence and a chain of
canonical record digests.

Where the threat model requires it, protect integrity with a signing or HMAC key
outside the ordinary policy database and application process, and periodically
seal records to an independent append-only or WORM destination.

The normal application execution identity should not be able to update or delete
audit records.

Avoid storing full task contents in audit data. Store privacy-safe identifiers,
scope hashes, decision metadata, and references to separately protected evidence.

If required audit persistence or sealing is unavailable, fail closed for actions
whose risk model depends on reliable accountability.

## Operational monitoring and response

Monitoring should detect both attacks and safety regressions.

Track rates and anomalies for:

- Failed authentication and unknown-principal attempts.

- Certificate, pin, enrollment, and credential-rotation failures.

- Policy denials, scope violations, approval rejections, and policy-store errors.

- Malformed frames, parser limits, invalid card updates, and protocol violations.

- Connection counts, handshake timeouts, queue high-water marks, slow consumers,
  file descriptor use, worker saturation, and task timeouts.

- Discovery floods, unexpected endpoint changes, cross-interface candidates, and
  blocked outbound destinations.

- Replays, idempotency conflicts, lifecycle conflicts, late results, and
  cancellation ownership failures.

- Administrative changes, policy generation changes, enrollment changes, and
  secret-access events.

Avoid paging on every expected denial. Alert on unusual rates, new sources,
correlated failures, loss of audit integrity, or meaningful deviation from a
known baseline.

### Incident response playbook

Keep a tested incident playbook. A minimal sequence is:

1. Establish an incident owner and a secure communication channel.

2. Preserve relevant logs, audit records, configuration versions, deployment
   metadata, and volatile evidence according to your legal and privacy rules.

3. Contain exposure by disabling the affected listener, policy grant, worker,
   endpoint, or integration.

4. Revoke or rotate credentials that may be exposed, including runtime tokens,
   certificates, enrollment keys, API keys, and cloud credentials.

5. Stop or fence affected workers so they cannot release late output.

6. Identify affected principals, tasks, data categories, actions, hosts, and
   versions using privacy-safe audit data.

7. Eradicate the root cause, validate a fix in staging, and deploy through the
   normal reviewed release path.

8. Re-authorize queued and replayed work under the new policy before resuming it.

9. Notify affected users, partners, and authorities when required by law,
   contract, or policy.

10. Document lessons learned, add tests and monitoring, and update this guidance
    or deployment runbooks as appropriate.

## Upgrade and change management

Treat protocol, transport, identity, and policy changes as security-sensitive.

Read release notes and migration guidance before upgrading.

Test upgrades in staging with representative credentials, policies, certificates,
network paths, handlers, resource adapters, and failure scenarios.

Do not silently downgrade a peer to a weaker transport or authentication profile
after an upgrade failure.

Use explicit configuration to allow a legacy profile during a time-bounded
migration, document the risk acceptance, and remove it after the migration.

Version and review policy changes separately from application code changes.

For high-impact changes, use dual control or an approval workflow.

Keep a rollback plan that does not reintroduce compromised credentials, unsafe
defaults, or an obsolete vulnerable build.

## Contact and policy updates

This policy may change as PolyMesh matures, new transport profiles are introduced,
or operational experience identifies better practices.

The version of `SECURITY.md` in the repository is the current public security
guidance for that source revision.

For a vulnerability report, use the private reporting channel described above.

For deployment-specific assurance, conduct a review of the exact version,
configuration, infrastructure, handlers, dependencies, and data flows you intend
to use.

Security is a shared responsibility between the project, deployers, integrators,
and every authority-bearing agent in the system.
