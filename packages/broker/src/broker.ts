/**
 * WebSocket router for the PolyMesh reference implementation.
 *
 * This deliberately stays a router: task execution and task persistence live
 * in agents.  The broker authenticates a connection, performs the mandatory
 * hello/card/ready exchange, records the live agent lease, then forwards
 * validated envelopes without rewriting their sender or recipient fields.
 */

import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { createServer as createSecureServer, type Server as HttpsServer } from "node:https";
import { isIP, type AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import type { TlsOptions } from "node:tls";
import WebSocket, { WebSocketServer } from "ws";

import {
  MAX_FRAME_BYTES,
  MAX_ROUTED_PROVENANCE_LIFETIME_MS,
  PROTOCOL_VERSION,
  SECURE_IDENTITY_PROFILE,
  EnrollmentStore,
  ProtocolError,
  authTranscript,
  capabilityContractTuple,
  cardDigest,
  canonicalize,
  createRoutedProvenance,
  envelopeSemanticDigest,
  createAuthProof,
  createCardIdentityFromPrivateKey,
  deriveSessionId,
  isAgentCard,
  isCapabilityContractTuple,
  isEnvelope,
  parseStrictJson,
  randomInstanceId,
  randomNonce,
  signAgentCard,
  uuidv7,
  verifyAuthProof,
  verifyEnrolledCard,
  type AgentCard,
  type AuthFrame,
  type CardIdentity,
  type CardFrame,
  type CapabilityContractTuple,
  type Ed25519PrivateKey,
  type Enrollment,
  type Envelope,
  type EnvelopeType,
  type HelloFrame,
  type ReceiptDisposition,
  type ReadyFrame,
  type VerifiedPrincipal,
  type WireTransport,
  validateHandshakeFrame,
} from "./protocol.js";
import { DuplicateAgentError, Registry, type RegistryEntry } from "./registry.js";
import {
  RuntimeTokenAuthority,
  normalizePeerClose,
  tlsChannelBinding,
  validateWebSocketUpgrade,
  type TokenRotationOptions,
} from "./security.js";

export const POLYMESH_PATH = "/polymesh";
export const HANDSHAKE_TIMEOUT_MS = 5_000;
export const DEFAULT_HTTP_HEADER_BYTES = 8 * 1024;
export const DEFAULT_HTTP_HEADER_COUNT = 64;
export const DEFAULT_HTTP_HEADER_TIMEOUT_MS = 5_000;
export const DEFAULT_HTTP_REQUEST_TIMEOUT_MS = 10_000;
/** Admission-control defaults. These are hard ceilings, not advisory hints. */
export const DEFAULT_MAX_PENDING_HANDSHAKES = 8;
export const DEFAULT_MAX_OPEN_SESSIONS = 32;
export const DEFAULT_MAX_PENDING_TASK_ROUTES = 1_024;
export const DEFAULT_MAX_PENDING_TASK_ROUTES_PER_SESSION = 32;
export const DEFAULT_MAX_REPLAY_LEDGER_ENTRIES = 4_096;
export const DEFAULT_MAX_LIFECYCLE_EVENTS_PER_ROUTE = 256;
export const MIN_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1_000;

/** TLS material for the enrolled mutual-TLS transport profile. */
export interface BrokerTlsOptions extends TlsOptions {
  key: NonNullable<TlsOptions["key"]>;
  cert: NonNullable<TlsOptions["cert"]>;
}

/** Local material required for the fail-closed enrolled-key WSS profile. */
export interface BrokerIdentityOptions {
  privateKey: Ed25519PrivateKey;
  /** Explicit local enrollment. Cards and mDNS records never add entries. */
  enrollments: EnrollmentStore | readonly Enrollment[];
}

type JsonRecord = Record<string, unknown>;

/** The minimum send/receive surface shared by `ws` and WireTransport. */
export interface BrokerTransport {
  send(data: string, ...args: unknown[]): unknown;
  close?(code?: number, reason?: string): unknown;
  terminate?(): unknown;
  on?(event: string, listener: (...args: any[]) => void): unknown;
  onMessage?(listener: (data: string) => void): unknown;
  onClose?(listener: (reason?: unknown) => void): unknown;
  onError?(listener: (error: Error) => void): unknown;
  readyState?: number;
}

export interface BrokerOptions {
  port?: number;
  host?: string;
  /** Exactly 32 CSPRNG bytes, encoded as unpadded base64url. */
  token?: string;
  /** TLS 1.3 mutual-authentication listener configuration for LAN/remote use. */
  tls?: BrokerTlsOptions;
  /** Required whenever a TLS listener is enabled. */
  identity?: BrokerIdentityOptions;
  /**
   * Permit `ws://` only for an explicitly selected numeric-loopback
   * development listener. It still requires a runtime token.
   */
  allowInsecureLoopbackDevelopment?: boolean;
  /** Exact browser origins permitted to make a WebSocket upgrade. Empty by default. */
  allowedOrigins?: readonly string[];
  /** Identity presented by the broker during the card exchange. */
  card?: AgentCard;
  agentId?: string;
  instanceId?: string;
  registry?: Registry<BrokerPeer, AgentCard>;
  ttlMs?: number;
  handshakeTimeoutMs?: number;
  maxFrameBytes?: number;
  maxHttpHeaderBytes?: number;
  maxHttpHeaderCount?: number;
  httpHeaderTimeoutMs?: number;
  httpRequestTimeoutMs?: number;
  /** Maximum transport connections still completing hello/card/ready. */
  maxPendingHandshakes?: number;
  /** Maximum concurrent inbound sessions, including handshakes. */
  maxOpenSessions?: number;
  /** Maximum retained task-route records. New work is rejected before allocation. */
  maxPendingTaskRoutes?: number;
  /** Maximum live task routes attributable to one authenticated session. */
  maxPendingTaskRoutesPerSession?: number;
  /** Maximum replay-ledger entries retained in this broker process. */
  maxReplayLedgerEntries?: number;
  /** Maximum lifecycle records retained for a single route. */
  maxLifecycleEventsPerRoute?: number;
  /** Replay and terminal-tombstone retention. Values below 24 hours are raised to the protocol minimum. */
  replayRetentionMs?: number;
  now?: () => number;
  onPeerConnected?: (peer: BrokerPeer) => void;
  onPeerDisconnected?: (peer: BrokerPeer, reason?: unknown) => void;
  onEnvelope?: (envelope: Envelope, peer: BrokerPeer) => void;
}

export interface AttachOptions {
  /** Used only for a pre-existing non-HTTP transport. */
  token?: string;
}

export type PeerPhase = "await_hello" | "await_card" | "await_auth" | "await_ready" | "active" | "closed";

export interface BrokerPeer {
  transport: BrokerTransport;
  phase: PeerPhase;
  authenticated: boolean;
  /** Runtime-token epoch that admitted this session, never a claimed identity. */
  authEpoch?: number;
  /** Enrolled principal after the TLS-bound Ed25519 proof has verified. */
  verifiedPrincipal?: VerifiedPrincipal;
  agentId?: string;
  instanceId?: string;
  card?: AgentCard;
  cardDigest?: string;
  sessionId?: string;
  initiatorNonce?: string;
  responderNonce?: string;
  initiatorHello?: Extract<HelloFrame, { role: "initiator" }>;
  responderHello?: Extract<HelloFrame, { role: "responder" }>;
  leaseId?: string;
  connectedAt: number;
}

interface TaskRoute {
  taskId: string;
  /** Exact capability contract pinned by the owner and admitted by the executor. */
  contract: CapabilityContractTuple;
  owner: { agentId: string; instanceId: string; sessionId?: string };
  executor: { agentId: string; instanceId: string; sessionId?: string };
  submitMessageId: string;
  /** Every equivalent retransmission that may receive admission correlation. */
  submitMessageIds: Set<string>;
  createdAt: number;
  deadline?: string;
  immutableFingerprint: string;
  /** State is advanced only by an exact, causally valid lifecycle record. */
  lifecycle: "submitted" | "accepted" | "rejected" | "completed" | "closed";
  nextEventSeq: number;
  events: Map<number, string>;
  capacityReserved: boolean;
  retainedUntil: number;
}

interface ReplayLedgerRecord {
  semanticDigest: string;
  expiresAt: number;
}

interface PreAuthenticatedTransport {
  /** Undefined for the mTLS + enrolled-key profile; tokens are loopback-only. */
  authEpoch?: number;
  /** An HTTP upgrade capacity reservation held until attach consumes it. */
  reservedHandshake: boolean;
}

function dateFromNow(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function defaultBrokerCard(agentId: string, instanceId: string): AgentCard {
  return {
    card_version: "1.0",
    agent_id: agentId,
    instance_id: instanceId,
    display_name: "PolyMesh Broker",
    issued_at: new Date().toISOString(),
    // A broker is normally long-lived, but a finite expiry keeps the card
    // schema honest and gives reconnecting peers a refresh point.
    expires_at: dateFromNow(24 * 60 * 60 * 1_000),
    revision: 1,
    capabilities: [
      { id: "org.polymesh.agent.ping", version: "1.0.0" },
      { id: "org.polymesh.agent.info", version: "1.0.0" },
      { id: "org.polymesh.capabilities.list", version: "1.0.0" },
    ],
  };
}

function websocketStateOpen(transport: BrokerTransport): boolean {
  // `readyState` is absent on the in-memory transport.  ws.OPEN is 1.
  return transport.readyState === undefined || transport.readyState === WebSocket.OPEN;
}

function asFrameInput(data: unknown): string | Uint8Array | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return undefined;
}

function frameByteLength(input: string | Uint8Array): number {
  return typeof input === "string" ? Buffer.byteLength(input, "utf8") : input.byteLength;
}

function taskIdOf(envelope: Envelope): string | undefined {
  const value = (envelope.params as JsonRecord | undefined)?.task_id;
  return typeof value === "string" ? value : undefined;
}

function taskContractOf(envelope: Envelope<"task.submit"> | Envelope): CapabilityContractTuple | undefined {
  const params = envelope.params as JsonRecord;
  const candidate = {
    capability_id: envelope.type === "task.submit" ? params.method : params.capability_id,
    capability_version: params.capability_version,
    capability_contract_digest: params.capability_contract_digest,
  };
  return isCapabilityContractTuple(candidate) ? candidate : undefined;
}

function sameCapabilityContract(left: CapabilityContractTuple, right: CapabilityContractTuple): boolean {
  return left.capability_id === right.capability_id &&
    left.capability_version === right.capability_version &&
    left.capability_contract_digest === right.capability_contract_digest;
}

function isLifecycle(type: EnvelopeType): boolean {
  return type === "task.accepted" || type === "task.rejected" || type === "task.progress" || type === "task.completed";
}

/** Records whose claimed remote source can change task or policy state. */
function requiresRoutedProvenance(type: EnvelopeType): boolean {
  return type === "task.submit" || type === "task.cancel" || isLifecycle(type) || type === "error";
}

/**
 * A local WebSocket router.  `start()` is idempotent and returns the broker so
 * callers can write `await new Broker({ port: 0 }).start()`.
 */
export class Broker {
  readonly options: Readonly<BrokerOptions>;
  readonly card: AgentCard;
  readonly cardDigest: string;
  readonly registry: Registry<BrokerPeer, AgentCard>;

  private readonly now: () => number;
  private readonly handshakeTimeoutMs: number;
  private readonly maxFrameBytes: number;
  private readonly maxHttpHeaderBytes: number;
  private readonly maxHttpHeaderCount: number;
  private readonly httpHeaderTimeoutMs: number;
  private readonly httpRequestTimeoutMs: number;
  private readonly maxPendingHandshakes: number;
  private readonly maxOpenSessions: number;
  private readonly maxPendingTaskRoutes: number;
  private readonly maxPendingTaskRoutesPerSession: number;
  private readonly maxReplayLedgerEntries: number;
  private readonly maxLifecycleEventsPerRoute: number;
  private readonly replayRetentionMs: number;
  private readonly allowedOrigins: readonly string[];
  private readonly tokenAuthority?: RuntimeTokenAuthority;
  private readonly identityProfile?: {
    privateKey: Ed25519PrivateKey;
    enrollments: EnrollmentStore;
    identity: CardIdentity;
    localPrincipal: VerifiedPrincipal;
  };
  private readonly peers = new Set<BrokerPeer>();
  private readonly pendingTasks = new Map<string, TaskRoute>();
  private readonly routesBySubmitMessageId = new Map<string, string>();
  /** Per-session reservations for live routes. Terminal tombstones do not consume them. */
  private readonly pendingRoutesBySession = new Map<string, number>();
  /** Message-id reuse protection. This is recorded before forwarding a valid envelope. */
  private readonly replayLedger = new Map<string, ReplayLedgerRecord>();
  private readonly handshakeTimers = new WeakMap<BrokerPeer, ReturnType<typeof setTimeout>>();
  private readonly preAuthenticatedTransports = new WeakMap<object, PreAuthenticatedTransport>();
  /** Upgrades reserved before WebSocket allocation, then consumed by attach. */
  private pendingUpgradeReservations = 0;
  private server?: HttpServer | HttpsServer;
  private wsServer?: WebSocketServer;
  private cleanupTimer?: ReturnType<typeof setInterval>;
  private tokenRotationTimer?: ReturnType<typeof setTimeout>;
  private closing = false;

  constructor(options: BrokerOptions = {}) {
    this.options = { ...options };
    this.now = options.now ?? Date.now;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    this.maxFrameBytes = options.maxFrameBytes ?? MAX_FRAME_BYTES;
    this.maxHttpHeaderBytes = options.maxHttpHeaderBytes ?? DEFAULT_HTTP_HEADER_BYTES;
    this.maxHttpHeaderCount = options.maxHttpHeaderCount ?? DEFAULT_HTTP_HEADER_COUNT;
    this.httpHeaderTimeoutMs = options.httpHeaderTimeoutMs ?? DEFAULT_HTTP_HEADER_TIMEOUT_MS;
    this.httpRequestTimeoutMs = options.httpRequestTimeoutMs ?? DEFAULT_HTTP_REQUEST_TIMEOUT_MS;
    this.maxPendingHandshakes = options.maxPendingHandshakes ?? DEFAULT_MAX_PENDING_HANDSHAKES;
    this.maxOpenSessions = options.maxOpenSessions ?? DEFAULT_MAX_OPEN_SESSIONS;
    this.maxPendingTaskRoutes = options.maxPendingTaskRoutes ?? DEFAULT_MAX_PENDING_TASK_ROUTES;
    this.maxPendingTaskRoutesPerSession = options.maxPendingTaskRoutesPerSession ?? DEFAULT_MAX_PENDING_TASK_ROUTES_PER_SESSION;
    this.maxReplayLedgerEntries = options.maxReplayLedgerEntries ?? DEFAULT_MAX_REPLAY_LEDGER_ENTRIES;
    this.maxLifecycleEventsPerRoute = options.maxLifecycleEventsPerRoute ?? DEFAULT_MAX_LIFECYCLE_EVENTS_PER_ROUTE;
    this.replayRetentionMs = Math.max(MIN_REPLAY_RETENTION_MS, options.replayRetentionMs ?? MIN_REPLAY_RETENTION_MS);
    this.allowedOrigins = Object.freeze([...(options.allowedOrigins ?? [])]);
    if (!Number.isInteger(this.maxFrameBytes) || this.maxFrameBytes <= 0 || this.maxFrameBytes > MAX_FRAME_BYTES) {
      throw new RangeError(`maxFrameBytes must be between 1 and ${MAX_FRAME_BYTES}`);
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshakeTimeoutMs must be a positive finite number");
    }
    if (!Number.isInteger(this.maxHttpHeaderBytes) || this.maxHttpHeaderBytes < 1_024) {
      throw new RangeError("maxHttpHeaderBytes must be an integer of at least 1024 bytes");
    }
    if (!Number.isInteger(this.maxHttpHeaderCount) || this.maxHttpHeaderCount < 1) {
      throw new RangeError("maxHttpHeaderCount must be a positive integer");
    }
    if (![this.httpHeaderTimeoutMs, this.httpRequestTimeoutMs].every((value) => Number.isFinite(value) && value > 0)) {
      throw new RangeError("HTTP timeouts must be positive finite durations");
    }
    if (this.httpHeaderTimeoutMs > this.httpRequestTimeoutMs) {
      throw new RangeError("httpHeaderTimeoutMs must not exceed httpRequestTimeoutMs");
    }
    if (![this.maxPendingHandshakes, this.maxOpenSessions, this.maxPendingTaskRoutes, this.maxPendingTaskRoutesPerSession, this.maxReplayLedgerEntries, this.maxLifecycleEventsPerRoute]
      .every((value) => Number.isInteger(value) && value > 0)) {
      throw new RangeError("broker admission limits must be positive integers");
    }
    if (!Number.isFinite(this.replayRetentionMs) || this.replayRetentionMs < MIN_REPLAY_RETENTION_MS) {
      throw new RangeError(`replayRetentionMs must be at least ${MIN_REPLAY_RETENTION_MS} ms`);
    }
    if (this.allowedOrigins.some((origin) => typeof origin !== "string" || origin.length === 0 || /[\r\n]/.test(origin))) {
      throw new TypeError("allowedOrigins must contain exact non-empty origin strings");
    }
    if (options.token !== undefined) this.tokenAuthority = new RuntimeTokenAuthority(options.token, this.now);

    const instanceId = options.instanceId ?? randomInstanceId();
    const agentId = options.agentId ?? "org.polymesh.broker";
    let localCard = options.card ?? defaultBrokerCard(agentId, instanceId);
    if (!isAgentCard(localCard)) throw new TypeError("Broker card is not a valid AgentCard");
    if (options.identity) {
      const enrollments = options.identity.enrollments instanceof EnrollmentStore
        ? options.identity.enrollments
        : new EnrollmentStore(options.identity.enrollments);
      const identity = createCardIdentityFromPrivateKey(options.identity.privateKey);
      if (localCard.identity !== undefined && (
        localCard.identity.key_id !== identity.key_id ||
        localCard.identity.public_key !== identity.public_key
      )) {
        throw new TypeError("Broker Card identity does not match the configured signing key");
      }
      localCard = signAgentCard(localCard, options.identity.privateKey);
      const localPrincipal = verifyEnrolledCard(localCard, enrollments, this.now());
      if (!localPrincipal) {
        throw new TypeError("The local signed Broker Card must be present in the enrolled identity store");
      }
      this.identityProfile = {
        privateKey: options.identity.privateKey,
        enrollments,
        identity,
        localPrincipal,
      };
    }
    this.card = localCard;
    this.cardDigest = cardDigest(localCard);
    this.registry = options.registry ?? new Registry<BrokerPeer, AgentCard>({ ttlMs: options.ttlMs, clock: this.now });
  }

  /** TCP port once started (including OS-assigned port for `port: 0`). */
  get port(): number | undefined {
    const address = this.server?.address();
    return typeof address === "object" && address ? address.port : undefined;
  }

  get host(): string {
    return this.options.host ?? "127.0.0.1";
  }

  get url(): string | undefined {
    const port = this.port;
    if (port === undefined) return undefined;
    const host = this.host.includes(":") ? `[${this.host}]` : this.host;
    return `${this.options.tls ? "wss" : "ws"}://${host}:${port}${POLYMESH_PATH}`;
  }

  /** Current token generation; useful for observability without exposing secret material. */
  get authEpoch(): number | undefined {
    return this.tokenAuthority?.authEpoch;
  }

  /**
   * Atomically rotate a loopback runtime token. Hard rotation immediately
   * tears down all authenticated sessions. Normal rotation permits the prior
   * token only during its bounded overlap and then tears down old-epoch peers.
   */
  rotateToken(token: string, options: TokenRotationOptions = {}): number {
    if (!this.tokenAuthority) throw new ProtocolError("AUTHENTICATION_FAILED", "No runtime token is configured", "identity");
    const epoch = this.tokenAuthority.rotate(token, options);
    if (this.tokenRotationTimer) clearTimeout(this.tokenRotationTimer);
    if (options.hard === true) {
      for (const peer of [...this.peers]) this.closePeer(peer, "credential rotated");
      return epoch;
    }
    const overlapMs = options.overlapMs ?? 30_000;
    this.tokenRotationTimer = setTimeout(() => {
      this.tokenAuthority?.clearExpiredPrevious();
      for (const peer of [...this.peers]) {
        if (peer.authEpoch !== undefined && peer.authEpoch < epoch) this.closePeer(peer, "credential rotated");
      }
    }, overlapMs);
    this.tokenRotationTimer.unref?.();
    return epoch;
  }

  address(): AddressInfo | string | null | undefined {
    return this.server?.address();
  }

  /** Snapshot of active, fully handshaken peers. */
  listPeers(): BrokerPeer[] {
    return this.registry.list().map((entry) => entry.transport).filter((peer): peer is BrokerPeer => peer !== undefined);
  }

  /** Start the HTTP/WebSocket listener. */
  async start(): Promise<this> {
    if (this.server?.listening) return this;
    if (this.server) throw new Error("Broker is already starting");
    this.closing = false;
    this.assertSecureListenerConfiguration();

    const requestListener = (request: IncomingMessage, response: import("node:http").ServerResponse) => this.handleHttp(request, response);
    const server = this.options.tls
      ? createSecureServer({
        ...this.options.tls,
        // Secure profiles do not negotiate below TLS 1.3 and require an
        // enrolled client certificate.  A PSK profile needs a separate,
        // authenticated transcript implementation and is intentionally not
        // silently substituted here.
        minVersion: "TLSv1.3",
        requestCert: true,
        rejectUnauthorized: true,
        enableTrace: false,
        requestTimeout: this.httpRequestTimeoutMs,
        headersTimeout: this.httpHeaderTimeoutMs,
        maxHeaderSize: this.maxHttpHeaderBytes,
        insecureHTTPParser: false,
      }, requestListener)
      : createServer({
        requestTimeout: this.httpRequestTimeoutMs,
        headersTimeout: this.httpHeaderTimeoutMs,
        maxHeaderSize: this.maxHttpHeaderBytes,
        insecureHTTPParser: false,
      }, requestListener);
    server.maxHeadersCount = this.maxHttpHeaderCount;
    server.headersTimeout = this.httpHeaderTimeoutMs;
    server.requestTimeout = this.httpRequestTimeoutMs;
    server.keepAliveTimeout = this.httpHeaderTimeoutMs;
    const wsServer = new WebSocketServer({
      noServer: true,
      maxPayload: this.maxFrameBytes,
      clientTracking: false,
      perMessageDeflate: false,
      // Never silently negotiate a caller's unrelated subprotocol just because
      // it appeared first in the header.
      handleProtocols: (protocols) => (protocols.has(PROTOCOL_VERSION) ? PROTOCOL_VERSION : false),
    });
    this.server = server;
    this.wsServer = wsServer;

    server.on("upgrade", (request, socket, head) => {
      // Some of the broader Node server typings permit an omitted `head`;
      // WebSocket upgrade processing treats that as an empty buffered tail.
      void this.handleUpgrade(request, socket, head ?? Buffer.alloc(0));
    });
    server.on("clientError", (_error, socket) => {
      // Do not reflect parser errors.  A terse response avoids turning the
      // HTTP parser into an oracle and releases the file descriptor promptly.
      this.rejectUpgrade(socket, 400, "Bad Request");
    });
    server.on("error", () => {
      // The listen promise and callers receive startup errors.  Runtime socket
      // errors are handled by ws/connection close events.
    });
    wsServer.on("connection", (socket, request) => {
      const transport = socket as unknown as BrokerTransport;
      const admission = this.consumePreAuthenticatedTransport(transport);
      if (!admission) {
        // A direct call to wsServer.emit("connection") is not an
        // authentication mechanism.  Fail closed if it bypassed validation.
        try {
          socket.close(1008, "authentication required");
        } catch {
          socket.terminate();
        }
        return;
      }
      this.attachPreAuthenticated(transport, admission.authEpoch, admission.reservedHandshake);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(this.options.port ?? 7337, this.host);
      });
    } catch (error) {
      this.wsServer = undefined;
      this.server = undefined;
      wsServer.close();
      server.close();
      if ((error as NodeJS.ErrnoException).code === "EADDRINUSE") {
        throw new ProtocolError("PORT_IN_USE", `Port ${this.options.port ?? 7337} is already in use`, "resource");
      }
      throw error;
    }

    const interval = Math.max(1_000, Math.min(this.registry.ttlMs / 2, 30_000));
    this.cleanupTimer = setInterval(() => this.cleanup(), interval);
    this.cleanupTimer.unref?.();
    return this;
  }

  /** Alias for integrations that call a server `listen` method. */
  listen(): Promise<this> {
    return this.start();
  }

  /**
   * Attach an already-created transport, primarily for deterministic in-memory
   * tests. It is deliberately token-authenticated too: a public
   * `authenticated: true` bypass would turn an adapter bug into a policy
   * bypass. The remote end must initiate the ordinary hello/card/ready flow.
   */
  attach(transport: BrokerTransport | WireTransport, options: AttachOptions = {}): BrokerPeer {
    const normalized = transport as unknown as BrokerTransport;
    const verification = this.tokenAuthority?.verify(options.token) ?? { valid: false };
    if (!verification.valid || verification.authEpoch === undefined) {
      return this.rejectAttachment(normalized, "AUTHENTICATION_FAILED", "A valid PolyMesh runtime token is required", "identity");
    }
    return this.attachPreAuthenticated(normalized, verification.authEpoch, false);
  }

  private attachPreAuthenticated(transport: BrokerTransport, authEpoch: number | undefined, consumesReservation: boolean): BrokerPeer {
    if (consumesReservation) this.releaseUpgradeReservation();
    if (!this.canAdmitPeer()) {
      return this.rejectAttachment(transport, "OVERLOADED", "Broker connection capacity is exhausted", "resource", true);
    }
    const peer: BrokerPeer = {
      transport,
      phase: "await_hello",
      authenticated: true,
      authEpoch,
      connectedAt: this.now(),
    };
    this.peers.add(peer);
    this.bindTransport(peer);
    this.handshakeTimers.set(
      peer,
      setTimeout(() => {
        if (peer.phase !== "active" && peer.phase !== "closed") {
          this.failHandshake(peer, "HANDSHAKE_TIMEOUT", "Handshake did not complete within five seconds", "protocol");
        }
      }, this.handshakeTimeoutMs),
    );
    return peer;
  }

  private consumePreAuthenticatedTransport(transport: BrokerTransport): PreAuthenticatedTransport | undefined {
    const target = transport as unknown as object;
    const admission = this.preAuthenticatedTransports.get(target);
    if (admission !== undefined) this.preAuthenticatedTransports.delete(target);
    return admission;
  }

  /** Alias that reads naturally in transport adapters. */
  accept(transport: BrokerTransport | WireTransport, options?: AttachOptions): BrokerPeer {
    return this.attach(transport, options);
  }

  /** Safely expire leases and task routing metadata. */
  cleanup(): void {
    const expired = this.registry.cleanup();
    for (const entry of expired) {
      const peer = entry.transport;
      if (peer && peer.phase !== "closed") this.closePeer(peer, "registry lease expired");
    }
    this.pruneRouteAndReplayState();
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = undefined;
    if (this.tokenRotationTimer) clearTimeout(this.tokenRotationTimer);
    this.tokenRotationTimer = undefined;

    for (const peer of [...this.peers]) this.closePeer(peer, "broker shutting down");
    this.registry.clear();
    this.pendingTasks.clear();
    this.routesBySubmitMessageId.clear();
    this.pendingRoutesBySession.clear();
    this.replayLedger.clear();

    const wsServer = this.wsServer;
    const server = this.server;
    this.wsServer = undefined;
    this.server = undefined;
    await Promise.all([
      wsServer
        ? new Promise<void>((resolve) => wsServer.close(() => resolve()))
        : Promise.resolve(),
      server
        ? new Promise<void>((resolve) => server.close(() => resolve()))
        : Promise.resolve(),
    ]);
  }

  private handleHttp(request: IncomingMessage, response: import("node:http").ServerResponse): void {
    if (request.url === "/.well-known/polymesh" && request.method === "GET") {
      const endpoint = this.url;
      response.writeHead(200, {
        "content-type": "application/polymesh+json; charset=utf-8",
        "cache-control": "max-age=60",
        ...(this.options.tls ? { "strict-transport-security": "max-age=31536000" } : {}),
      });
      response.end(
        JSON.stringify({
          v: "0.1",
          agent_id: this.card.agent_id,
          instance_id: this.card.instance_id,
          endpoints: endpoint ? [{ transport: "websocket", url: endpoint }] : [],
        }),
      );
      return;
    }
    response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "not found" }));
  }

  private async handleUpgrade(
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
  ): Promise<void> {
    if (request.url !== POLYMESH_PATH) {
      this.rejectUpgrade(socket, 404, "Not Found");
      return;
    }
    const upgrade = validateWebSocketUpgrade(request, {
      path: POLYMESH_PATH,
      subprotocol: PROTOCOL_VERSION,
      allowedOrigins: this.allowedOrigins,
    });
    if (!upgrade.ok) {
      this.rejectUpgrade(socket, upgrade.status, upgrade.statusText, upgrade.headers);
      return;
    }
    let authEpoch: number | undefined;
    if (this.options.tls) {
      const tlsSocket = request.socket as unknown as { authorized?: boolean; getProtocol?: () => string | null };
      // `rejectUnauthorized` performs the certificate check; this defensive
      // check makes a proxy/adapter that strips it fail closed as well.
      if (tlsSocket.authorized !== true || tlsSocket.getProtocol?.() !== "TLSv1.3") {
        this.rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
    } else {
      const verification = this.tokenAuthority?.verify(upgrade.token) ?? { valid: false };
      if (!verification.valid || verification.authEpoch === undefined) {
        this.rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
      authEpoch = verification.authEpoch;
    }
    const wsServer = this.wsServer;
    if (!wsServer) {
      this.rejectUpgrade(socket, 503, "Service Unavailable", { "Retry-After": "1" });
      return;
    }
    // Reserve before allocating WebSocket/session state. This closes the
    // gap where many valid HTTP upgrades could otherwise allocate sockets
    // before their handshake limits are checked.
    if (!this.reserveUpgradeAdmission()) {
      this.rejectUpgrade(socket, 429, "Too Many Requests", { "Retry-After": "1" });
      return;
    }
    try {
      wsServer.handleUpgrade(request, socket, head, (ws) => {
        this.preAuthenticatedTransports.set(ws as unknown as object, {
          ...(authEpoch === undefined ? {} : { authEpoch }),
          reservedHandshake: true,
        });
        wsServer.emit("connection", ws, request);
      });
    } catch {
      this.releaseUpgradeReservation();
      this.rejectUpgrade(socket, 400, "Bad Request");
    }
  }

  private bindTransport(peer: BrokerPeer): void {
    const transport = peer.transport;
    const onMessage = (data: unknown, isBinary?: boolean) => {
      if (isBinary) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Binary WebSocket frames are not supported", "parse");
        return;
      }
      const input = asFrameInput(data);
      if (input === undefined || frameByteLength(input) > this.maxFrameBytes) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Frame exceeds the maximum size", "parse");
        return;
      }
      this.receive(peer, input);
    };
    const onClose = (code?: unknown, reason?: unknown) => {
      const close = normalizePeerClose(code, reason);
      // Native close metadata is untrusted transport input.  The local close
      // path never sends a second close frame after this callback.
      this.closePeer(peer, close.reason, false);
    };
    const onError = (_error: unknown) => this.closePeer(peer, "transport error");

    if (typeof transport.on === "function") {
      transport.on("message", onMessage);
      transport.on("close", onClose);
      transport.on("error", onError);
    } else {
      transport.onMessage?.((data) => onMessage(data, false));
      transport.onClose?.(onClose);
      transport.onError?.((error) => onError(error));
    }
  }

  private receive(peer: BrokerPeer, input: string | Uint8Array): void {
    const parsed = parseStrictJson(input, { maxBytes: this.maxFrameBytes });
    if (parsed.ok === false) {
      this.failHandshakeOrError(
        peer,
        parsed.code,
        "Frame is not valid strict JSON",
        parsed.code === "RESOURCE_EXHAUSTED" ? "resource" : "parse",
      );
      return;
    }
    const frame: unknown = parsed.value;

    if (peer.phase === "await_hello") {
      this.receiveHello(peer, frame);
      return;
    }
    if (peer.phase === "await_card") {
      this.receiveCard(peer, frame);
      return;
    }
    if (peer.phase === "await_auth") {
      this.receiveAuth(peer, frame);
      return;
    }
    if (peer.phase === "await_ready") {
      this.receiveReady(peer, frame);
      return;
    }
    if (peer.phase === "active") this.receiveEnvelope(peer, frame);
  }

  private receiveHello(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "hello" || validated.value.role !== "initiator") {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "Expected an initiator hello for PolyMesh 0.1", "protocol");
      return;
    }
    const hello: HelloFrame = validated.value;
    if (this.identityProfile ? hello.security_profile !== SECURE_IDENTITY_PROFILE : hello.security_profile !== undefined) {
      this.failHandshake(peer, "SECURITY_PROFILE_MISMATCH", "Peer selected an unexpected security profile", "identity");
      return;
    }
    if (hello.agent_id === this.card.agent_id && hello.instance_id === this.card.instance_id) {
      this.failHandshake(peer, "SELF_CONNECTION", "An agent cannot connect to itself", "identity");
      return;
    }
    peer.agentId = hello.agent_id;
    peer.instanceId = hello.instance_id;
    peer.initiatorNonce = hello.nonce;
    peer.initiatorHello = hello;
    peer.responderNonce = randomNonce();
    peer.sessionId = deriveSessionId(peer.initiatorNonce, peer.responderNonce);
    peer.phase = "await_card";
    const responderHello: Extract<HelloFrame, { role: "responder" }> = {
      type: "hello",
      v: "0.1",
      role: "responder",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: peer.responderNonce,
      echo: peer.initiatorNonce,
      sid: peer.sessionId,
      ...(this.identityProfile === undefined ? {} : { security_profile: SECURE_IDENTITY_PROFILE }),
    };
    peer.responderHello = responderHello;
    this.sendRaw(peer, responderHello);
  }

  private receiveCard(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "card") {
      this.failHandshake(peer, "MALFORMED_FRAME", "Invalid card handshake frame", "parse");
      return;
    }
    const cardFrame: CardFrame = validated.value;
    if (cardFrame.sid !== peer.sessionId || cardFrame.for_nonce !== peer.responderNonce) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Card transcript does not match the handshake", "protocol");
      return;
    }
    if (cardFrame.card.agent_id !== peer.agentId || cardFrame.card.instance_id !== peer.instanceId) {
      this.failHandshake(peer, "SOURCE_IDENTITY_MISMATCH", "Card identity does not match hello identity", "identity");
      return;
    }
    if (Date.parse(cardFrame.card.expires_at) <= this.now()) {
      this.failHandshake(peer, "CARD_EXPIRED", "Agent card has expired", "protocol");
      return;
    }
    const actualDigest = cardDigest(cardFrame.card);
    if (actualDigest !== cardFrame.digest) {
      this.failHandshake(peer, "CARD_DIGEST_MISMATCH", "Card digest does not match card contents", "protocol");
      return;
    }
    peer.card = cardFrame.card;
    peer.cardDigest = actualDigest;
    const profile = this.identityProfile;
    if (profile) {
      const principal = verifyEnrolledCard(cardFrame.card, profile.enrollments, this.now());
      if (!principal || !cardFrame.card.identity ||
        principal.agent_id !== peer.agentId ||
        principal.key_id !== cardFrame.card.identity.key_id) {
        this.failHandshake(peer, "AUTHENTICATION_FAILED", "Peer Card is not signed by an enrolled identity", "identity");
        return;
      }
      const existing = this.registry.lookup(peer.agentId!);
      const existingPrincipal = existing?.transport?.verifiedPrincipal;
      if (existingPrincipal && existingPrincipal.key_id !== principal.key_id) {
        this.failHandshake(peer, "IDENTITY_COLLISION", "A different enrolled key already owns this agent ID", "identity");
        return;
      }
      if (existingPrincipal && existingPrincipal.key_id === principal.key_id && existing.instanceId === peer.instanceId) {
        this.failHandshake(peer, "INSTANCE_ID_COLLISION", "This enrolled instance ID is already active", "identity");
        return;
      }
      peer.verifiedPrincipal = principal;
      peer.phase = "await_auth";
    } else {
      peer.phase = "await_ready";
    }
    this.sendRaw(peer, {
      type: "card",
      sid: peer.sessionId,
      for_nonce: peer.initiatorNonce,
      digest: this.cardDigest,
      card: this.card,
    });
  }

  private receiveAuth(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "auth" || validated.value.sid !== peer.sessionId) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Invalid peer authentication proof", "identity");
      return;
    }
    const profile = this.identityProfile;
    const peerCard = peer.card;
    if (!profile || !peerCard?.identity || !peer.verifiedPrincipal ||
      validated.value.agent_id !== peer.agentId ||
      validated.value.key_id !== peerCard.identity.key_id) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Authentication proof does not match the enrolled Card", "identity");
      return;
    }
    let principal: VerifiedPrincipal | undefined;
    try {
      principal = verifyAuthProof(validated.value as AuthFrame, this.secureTranscript(peer), profile.enrollments, this.now());
    } catch {
      principal = undefined;
    }
    if (!principal || principal.key_id !== peer.verifiedPrincipal.key_id || principal.agent_id !== peer.verifiedPrincipal.agent_id) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Peer did not prove possession of its enrolled key", "identity");
      return;
    }
    peer.verifiedPrincipal = principal;
    peer.phase = "await_ready";
    try {
      this.sendRaw(peer, createAuthProof(
        profile.identity,
        this.card.agent_id,
        peer.sessionId!,
        this.secureTranscript(peer),
        profile.privateKey,
      ));
    } catch {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Unable to construct broker authentication proof", "identity");
    }
  }

  private secureTranscript(peer: BrokerPeer): Buffer {
    if (!peer.initiatorHello || !peer.responderHello || !peer.cardDigest) {
      throw new TypeError("Secure handshake transcript is incomplete");
    }
    const binding = tlsChannelBinding(peer.transport);
    if (!binding) throw new TypeError("TLS 1.3 channel binding is unavailable");
    return authTranscript({
      initiator_hello: peer.initiatorHello,
      responder_hello: peer.responderHello,
      initiator_card_digest: peer.cardDigest,
      responder_card_digest: this.cardDigest,
      tls_channel_binding: binding,
    });
  }

  private receiveReady(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (
      validated.ok === false ||
      validated.value.type !== "ready" ||
      !peer.agentId ||
      !peer.instanceId ||
      !peer.card ||
      (this.identityProfile !== undefined && peer.verifiedPrincipal === undefined)
    ) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Ready transcript does not match the handshake", "protocol");
      return;
    }
    const ready: ReadyFrame = validated.value;
    if (ready.sid !== peer.sessionId || ready.self_card !== peer.cardDigest || ready.peer_card !== this.cardDigest) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Ready transcript does not match the handshake", "protocol");
      return;
    }

    try {
      const record = this.registry.register({
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        sessionId: peer.sessionId,
        card: peer.card,
        transport: peer,
      });
      peer.leaseId = record.leaseId;
    } catch (error) {
      if (error instanceof DuplicateAgentError) {
        this.failHandshake(peer, "DUPLICATE_CONNECTION", error.message, "routing");
        return;
      }
      this.failHandshake(peer, "INTERNAL_ERROR", "Could not register agent", "internal");
      return;
    }

    peer.phase = "active";
    this.clearHandshakeTimer(peer);
    this.sendRaw(peer, {
      type: "ready",
      sid: peer.sessionId,
      self_card: this.cardDigest,
      peer_card: peer.cardDigest,
    });
    this.options.onPeerConnected?.(peer);
  }

  private receiveEnvelope(peer: BrokerPeer, frame: unknown): void {
    if (!isEnvelope(frame)) {
      this.sendError(peer, "MALFORMED_FRAME", "Frame is not a valid PolyMesh envelope", "parse");
      return;
    }
    const envelope = frame as Envelope;
    if (envelope.source.agent_id !== peer.agentId || envelope.source.instance_id !== peer.instanceId) {
      this.sendError(
        peer,
        "SOURCE_IDENTITY_MISMATCH",
        "Envelope source does not match the authenticated connection",
        "identity",
        envelope.message_id,
      );
      return;
    }
    // Provenance is created only after this authenticated ingress check. A
    // sender-supplied attachment would otherwise let one routed peer try to
    // smuggle an attestation into another route or create nested signatures.
    if (envelope.provenance !== undefined) {
      this.sendError(peer, "PROVENANCE_FORBIDDEN", "Only the broker may attach routed provenance", "identity", envelope.message_id);
      return;
    }

    // Receipts are broker-local, terminal control observations. They are
    // intentionally neither replay-ledger inputs nor routable application
    // traffic, and a receipt must never itself trigger another receipt.
    if (envelope.type === "receipt") return;

    let semanticDigest: string;
    try {
      semanticDigest = envelopeSemanticDigest(envelope);
    } catch {
      this.sendError(peer, "MALFORMED_FRAME", "Envelope semantics cannot be canonicalized", "parse", envelope.message_id);
      return;
    }
    const replay = this.admitReplayEnvelope(peer, envelope, semanticDigest);
    if (replay === "conflict") {
      this.sendError(
        peer,
        "PMX.DELIVERY.MESSAGE_ID_CONFLICT",
        "message_id was reused with different message semantics",
        "delivery",
        envelope.message_id,
      );
      this.sendReceipt(peer, envelope, semanticDigest, "rejected");
      return;
    }
    if (replay === "overloaded") {
      this.sendError(
        peer,
        "OVERLOADED",
        "Broker replay ledger capacity is exhausted",
        "resource",
        envelope.message_id,
        {},
        true,
      );
      return;
    }
    this.registry.touch(peer.agentId!, { sessionId: peer.sessionId });

    // A direct ping to the broker gets a fast, signed-by-session response.
    if (envelope.target.agent_id === this.card.agent_id) {
      if (envelope.target.instance_id !== undefined && envelope.target.instance_id !== this.card.instance_id) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Target broker instance is unavailable", "routing", envelope.message_id, {
          target: this.card.agent_id,
          instance_id: envelope.target.instance_id,
        }, true);
        this.sendReceipt(peer, envelope, semanticDigest, "rejected");
        return;
      }
      if (envelope.type === "ping") {
        this.sendPong(peer, envelope as Envelope<"ping">);
        this.emitEnvelope(peer, envelope);
        this.sendReceipt(peer, envelope, semanticDigest, replay === "duplicate" ? "duplicate" : "accepted");
        return;
      }
      if (envelope.type === "task.submit") {
        this.handleBrokerTask(peer, envelope as Envelope<"task.submit">);
        this.emitEnvelope(peer, envelope);
        this.sendReceipt(peer, envelope, semanticDigest, replay === "duplicate" ? "duplicate" : "accepted");
        return;
      }
    }
    const routed = this.routeEnvelope(peer, envelope);
    if (routed) this.emitEnvelope(peer, envelope);
    this.sendReceipt(peer, envelope, semanticDigest, routed ? (replay === "duplicate" ? "duplicate" : "accepted") : "rejected");
  }

  private routeEnvelope(peer: BrokerPeer, envelope: Envelope): boolean {
    const taskId = taskIdOf(envelope);
    if (envelope.type === "task.submit" && taskId) {
      const declaredDeadline = envelope.delivery.deadline;
      const deadlineAt = declaredDeadline ? Date.parse(declaredDeadline) : Number.NaN;
      if (!Number.isFinite(deadlineAt) || deadlineAt <= this.now()) {
        this.sendError(peer, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed", "task", envelope.message_id);
        return false;
      }
      const target = this.lookupTarget(peer, envelope);
      if (!target) return false;
      const contract = taskContractOf(envelope);
      if (!contract) {
        this.sendError(peer, "MALFORMED_FRAME", "Task submission has no valid capability contract", "parse", envelope.message_id);
        return false;
      }
      const prior = this.pendingTasks.get(taskId);
      const immutableFingerprint = canonicalize({
        method: (envelope.params as JsonRecord).method as never,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: (envelope.params as JsonRecord).params as never,
        deadline: (envelope.params as JsonRecord).deadline as never,
      } as never);
      if (
        prior &&
        (!this.isExactRoutePeer(prior.owner, peer) ||
          prior.executor.agentId !== target.agentId ||
          prior.executor.instanceId !== target.instanceId ||
          prior.executor.sessionId !== target.sessionId)
      ) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID is already assigned to another route", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (prior && prior.immutableFingerprint !== immutableFingerprint) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID was reused with different immutable input", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (prior) {
        if (!this.addSubmitMessageId(prior, envelope.message_id)) {
          this.sendError(peer, "OVERLOADED", "Too many retransmissions for this task route", "resource", envelope.message_id, {}, true);
          return false;
        }
        const currentTarget = this.registry.lookup(prior.executor.agentId, prior.executor.instanceId);
        if (!currentTarget || currentTarget.sessionId !== prior.executor.sessionId) {
          this.sendError(peer, "TARGET_UNAVAILABLE", "Task executor is no longer connected", "routing", envelope.message_id, {
            task_id: taskId,
            target: prior.executor.agentId,
          }, true);
          return false;
        }
        return this.forwardEnvelope(peer, currentTarget.transport!, envelope);
      }

      if (!this.reserveTaskRoute(peer, target)) {
        this.sendError(peer, "OVERLOADED", "Broker task-route capacity is exhausted", "resource", envelope.message_id, {}, true);
        return false;
      }
      const route: TaskRoute = {
          taskId,
          contract,
          owner: { agentId: peer.agentId!, instanceId: peer.instanceId!, sessionId: peer.sessionId },
          executor: { agentId: target.agentId, instanceId: target.instanceId, sessionId: target.sessionId },
          submitMessageId: envelope.message_id,
          submitMessageIds: new Set([envelope.message_id]),
          createdAt: this.now(),
          deadline: declaredDeadline,
          immutableFingerprint,
          lifecycle: "submitted",
          nextEventSeq: 1,
          events: new Map(),
          capacityReserved: true,
          retainedUntil: Math.max(deadlineAt, this.now()) + this.replayRetentionMs,
        };
      this.pendingTasks.set(taskId, route);
      this.routesBySubmitMessageId.set(envelope.message_id, taskId);
      if (!this.forwardEnvelope(peer, target.transport!, envelope)) {
        this.deleteRoute(route);
        return false;
      }
      return true;
    }

    if (isLifecycle(envelope.type) && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (
        !route ||
        !this.isExactRoutePeer(route.executor, peer) ||
        envelope.target.agent_id !== route.owner.agentId ||
        (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.owner.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.FORGED_RESULT", "Lifecycle event is not authorized for this task", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (route.lifecycle === "closed") {
        this.sendError(peer, "PMX.TASK.TERMINAL", "Task route is no longer active", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const lifecycle = this.admitLifecycle(route, envelope);
      if (lifecycle === "event-conflict") {
        this.sendError(peer, "PMX.TASK.EVENT_CONFLICT", "Lifecycle sequence was reused with different content", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (lifecycle === "overloaded") {
        this.sendError(peer, "OVERLOADED", "Lifecycle history capacity is exhausted", "resource", envelope.message_id, {}, true);
        return false;
      }
      if (lifecycle === "invalid") {
        this.sendError(peer, "PMX.TASK.INVALID_LIFECYCLE", "Lifecycle event is not a valid causal transition", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const owner = this.registry.lookup(route.owner.agentId, route.owner.instanceId);
      if (!owner || owner.sessionId !== route.owner.sessionId) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Task owner is no longer connected", "routing", envelope.message_id, {
          target: route.owner.agentId,
          task_id: taskId,
        }, true);
        return false;
      }
      return this.forwardEnvelope(peer, owner.transport!, envelope);
    }

    if (envelope.type === "task.cancel" && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (!route || route.lifecycle === "closed") {
        this.sendError(peer, "PMX.TASK.NOT_FOUND", "No active task route exists for this cancellation", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (!this.isExactRoutePeer(route.owner, peer)) {
        this.sendError(peer, "AUTHORIZATION_DENIED", "Only the task owner may cancel a task", "identity", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (
        route.lifecycle === "rejected" ||
        route.lifecycle === "completed" ||
        envelope.target.agent_id !== route.executor.agentId ||
        (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.executor.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.TERMINAL", "Cancellation target or task state is no longer cancellable", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const executor = this.registry.lookup(route.executor.agentId, route.executor.instanceId);
      if (!executor || executor.sessionId !== route.executor.sessionId) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Task executor is no longer connected", "routing", envelope.message_id, {
          task_id: taskId,
          target: route.executor.agentId,
        }, true);
        return false;
      }
      return this.forwardEnvelope(peer, executor.transport!, envelope);
    }

    if (envelope.type === "error") return this.routeCorrelatedError(peer, envelope as Envelope<"error">);
    if (envelope.type === "card") {
      this.sendError(peer, "UNSUPPORTED_METHOD", "Post-ready card envelopes are not routable", "protocol", envelope.message_id);
      return false;
    }

    const target = this.lookupTarget(peer, envelope);
    if (!target) return false;
    return this.sendEnvelope(target.transport!, envelope);
  }

  /** Invoke observer hooks only after routing/admission has accepted a record. */
  private emitEnvelope(peer: BrokerPeer, envelope: Envelope): void {
    try {
      this.options.onEnvelope?.(envelope, peer);
    } catch {
      // Observer failures must not turn a validated peer record into a broker
      // crash or influence routing state.
    }
  }

  private routeSessionKey(identity: { agentId: string; instanceId: string; sessionId?: string }): string {
    return `${identity.agentId}\0${identity.instanceId}\0${identity.sessionId ?? ""}`;
  }

  private peerSessionKey(peer: BrokerPeer): string {
    return this.routeSessionKey({
      agentId: peer.agentId ?? "",
      instanceId: peer.instanceId ?? "",
      sessionId: peer.sessionId,
    });
  }

  private isExactRoutePeer(identity: { agentId: string; instanceId: string; sessionId?: string }, peer: BrokerPeer): boolean {
    return identity.agentId === peer.agentId &&
      identity.instanceId === peer.instanceId &&
      identity.sessionId === peer.sessionId;
  }

  /** Reserve route capacity before allocating an in-memory task record. */
  private reserveTaskRoute(owner: BrokerPeer, executor: RegistryEntry<BrokerPeer, AgentCard>): boolean {
    this.pruneRouteAndReplayState();
    if (this.pendingTasks.size >= this.maxPendingTaskRoutes) return false;
    const keys = new Set([
      this.peerSessionKey(owner),
      this.routeSessionKey({ agentId: executor.agentId, instanceId: executor.instanceId, sessionId: executor.sessionId }),
    ]);
    for (const key of keys) {
      if ((this.pendingRoutesBySession.get(key) ?? 0) >= this.maxPendingTaskRoutesPerSession) return false;
    }
    for (const key of keys) this.pendingRoutesBySession.set(key, (this.pendingRoutesBySession.get(key) ?? 0) + 1);
    return true;
  }

  private releaseRouteCapacity(route: TaskRoute): void {
    if (!route.capacityReserved) return;
    route.capacityReserved = false;
    const keys = new Set([
      this.routeSessionKey(route.owner),
      this.routeSessionKey(route.executor),
    ]);
    for (const key of keys) {
      const count = this.pendingRoutesBySession.get(key) ?? 0;
      if (count <= 1) this.pendingRoutesBySession.delete(key);
      else this.pendingRoutesBySession.set(key, count - 1);
    }
  }

  private deleteRoute(route: TaskRoute): void {
    if (this.pendingTasks.get(route.taskId) !== route) return;
    this.pendingTasks.delete(route.taskId);
    this.releaseRouteCapacity(route);
    for (const messageId of route.submitMessageIds) {
      if (this.routesBySubmitMessageId.get(messageId) === route.taskId) this.routesBySubmitMessageId.delete(messageId);
    }
  }

  private addSubmitMessageId(route: TaskRoute, messageId: string): boolean {
    if (route.submitMessageIds.has(messageId)) return true;
    // The bounded replay set also caps untrusted `in_reply_to` correlation
    // state. It shares the lifecycle ceiling because both belong to one task.
    if (route.submitMessageIds.size >= this.maxLifecycleEventsPerRoute) return false;
    route.submitMessageIds.add(messageId);
    this.routesBySubmitMessageId.set(messageId, route.taskId);
    return true;
  }

  private admitLifecycle(route: TaskRoute, envelope: Envelope): "accepted" | "duplicate" | "invalid" | "event-conflict" | "overloaded" {
    const params = envelope.params as JsonRecord;
    const sequence = params.event_seq;
    if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return "invalid";
    if ((envelope.type === "task.accepted" || envelope.type === "task.rejected") &&
      (!envelope.in_reply_to || !route.submitMessageIds.has(envelope.in_reply_to))) {
      return "invalid";
    }
    if (envelope.type === "task.accepted" || envelope.type === "task.completed") {
      const echoedContract = taskContractOf(envelope);
      if (!echoedContract || !sameCapabilityContract(route.contract, echoedContract)) return "invalid";
    }
    let digest: string;
    try {
      // Envelope IDs, timestamps, and delivery IDs change on retransmission;
      // the lifecycle semantics must not. Correlation is checked separately.
      digest = canonicalize({
        type: envelope.type,
        source: envelope.source,
        target: envelope.target,
        params: envelope.params,
      } as never);
    } catch {
      return "invalid";
    }
    const previous = route.events.get(sequence);
    if (previous !== undefined) return previous === digest ? "duplicate" : "event-conflict";
    if (route.events.size >= this.maxLifecycleEventsPerRoute) return "overloaded";
    if (sequence !== route.nextEventSeq) return "invalid";

    if (envelope.type === "task.accepted") {
      if (route.lifecycle !== "submitted") return "invalid";
      route.lifecycle = "accepted";
    } else if (envelope.type === "task.rejected") {
      if (route.lifecycle !== "submitted") return "invalid";
      route.lifecycle = "rejected";
      this.releaseRouteCapacity(route);
    } else if (envelope.type === "task.progress") {
      if (route.lifecycle !== "accepted") return "invalid";
    } else if (envelope.type === "task.completed") {
      if (route.lifecycle !== "accepted") return "invalid";
      route.lifecycle = "completed";
      this.releaseRouteCapacity(route);
    } else {
      return "invalid";
    }
    route.events.set(sequence, digest);
    route.nextEventSeq = sequence + 1;
    return "accepted";
  }

  /** Only forward executor errors that are exactly correlated to a route. */
  private routeCorrelatedError(peer: BrokerPeer, envelope: Envelope<"error">): boolean {
    const messageId = envelope.in_reply_to;
    const route = messageId ? this.pendingTasks.get(this.routesBySubmitMessageId.get(messageId) ?? "") : undefined;
    if (
      !route ||
      (route.lifecycle !== "submitted" && route.lifecycle !== "accepted") ||
      !this.isExactRoutePeer(route.executor, peer) ||
      envelope.target.agent_id !== route.owner.agentId ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.owner.instanceId)
    ) {
      this.sendError(peer, "PMX.TASK.FORGED_ERROR", "Error is not authorized for a live task route", "task", envelope.message_id);
      return false;
    }
    const owner = this.registry.lookup(route.owner.agentId, route.owner.instanceId);
    if (!owner || owner.sessionId !== route.owner.sessionId) {
      this.sendError(peer, "TARGET_UNAVAILABLE", "Task owner is no longer connected", "routing", envelope.message_id, {
        task_id: route.taskId,
        target: route.owner.agentId,
      }, true);
      return false;
    }
    return this.forwardEnvelope(peer, owner.transport!, envelope);
  }

  /** Insert a semantic message-id fingerprint before any forwarding side effect. */
  private admitReplayEnvelope(
    peer: BrokerPeer,
    envelope: Envelope,
    semanticDigest: string = envelopeSemanticDigest(envelope),
  ): "new" | "duplicate" | "conflict" | "overloaded" {
    this.pruneRouteAndReplayState();
    const key = this.replayLedgerKey(peer, envelope.message_id);
    const prior = this.replayLedger.get(key);
    if (prior) return prior.semanticDigest === semanticDigest ? "duplicate" : "conflict";
    if (this.replayLedger.size >= this.maxReplayLedgerEntries) return "overloaded";
    const deadline = envelope.delivery.deadline ? Date.parse(envelope.delivery.deadline) : Number.NaN;
    this.replayLedger.set(key, {
      semanticDigest,
      expiresAt: Math.max(this.now(), Number.isFinite(deadline) ? deadline : this.now()) + this.replayRetentionMs,
    });
    return "new";
  }

  private replayLedgerKey(peer: BrokerPeer, messageId: string): string {
    // Stable enrolled keys survive instance restarts; the legacy loopback
    // fallback remains scoped to the authenticated session identity.
    const securePrincipal = peer.verifiedPrincipal?.principal_id;
    return securePrincipal
      ? `${securePrincipal}\0${messageId}`
      : `${peer.agentId ?? ""}\0${peer.instanceId ?? ""}\0${messageId}`;
  }

  private pruneRouteAndReplayState(now = this.now()): void {
    for (const route of [...this.pendingTasks.values()]) {
      const deadline = route.deadline ? Date.parse(route.deadline) : Number.NaN;
      if ((route.lifecycle === "submitted" || route.lifecycle === "accepted") && Number.isFinite(deadline) && deadline <= now) {
        route.lifecycle = "closed";
        this.releaseRouteCapacity(route);
      }
      if (route.retainedUntil <= now) this.deleteRoute(route);
    }
    for (const [key, record] of this.replayLedger) {
      if (record.expiresAt <= now) this.replayLedger.delete(key);
    }
  }

  private lookupTarget(peer: BrokerPeer, envelope: Envelope): RegistryEntry<BrokerPeer, AgentCard> | undefined {
    const target = this.registry.lookup(envelope.target.agent_id, envelope.target.instance_id);
    if (!target) {
      const agentExists = this.registry.lookup(envelope.target.agent_id);
      this.sendError(
        peer,
        agentExists ? "TARGET_UNAVAILABLE" : "UNKNOWN_TARGET",
        agentExists ? "Target instance is unavailable" : "No live agent has that id",
        "routing",
        envelope.message_id,
        { target: envelope.target.agent_id, instance_id: envelope.target.instance_id ?? null },
        true,
      );
      return undefined;
    }
    return target;
  }

  private sendPong(peer: BrokerPeer, ping: Envelope): void {
    const n = (ping.params as JsonRecord).n;
    const pong = this.makeEnvelope("pong", peer, { n }, ping.message_id);
    this.sendEnvelope(peer, pong);
  }

  /**
   * A receipt is emitted only after the replay/admission path has recorded a
   * disposition. It is addressed back to the submitting session and never
   * enters the router, so it cannot create acknowledgement loops.
   */
  private sendReceipt(
    peer: BrokerPeer,
    received: Envelope,
    semanticDigest: string,
    disposition: ReceiptDisposition,
  ): void {
    if (peer.phase !== "active" || !peer.agentId || !peer.instanceId) return;
    this.sendEnvelope(peer, this.makeEnvelope("receipt", peer, {
      received_message_id: received.message_id,
      semantic_digest: semanticDigest,
      disposition,
    }, received.message_id));
  }

  /** Serve the three standard broker capabilities without pretending it is a routed peer. */
  private handleBrokerTask(peer: BrokerPeer, submit: Envelope<"task.submit">): void {
    const params = submit.params as JsonRecord;
    const taskId = typeof params.task_id === "string" ? params.task_id : undefined;
    const method = typeof params.method === "string" ? params.method : undefined;
    if (!taskId || !method) {
      this.sendError(peer, "MALFORMED_FRAME", "Broker task submission is malformed", "parse", submit.message_id);
      return;
    }
    const reject = (code: string, message: string) => {
      this.sendEnvelope(peer, this.makeEnvelope("task.rejected", peer, {
        task_id: taskId,
        event_seq: 1,
        code,
        message,
      }, submit.message_id));
    };
    if (Date.parse(String(params.deadline)) <= this.now()) {
      reject("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed");
      return;
    }
    const capability = this.card.capabilities.find((entry) => entry.id === method);
    if (!capability) {
      reject("UNSUPPORTED_CAPABILITY", `Broker does not implement ${method}`);
      return;
    }
    const submittedContract = taskContractOf(submit);
    const advertisedContract = capabilityContractTuple(capability);
    if (!submittedContract || !sameCapabilityContract(submittedContract, advertisedContract)) {
      reject("CAPABILITY_CONTRACT_MISMATCH", "Task capability contract does not match the broker's advertised capability");
      return;
    }
    let result: JsonRecord | AgentCard | Array<Pick<AgentCard["capabilities"][number], "id" | "version">>;
    if (method === "org.polymesh.agent.ping") result = {};
    else if (method === "org.polymesh.agent.info") result = this.card;
    else if (method === "org.polymesh.capabilities.list") {
      result = this.card.capabilities.map(({ id, version }) => ({ id, version }));
    } else {
      reject("UNSUPPORTED_CAPABILITY", `Broker does not implement ${method}`);
      return;
    }
    this.sendEnvelope(peer, this.makeEnvelope("task.accepted", peer, {
      task_id: taskId,
      event_seq: 1,
      accepted_at: new Date(this.now()).toISOString(),
      ...advertisedContract,
    }, submit.message_id));
    this.sendEnvelope(peer, this.makeEnvelope("task.completed", peer, {
      task_id: taskId,
      event_seq: 2,
      ...advertisedContract,
      terminal: {
        outcome: "succeeded",
        result,
        completed_at: new Date(this.now()).toISOString(),
      },
    }));
  }

  private makeEnvelope(type: EnvelopeType, target: BrokerPeer, params: JsonRecord, inReplyTo?: string): Envelope {
    const targetAgent = target.agentId;
    const targetInstance = target.instanceId;
    if (!targetAgent || !targetInstance) throw new Error("Cannot send an envelope before peer identity is known");
    return {
      protocol: PROTOCOL_VERSION,
      type,
      message_id: uuidv7(),
      timestamp: new Date(this.now()).toISOString(),
      source: { agent_id: this.card.agent_id, instance_id: this.card.instance_id },
      target: { agent_id: targetAgent, instance_id: targetInstance },
      delivery: {
        mode: "at_least_once",
        idempotency_key: `${type}:${uuidv7()}`,
        deadline: new Date(this.now() + 60_000).toISOString(),
      },
      ...(inReplyTo ? { in_reply_to: inReplyTo } : {}),
      params,
    } as Envelope;
  }

  private sendError(
    peer: BrokerPeer,
    code: string,
    message: string,
    category: string,
    inReplyTo?: string,
    details: JsonRecord = {},
    retryable = false,
  ): void {
    if (peer.phase !== "active" || !peer.agentId || !peer.instanceId) {
      this.failHandshake(peer, code, message, category);
      return;
    }
    const envelope = this.makeEnvelope(
      "error",
      peer,
      {
        category,
        code,
        message,
        retryable,
        retry_after_ms: null,
        details,
      },
      inReplyTo,
    );
    this.sendEnvelope(peer, envelope);
  }

  /**
   * Forward a record after adding a target-session-bound broker attestation in
   * the enrolled WSS profile.  The legacy explicit-loopback development
   * profile intentionally preserves its existing transport-only behaviour.
   */
  private forwardEnvelope(source: BrokerPeer, target: BrokerPeer, envelope: Envelope): boolean {
    const profile = this.identityProfile;
    if (!profile || !requiresRoutedProvenance(envelope.type)) return this.sendEnvelope(target, envelope);
    if (!source.verifiedPrincipal || !source.sessionId || !target.sessionId ||
      !source.agentId || !source.instanceId || !target.agentId || !target.instanceId ||
      source.verifiedPrincipal.agent_id !== source.agentId ||
      envelope.source.agent_id !== source.agentId || envelope.source.instance_id !== source.instanceId ||
      envelope.target.agent_id !== target.agentId ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== target.instanceId)) {
      this.sendError(source, "AUTHENTICATION_FAILED", "Secure routed provenance cannot be established", "identity", envelope.message_id);
      return false;
    }
    const now = this.now();
    const deadline = Date.parse(envelope.delivery.deadline ?? "");
    const expiresAt = Math.min(now + MAX_ROUTED_PROVENANCE_LIFETIME_MS, deadline);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      this.sendError(source, "PMX.TASK.DEADLINE_EXCEEDED", "Routed provenance expired before forwarding", "task", envelope.message_id);
      return false;
    }
    try {
      const provenance = createRoutedProvenance({
        envelope,
        broker: {
          agent_id: this.card.agent_id,
          instance_id: this.card.instance_id,
          key_id: profile.localPrincipal.key_id,
        },
        sourcePrincipal: source.verifiedPrincipal,
        sourceSessionId: source.sessionId,
        targetSessionId: target.sessionId,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
        privateKey: profile.privateKey,
      });
      return this.sendEnvelope(target, { ...envelope, provenance });
    } catch {
      this.sendError(source, "AUTHENTICATION_FAILED", "Secure routed provenance could not be signed", "identity", envelope.message_id);
      return false;
    }
  }

  private sendEnvelope(peer: BrokerPeer, envelope: Envelope): boolean {
    return this.sendRaw(peer, envelope);
  }

  private sendRaw(peer: BrokerPeer, value: unknown): boolean {
    if (peer.phase === "closed" || !websocketStateOpen(peer.transport)) return false;
    try {
      peer.transport.send(JSON.stringify(value));
      return true;
    } catch (error) {
      this.closePeer(peer, error);
      return false;
    }
  }

  private failHandshakeOrError(peer: BrokerPeer, code: string, message: string, category: string): void {
    if (peer.phase === "active") this.sendError(peer, code, message, category);
    else this.failHandshake(peer, code, message, category);
  }

  private failHandshake(peer: BrokerPeer, code: string, message: string, category: string): void {
    if (peer.phase === "closed") return;
    this.sendRaw(peer, {
      type: "error",
      params: { category, code, message, retryable: false, retry_after_ms: null, details: {} },
    });
    this.closePeer(peer, `${code}: ${message}`);
  }

  private closePeer(peer: BrokerPeer, reason?: unknown, closeTransport = true): void {
    if (peer.phase === "closed") return;
    const wasActive = peer.phase === "active";
    peer.phase = "closed";
    this.clearHandshakeTimer(peer);
    this.peers.delete(peer);
    if (peer.agentId) {
      this.registry.remove(peer.agentId, { sessionId: peer.sessionId, transport: peer });
    }

    // A disconnected participant cannot safely commit a further transition on
    // its pinned route. Retain the tombstone, release active capacity, and do
    // not silently rebind it to a later session with the same claimed ID.
    if (wasActive && peer.agentId && peer.instanceId) {
      for (const route of [...this.pendingTasks.values()]) {
        const executorDisconnected = this.isExactRoutePeer(route.executor, peer);
        const ownerDisconnected = this.isExactRoutePeer(route.owner, peer);
        if ((route.lifecycle === "submitted" || route.lifecycle === "accepted") && (executorDisconnected || ownerDisconnected)) {
          route.lifecycle = "closed";
          this.releaseRouteCapacity(route);
        }
        if (executorDisconnected) {
          const owner = this.registry.lookup(route.owner.agentId, route.owner.instanceId);
          if (owner && owner.sessionId === route.owner.sessionId) {
            this.sendError(
              owner.transport!,
              "TARGET_UNAVAILABLE",
              "Task executor disconnected before a terminal result",
              "routing",
              route.submitMessageId,
              { task_id: route.taskId, target: peer.agentId },
              true,
            );
          }
        }
      }
    }
    if (wasActive) this.options.onPeerDisconnected?.(peer, reason);

    if (closeTransport) {
      try {
        if (typeof peer.transport.close === "function") peer.transport.close(1000, "PolyMesh connection closed");
        else peer.transport.terminate?.();
      } catch {
        // Transport teardown is best effort and is intentionally idempotent.
      }
    }
  }

  private clearHandshakeTimer(peer: BrokerPeer): void {
    const timer = this.handshakeTimers.get(peer);
    if (timer) clearTimeout(timer);
    this.handshakeTimers.delete(peer);
  }

  private pendingHandshakeCount(): number {
    let count = this.pendingUpgradeReservations;
    for (const peer of this.peers) {
      if (peer.phase === "await_hello" || peer.phase === "await_card" || peer.phase === "await_auth" || peer.phase === "await_ready") count += 1;
    }
    return count;
  }

  /** Check capacity before creating a connection/session object. */
  private canAdmitPeer(): boolean {
    return this.peers.size < this.maxOpenSessions && this.pendingHandshakeCount() < this.maxPendingHandshakes;
  }

  /** Reserve capacity at the HTTP layer before WebSocket allocation. */
  private reserveUpgradeAdmission(): boolean {
    if (this.peers.size + this.pendingUpgradeReservations >= this.maxOpenSessions) return false;
    if (this.pendingHandshakeCount() >= this.maxPendingHandshakes) return false;
    this.pendingUpgradeReservations += 1;
    return true;
  }

  private releaseUpgradeReservation(): void {
    if (this.pendingUpgradeReservations > 0) this.pendingUpgradeReservations -= 1;
  }

  /** Reject pre-handshake input without adding it to the peer/session set. */
  private rejectAttachment(
    transport: BrokerTransport,
    code: string,
    message: string,
    category: string,
    retryable = false,
  ): BrokerPeer {
    const peer: BrokerPeer = {
      transport,
      phase: "closed",
      authenticated: false,
      connectedAt: this.now(),
    };
    try {
      transport.send(JSON.stringify({
        type: "error",
        params: { category, code, message, retryable, retry_after_ms: retryable ? 1_000 : null, details: {} },
      }));
    } catch {
      // The rejected transport may already have disappeared.
    }
    try {
      transport.close?.(retryable ? 1013 : 1008, retryable ? "overloaded" : "authentication failed");
    } catch {
      transport.terminate?.();
    }
    return peer;
  }

  private assertSecureListenerConfiguration(): void {
    if (this.options.tls && !this.identityProfile) {
      throw new ProtocolError(
        "AUTHENTICATION_FAILED",
        "TLS listeners require an enrolled Ed25519 identity profile",
        "identity",
      );
    }
    if (!this.options.tls && !this.tokenAuthority) {
      throw new ProtocolError(
        "AUTHENTICATION_FAILED",
        "A 32-byte loopback runtime token is required before starting a listener",
        "identity",
      );
    }
    if (!this.options.tls && (!this.options.allowInsecureLoopbackDevelopment || !isNumericLoopbackHost(this.host))) {
      throw new ProtocolError(
        "INSECURE_TRANSPORT_DISABLED",
        "Plain WebSocket is restricted to an explicitly enabled numeric-loopback development listener",
        "protocol",
      );
    }
  }

  private rejectUpgrade(
    socket: Duplex,
    status: number,
    statusText: string,
    headers: Record<string, string> = {},
  ): void {
    if (socket.destroyed) return;
    const lines = [`HTTP/1.1 ${status} ${statusText}`, "Connection: close", "Content-Length: 0"];
    for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
    try {
      socket.write(`${lines.join("\r\n")}\r\n\r\n`);
    } finally {
      socket.destroy();
    }
  }
}

function isNumericLoopbackHost(host: string): boolean {
  if (host === "::1") return true;
  if (isIP(host) !== 4) return false;
  return Number(host.split(".", 1)[0]) === 127;
}

export default Broker;
