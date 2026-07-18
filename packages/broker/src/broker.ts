/**
 * WebSocket router for the PolyMesh reference implementation.
 *
 * This deliberately stays a router: task execution and task persistence live
 * in agents.  The broker authenticates a connection, performs the mandatory
 * hello/card/ready exchange, records the live agent lease, then forwards
 * validated envelopes without rewriting their sender or recipient fields.
 */

import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import WebSocket, { WebSocketServer } from "ws";

import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  ProtocolError,
  cardDigest,
  canonicalize,
  deriveSessionId,
  isAgentId,
  isAgentCard,
  isInstanceId,
  isNonce,
  isEnvelope,
  randomInstanceId,
  randomNonce,
  uuidv7,
  type AgentCard,
  type Envelope,
  type EnvelopeType,
  type WireTransport,
} from "./protocol.js";
import { DuplicateAgentError, Registry, type RegistryEntry } from "./registry.js";

export const POLYMESH_PATH = "/polymesh";
export const HANDSHAKE_TIMEOUT_MS = 5_000;

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
  /** A loopback/session token. Omit for intentionally open local development. */
  token?: string;
  /** Identity presented by the broker during the card exchange. */
  card?: AgentCard;
  agentId?: string;
  instanceId?: string;
  registry?: Registry<BrokerPeer, AgentCard>;
  ttlMs?: number;
  handshakeTimeoutMs?: number;
  maxFrameBytes?: number;
  now?: () => number;
  onPeerConnected?: (peer: BrokerPeer) => void;
  onPeerDisconnected?: (peer: BrokerPeer, reason?: unknown) => void;
  onEnvelope?: (envelope: Envelope, peer: BrokerPeer) => void;
}

export interface AttachOptions {
  /** Used only for in-memory transports; HTTP upgrades authenticate separately. */
  token?: string;
  /** Skip token comparison for a transport that was authenticated externally. */
  authenticated?: boolean;
  request?: IncomingMessage;
}

export type PeerPhase = "await_hello" | "await_card" | "await_ready" | "active" | "closed";

export interface BrokerPeer {
  transport: BrokerTransport;
  phase: PeerPhase;
  authenticated: boolean;
  agentId?: string;
  instanceId?: string;
  card?: AgentCard;
  cardDigest?: string;
  sessionId?: string;
  initiatorNonce?: string;
  responderNonce?: string;
  leaseId?: string;
  connectedAt: number;
}

interface TaskRoute {
  taskId: string;
  owner: { agentId: string; instanceId: string; sessionId?: string };
  executor: { agentId: string; instanceId: string; sessionId?: string };
  submitMessageId: string;
  createdAt: number;
  deadline?: string;
  immutableFingerprint: string;
  terminal: boolean;
}

interface HelloFrame extends JsonRecord {
  type: "hello";
  v: string;
  role: "initiator" | "responder";
  agent_id: string;
  instance_id: string;
  nonce: string;
  echo?: string;
  sid?: string;
}

interface CardFrame extends JsonRecord {
  type: "card";
  sid: string;
  for_nonce: string;
  digest: string;
  card: AgentCard;
}

interface ReadyFrame extends JsonRecord {
  type: "ready";
  sid: string;
  self_card: string;
  peer_card: string;
}

function isObject(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHello(value: unknown): value is HelloFrame {
  return (
    isObject(value) &&
    value.type === "hello" &&
    typeof value.v === "string" &&
    (value.role === "initiator" || value.role === "responder") &&
    typeof value.agent_id === "string" &&
    typeof value.instance_id === "string" &&
    typeof value.nonce === "string"
  );
}

function isCardFrame(value: unknown): value is CardFrame {
  return (
    isObject(value) &&
    value.type === "card" &&
    typeof value.sid === "string" &&
    typeof value.for_nonce === "string" &&
    typeof value.digest === "string" &&
    isObject(value.card)
  );
}

function isReady(value: unknown): value is ReadyFrame {
  return (
    isObject(value) &&
    value.type === "ready" &&
    typeof value.sid === "string" &&
    typeof value.self_card === "string" &&
    typeof value.peer_card === "string"
  );
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

function asText(data: unknown): string | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  return undefined;
}

function taskIdOf(envelope: Envelope): string | undefined {
  const value = (envelope.params as JsonRecord | undefined)?.task_id;
  return typeof value === "string" ? value : undefined;
}

function isLifecycle(type: EnvelopeType): boolean {
  return type === "task.accepted" || type === "task.rejected" || type === "task.progress" || type === "task.completed";
}

function isTerminal(type: EnvelopeType): boolean {
  return type === "task.rejected" || type === "task.completed";
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
  private readonly peers = new Set<BrokerPeer>();
  private readonly pendingTasks = new Map<string, TaskRoute>();
  private readonly handshakeTimers = new WeakMap<BrokerPeer, ReturnType<typeof setTimeout>>();
  private server?: HttpServer;
  private wsServer?: WebSocketServer;
  private cleanupTimer?: ReturnType<typeof setInterval>;
  private closing = false;

  constructor(options: BrokerOptions = {}) {
    this.options = { ...options };
    this.now = options.now ?? Date.now;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    this.maxFrameBytes = options.maxFrameBytes ?? MAX_FRAME_BYTES;
    if (!Number.isInteger(this.maxFrameBytes) || this.maxFrameBytes <= 0 || this.maxFrameBytes > MAX_FRAME_BYTES) {
      throw new RangeError(`maxFrameBytes must be between 1 and ${MAX_FRAME_BYTES}`);
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshakeTimeoutMs must be a positive finite number");
    }

    const instanceId = options.instanceId ?? randomInstanceId();
    const agentId = options.agentId ?? "org.polymesh.broker";
    this.card = options.card ?? defaultBrokerCard(agentId, instanceId);
    if (!isAgentCard(this.card)) throw new TypeError("Broker card is not a valid AgentCard");
    this.cardDigest = cardDigest(this.card);
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
    return `ws://${host}:${port}${POLYMESH_PATH}`;
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

    const server = createServer((request, response) => this.handleHttp(request, response));
    const wsServer = new WebSocketServer({
      noServer: true,
      maxPayload: this.maxFrameBytes,
      clientTracking: false,
      // Never silently negotiate a caller's unrelated subprotocol just because
      // it appeared first in the header.
      handleProtocols: (protocols) => (protocols.has(PROTOCOL_VERSION) ? PROTOCOL_VERSION : false),
    });
    this.server = server;
    this.wsServer = wsServer;

    server.on("upgrade", (request, socket, head) => {
      void this.handleUpgrade(request, socket, head);
    });
    server.on("error", () => {
      // The listen promise and callers receive startup errors.  Runtime socket
      // errors are handled by ws/connection close events.
    });
    wsServer.on("connection", (socket, request) => {
      this.attach(socket as unknown as BrokerTransport, { authenticated: true, request });
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
   * tests.  The remote end must initiate the ordinary hello/card/ready flow.
   */
  attach(transport: BrokerTransport | WireTransport, options: AttachOptions = {}): BrokerPeer {
    const normalized = transport as unknown as BrokerTransport;
    const authenticated = options.authenticated || !this.options.token || this.sameToken(options.token, this.options.token);
    const peer: BrokerPeer = {
      transport: normalized,
      phase: "await_hello",
      authenticated,
      connectedAt: this.now(),
    };
    this.peers.add(peer);

    if (!authenticated) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "A valid PolyMesh token is required", "identity");
      return peer;
    }

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
    const now = this.now();
    for (const [taskId, route] of this.pendingTasks) {
      const deadline = route.deadline ? Date.parse(route.deadline) : Number.NaN;
      // Keep terminal records for at least the registry lease; active records
      // expire at their declared deadline so a dead client cannot leak routes.
      if ((Number.isFinite(deadline) && deadline <= now) || (route.terminal && now - route.createdAt > this.registry.ttlMs)) {
        this.pendingTasks.delete(taskId);
      }
    }
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = undefined;

    for (const peer of [...this.peers]) this.closePeer(peer, "broker shutting down");
    this.registry.clear();
    this.pendingTasks.clear();

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
    const url = this.requestUrl(request);
    if (url.pathname === "/.well-known/polymesh" && request.method === "GET") {
      const endpoint = this.url;
      response.writeHead(200, {
        "content-type": "application/polymesh+json; charset=utf-8",
        "cache-control": "max-age=60",
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
    const url = this.requestUrl(request);
    if (url.pathname !== POLYMESH_PATH) {
      this.rejectUpgrade(socket, 404, "Not Found");
      return;
    }
    const protocols = String(request.headers["sec-websocket-protocol"] ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (!protocols.includes(PROTOCOL_VERSION)) {
      this.rejectUpgrade(socket, 426, "Upgrade Required", { "Sec-WebSocket-Protocol": PROTOCOL_VERSION });
      return;
    }
    if (this.options.token && !this.sameToken(this.extractToken(request, url), this.options.token)) {
      this.rejectUpgrade(socket, 403, "Forbidden");
      return;
    }
    const wsServer = this.wsServer;
    if (!wsServer) {
      this.rejectUpgrade(socket, 503, "Service Unavailable", { "Retry-After": "1" });
      return;
    }
    wsServer.handleUpgrade(request, socket, head, (ws) => wsServer.emit("connection", ws, request));
  }

  private bindTransport(peer: BrokerPeer): void {
    const transport = peer.transport;
    const onMessage = (data: unknown, isBinary?: boolean) => {
      if (isBinary) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Binary WebSocket frames are not supported", "parse");
        return;
      }
      const text = asText(data);
      if (text === undefined || Buffer.byteLength(text, "utf8") > this.maxFrameBytes) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Frame exceeds the maximum size", "parse");
        return;
      }
      this.receive(peer, text);
    };
    const onClose = (reason?: unknown) => this.closePeer(peer, reason);
    const onError = (error: unknown) => this.closePeer(peer, error);

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

  private receive(peer: BrokerPeer, text: string): void {
    let frame: unknown;
    try {
      frame = JSON.parse(text) as unknown;
    } catch {
      this.failHandshakeOrError(peer, "MALFORMED_JSON", "Frame is not valid JSON", "parse");
      return;
    }

    if (peer.phase === "await_hello") {
      this.receiveHello(peer, frame);
      return;
    }
    if (peer.phase === "await_card") {
      this.receiveCard(peer, frame);
      return;
    }
    if (peer.phase === "await_ready") {
      this.receiveReady(peer, frame);
      return;
    }
    if (peer.phase === "active") this.receiveEnvelope(peer, frame);
  }

  private receiveHello(peer: BrokerPeer, frame: unknown): void {
    if (
      !isHello(frame) ||
      frame.role !== "initiator" ||
      frame.v !== "0.1" ||
      !isAgentId(frame.agent_id) ||
      !isInstanceId(frame.instance_id) ||
      !isNonce(frame.nonce)
    ) {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "Expected an initiator hello for PolyMesh 0.1", "protocol");
      return;
    }
    if (!frame.agent_id || !frame.instance_id || !frame.nonce) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Hello is missing identity fields", "parse");
      return;
    }
    if (frame.agent_id === this.card.agent_id && frame.instance_id === this.card.instance_id) {
      this.failHandshake(peer, "SELF_CONNECTION", "An agent cannot connect to itself", "identity");
      return;
    }
    peer.agentId = frame.agent_id;
    peer.instanceId = frame.instance_id;
    peer.initiatorNonce = frame.nonce;
    peer.responderNonce = randomNonce();
    peer.sessionId = deriveSessionId(peer.initiatorNonce, peer.responderNonce);
    peer.phase = "await_card";
    this.sendRaw(peer, {
      type: "hello",
      v: "0.1",
      role: "responder",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: peer.responderNonce,
      echo: peer.initiatorNonce,
      sid: peer.sessionId,
    });
  }

  private receiveCard(peer: BrokerPeer, frame: unknown): void {
    if (!isCardFrame(frame) || frame.sid !== peer.sessionId || frame.for_nonce !== peer.responderNonce || !isAgentCard(frame.card)) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Invalid card handshake frame", "parse");
      return;
    }
    if (frame.card.agent_id !== peer.agentId || frame.card.instance_id !== peer.instanceId) {
      this.failHandshake(peer, "SOURCE_IDENTITY_MISMATCH", "Card identity does not match hello identity", "identity");
      return;
    }
    if (Date.parse(frame.card.expires_at) <= this.now()) {
      this.failHandshake(peer, "CARD_EXPIRED", "Agent card has expired", "protocol");
      return;
    }
    const actualDigest = cardDigest(frame.card);
    if (actualDigest !== frame.digest) {
      this.failHandshake(peer, "CARD_DIGEST_MISMATCH", "Card digest does not match card contents", "protocol");
      return;
    }
    peer.card = frame.card;
    peer.cardDigest = actualDigest;
    peer.phase = "await_ready";
    this.sendRaw(peer, {
      type: "card",
      sid: peer.sessionId,
      for_nonce: peer.initiatorNonce,
      digest: this.cardDigest,
      card: this.card,
    });
  }

  private receiveReady(peer: BrokerPeer, frame: unknown): void {
    if (
      !isReady(frame) ||
      frame.sid !== peer.sessionId ||
      frame.self_card !== peer.cardDigest ||
      frame.peer_card !== this.cardDigest ||
      !peer.agentId ||
      !peer.instanceId ||
      !peer.card
    ) {
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
    this.registry.touch(peer.agentId!, { sessionId: peer.sessionId });

    // A direct ping to the broker gets a fast, signed-by-session response.
    if (envelope.target.agent_id === this.card.agent_id) {
      if (envelope.target.instance_id !== undefined && envelope.target.instance_id !== this.card.instance_id) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Target broker instance is unavailable", "routing", envelope.message_id, {
          target: this.card.agent_id,
          instance_id: envelope.target.instance_id,
        }, true);
        return;
      }
      if (envelope.type === "ping") {
        this.sendPong(peer, envelope as Envelope<"ping">);
        return;
      }
      if (envelope.type === "task.submit") {
        this.handleBrokerTask(peer, envelope as Envelope<"task.submit">);
        return;
      }
    }
    this.options.onEnvelope?.(envelope, peer);
    this.routeEnvelope(peer, envelope);
  }

  private routeEnvelope(peer: BrokerPeer, envelope: Envelope): void {
    const taskId = taskIdOf(envelope);
    if (envelope.type === "task.submit" && taskId) {
      const target = this.lookupTarget(peer, envelope);
      if (!target) return;
      const prior = this.pendingTasks.get(taskId);
      const immutableFingerprint = canonicalize({
        method: (envelope.params as JsonRecord).method as never,
        params: (envelope.params as JsonRecord).params as never,
        deadline: (envelope.params as JsonRecord).deadline as never,
      } as never);
      if (
        prior &&
        (prior.owner.agentId !== peer.agentId ||
          prior.owner.instanceId !== peer.instanceId ||
          prior.executor.agentId !== target.agentId ||
          prior.executor.instanceId !== target.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID is already assigned to another route", "task", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      if (prior && prior.immutableFingerprint !== immutableFingerprint) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID was reused with different immutable input", "task", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      if (!prior) {
        this.pendingTasks.set(taskId, {
          taskId,
          owner: { agentId: peer.agentId!, instanceId: peer.instanceId!, sessionId: peer.sessionId },
          executor: { agentId: target.agentId, instanceId: target.instanceId, sessionId: target.sessionId },
          submitMessageId: envelope.message_id,
          createdAt: this.now(),
          deadline: envelope.delivery.deadline,
          immutableFingerprint,
          terminal: false,
        });
      }
      this.sendEnvelope(target.transport!, envelope);
      return;
    }

    if (isLifecycle(envelope.type) && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (
        !route ||
        route.executor.agentId !== peer.agentId ||
        route.executor.instanceId !== peer.instanceId ||
        envelope.target.agent_id !== route.owner.agentId ||
        (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.owner.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.FORGED_RESULT", "Lifecycle event is not authorized for this task", "task", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      if (route.terminal) {
        this.sendError(peer, "PMX.TASK.TERMINAL", "Task already has a terminal lifecycle event", "task", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      if (
        (envelope.type === "task.accepted" || envelope.type === "task.rejected") &&
        envelope.in_reply_to !== route.submitMessageId
      ) {
        this.sendError(peer, "PMX.TASK.FORGED_RESULT", "Admission response does not reference the original submission", "task", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      const owner = this.registry.lookup(route.owner.agentId, route.owner.instanceId);
      if (!owner) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Task owner is no longer connected", "routing", envelope.message_id, {
          target: route.owner.agentId,
          task_id: taskId,
        }, true);
        return;
      }
      if (isTerminal(envelope.type)) route.terminal = true;
      this.sendEnvelope(owner.transport!, envelope);
      return;
    }

    if (envelope.type === "task.cancel" && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (route && (route.owner.agentId !== peer.agentId || route.owner.instanceId !== peer.instanceId)) {
        this.sendError(peer, "AUTHORIZATION_DENIED", "Only the task owner may cancel a task", "identity", envelope.message_id, {
          task_id: taskId,
        });
        return;
      }
      if (route) {
        if (
          envelope.target.agent_id !== route.executor.agentId ||
          (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.executor.instanceId)
        ) {
          this.sendError(peer, "PMX.TASK.FORGED_RESULT", "Cancellation target does not match the accepting executor", "task", envelope.message_id, {
            task_id: taskId,
          });
          return;
        }
        const executor = this.registry.lookup(route.executor.agentId, route.executor.instanceId);
        if (!executor) {
          this.sendError(peer, "TARGET_UNAVAILABLE", "Task executor is no longer connected", "routing", envelope.message_id, {
            task_id: taskId,
            target: route.executor.agentId,
          }, true);
          return;
        }
        this.sendEnvelope(executor.transport!, envelope);
        return;
      }
    }

    const target = this.lookupTarget(peer, envelope);
    if (!target) return;
    this.sendEnvelope(target.transport!, envelope);
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
    }, submit.message_id));
    this.sendEnvelope(peer, this.makeEnvelope("task.completed", peer, {
      task_id: taskId,
      event_seq: 2,
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

    // A disconnected executor cannot complete outstanding routes. Inform each
    // still-connected owner; never fabricate a terminal task outcome.
    if (wasActive && peer.agentId && peer.instanceId) {
      for (const route of this.pendingTasks.values()) {
        if (
          !route.terminal &&
          route.executor.agentId === peer.agentId &&
          route.executor.instanceId === peer.instanceId &&
          route.executor.sessionId === peer.sessionId
        ) {
          const owner = this.registry.lookup(route.owner.agentId, route.owner.instanceId);
          if (owner) {
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

  private requestUrl(request: IncomingMessage): URL {
    return new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  }

  private extractToken(request: IncomingMessage, url: URL): string | undefined {
    const direct = request.headers["x-polymesh-token"];
    if (typeof direct === "string") return direct;
    const authorization = request.headers.authorization;
    if (typeof authorization === "string") {
      const match = /^Bearer\s+(.+)$/i.exec(authorization);
      return match?.[1] ?? authorization;
    }
    return url.searchParams.get("token") ?? undefined;
  }

  private sameToken(given: string | undefined, expected: string | undefined): boolean {
    if (!given || !expected) return false;
    const left = Buffer.from(given);
    const right = Buffer.from(expected);
    return left.length === right.length && timingSafeEqual(left, right);
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

export default Broker;
