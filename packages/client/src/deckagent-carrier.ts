/**
 * DeckAgent tunnel carrier for PolyMesh internet bridging.
 *
 * A DeckAgent tunnel is one physical newline-delimited WebSocket. This class
 * exposes one of its multiplexed virtual agent channels as a WebSocket-shaped
 * `WireTransport`, while retaining the other channel records so callers can
 * deliberately multiplex them through `openChannel` / `sendOnChannel`.
 */
import WebSocket, { type ClientOptions as WebSocketClientOptions } from "ws";

import {
  MAX_FRAME_BYTES,
  ProtocolError,
  parseStrictJson,
  uuidv7,
  type JsonValue,
  type WireCloseListener,
  type WireData,
  type WireErrorListener,
  type WireMessageEvent,
  type WireMessageListener,
  type WireOpenListener,
  type WireTransport,
} from "@polymesh/broker";

/** Reserved DeckAgent tool name. It is never delegated to an arbitrary tool. */
export const DECKAGENT_ENVELOPE_TOOL = "__polymesh_envelope__" as const;
export const DECKAGENT_TUNNEL_PROTOCOL_VERSION = 1 as const;
export const DECKAGENT_HEARTBEAT_ACK_TIMEOUT_MS = 45_000;
export const DECKAGENT_HEARTBEAT_GRACE_MS = 2_000;
export const DECKAGENT_AUTH_TIMEOUT_MS = 45_000;
export const DECKAGENT_TOOL_TIMEOUT_MS = 180_000;
export const DECKAGENT_RECONNECT_INITIAL_MS = 1_000;
export const DECKAGENT_RECONNECT_MAX_MS = 30_000;
export const DECKAGENT_RECONNECT_MAX_ATTEMPTS = 10;
export const DECKAGENT_FENCE_TIMEOUT_MS = 60_000;

export type DeckAgentConnectionState =
  | "stopped"
  | "connecting"
  | "authenticating"
  | "connected";

export type DeckAgentChannelState = "closed" | "opening" | "ready";

/** A mesh-scoped virtual channel identity. Both JSON spellings are accepted at construction. */
export interface DeckAgentChannelIdentity {
  meshId?: string;
  agentId?: string;
  instanceId?: string;
  mesh_id?: string;
  agent_id?: string;
  instance_id?: string;
}

export interface DeckAgentChannelSnapshot {
  meshId: string;
  agentId: string;
  instanceId: string;
  mesh_id: string;
  agent_id: string;
  instance_id: string;
  state: DeckAgentChannelState;
  fence: number;
  receivedThrough: number;
  received_through: number;
  inboundReceivedThrough: number;
  inbound_received_through: number;
  nextSequence: number;
  outboxSize: number;
}

/** Immutable inspection record for one locally replayable envelope. */
export interface DeckAgentOutboxSnapshot {
  sequence: number;
  envelope: unknown;
}

export interface DeckAgentChannelConfig {
  heartbeatMs?: number;
  heartbeat_ms?: number;
  reconnectInitialMs?: number;
  reconnect_initial_ms?: number;
  reconnectMaxMs?: number;
  reconnect_max_ms?: number;
  reconnectMaxAttempts?: number;
  reconnect_max_attempts?: number;
  fenceTimeoutMs?: number;
  fence_timeout_ms?: number;
}

/** Narrow WebSocket surface used by the carrier; it intentionally supports test doubles. */
export interface DeckAgentTunnelSocket {
  readyState?: number;
  on?(event: "open" | "message" | "close" | "error" | string, listener: (...args: any[]) => void): unknown;
  once?(event: "open" | "message" | "close" | "error" | string, listener: (...args: any[]) => void): unknown;
  off?(event: "open" | "message" | "close" | "error" | string, listener: (...args: any[]) => void): unknown;
  send(data: string, callback?: (error?: Error) => void): unknown;
  close?(code?: number, reason?: string): unknown;
  terminate?(): unknown;
}

export interface DeckAgentCarrierOptions {
  /** DeckAgent worker base URL. The internet carrier requires `wss:`. */
  workerUrl?: string;
  worker_url?: string;
  deviceId?: string;
  device_id?: string;
  token: string;
  channel: DeckAgentChannelIdentity;
  channelConfig?: DeckAgentChannelConfig;
  channel_config?: DeckAgentChannelConfig;
  heartbeatMs?: number;
  heartbeat_ms?: number;
  reconnectInitialMs?: number;
  reconnect_initial_ms?: number;
  reconnectMaxMs?: number;
  reconnect_max_ms?: number;
  reconnectMaxAttempts?: number;
  reconnect_max_attempts?: number;
  fenceTimeoutMs?: number;
  fence_timeout_ms?: number;
  daemonVersion?: string;
  daemon_version?: string;
  protocolVersion?: number;
  protocol_version?: number;
  /** Dependency injection seam for a real `ws` client or a mock tunnel. */
  createWebSocket?: (url: string, options: WebSocketClientOptions) => DeckAgentTunnelSocket;
  now?: () => number;
}

interface NormalizedChannelIdentity {
  meshId: string;
  agentId: string;
  instanceId: string;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: Error): void;
  settled: boolean;
}

interface OutboxRecord {
  sequence: number;
  envelope: unknown;
}

interface ChannelRecord {
  readonly identity: NormalizedChannelIdentity;
  state: DeckAgentChannelState;
  fence: number;
  receivedThrough: number;
  inboundReceivedThrough: number;
  nextSequence: number;
  highestSentSequence: number;
  readonly outbox: Map<number, OutboxRecord>;
  opening?: Deferred<void>;
  openingRequestId?: string;
  fenceTimer?: ReturnType<typeof setTimeout>;
}

interface PendingToolCall {
  channelKey: string;
  fence: number;
  kind: "open" | "envelope" | "close";
  sequence?: number;
  timer?: ReturnType<typeof setTimeout>;
}

type TunnelRecord = Record<string, unknown>;

const SOCKET_CONNECTING = 0;
const SOCKET_OPEN = 1;

function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (reason: Error) => void;
  const result: Deferred<T> = {
    promise: new Promise<T>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    }),
    resolve(value) {
      if (result.settled) return;
      result.settled = true;
      resolvePromise(value);
    },
    reject(reason) {
      if (result.settled) return;
      result.settled = true;
      rejectPromise(reason);
    },
    settled: false,
  };
  // Channel opens are often initiated by reconnection machinery rather than
  // an application awaiting the promise. Keep an internal rejection handler
  // so an intentional shutdown cannot become an unhandled rejection; callers
  // still receive the original promise and its rejection unchanged.
  void result.promise.catch(() => undefined);
  return result;
}

function isRecord(value: unknown): value is TunnelRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || value.includes("\0")) {
    throw new TypeError(`${name} must be a bounded non-empty string`);
  }
  return value;
}

function optionalNumber(value: unknown, fallback: number, name: string): number {
  const selected: unknown = value === undefined ? fallback : value;
  if (typeof selected !== "number" || !Number.isFinite(selected) || selected <= 0) {
    throw new RangeError(`${name} must be a positive finite number`);
  }
  return selected;
}

function optionValue(
  options: DeckAgentCarrierOptions,
  config: DeckAgentChannelConfig | undefined,
  camel: keyof DeckAgentCarrierOptions,
  snake: keyof DeckAgentCarrierOptions,
  configCamel: keyof DeckAgentChannelConfig,
  configSnake: keyof DeckAgentChannelConfig,
): unknown {
  return options[camel] ?? options[snake] ?? config?.[configCamel] ?? config?.[configSnake];
}

function normalizeIdentity(identity: DeckAgentChannelIdentity): NormalizedChannelIdentity {
  return {
    meshId: requiredString(identity.meshId ?? identity.mesh_id, "channel.mesh_id"),
    agentId: requiredString(identity.agentId ?? identity.agent_id, "channel.agent_id"),
    instanceId: requiredString(identity.instanceId ?? identity.instance_id, "channel.instance_id"),
  };
}

function channelKey(identity: NormalizedChannelIdentity): string {
  return `${identity.meshId}\0${identity.agentId}\0${identity.instanceId}`;
}

function eventReason(reason: unknown): string {
  if (typeof reason === "string") return reason;
  if (Buffer.isBuffer(reason) || reason instanceof Uint8Array) return Buffer.from(reason).toString("utf8");
  return "";
}

function dataText(data: unknown): string | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data) || data instanceof Uint8Array) return Buffer.from(data).toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  return undefined;
}

/**
 * A reconnecting, fenced DeckAgent tunnel adapter. It fulfils the public
 * `WireTransport` interface so it can be passed directly to PolyMesh clients
 * and brokers that consume a WebSocket-shaped transport.
 */
export class DeckAgentCarrier implements WireTransport {
  static readonly CONNECTING = SOCKET_CONNECTING;
  static readonly OPEN = SOCKET_OPEN;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly CONNECTING = DeckAgentCarrier.CONNECTING;
  readonly OPEN = DeckAgentCarrier.OPEN;
  readonly CLOSING = DeckAgentCarrier.CLOSING;
  readonly CLOSED = DeckAgentCarrier.CLOSED;
  readyState = DeckAgentCarrier.CONNECTING;
  onmessage?: (event: WireMessageEvent) => void;
  onclose?: (event: { code: number; reason: string }) => void;
  onerror?: (event: { error: Error }) => void;

  private readonly workerUrl: string;
  private readonly deviceId: string;
  private readonly token: string;
  private readonly daemonVersion?: string;
  private readonly protocolVersion: number;
  private readonly heartbeatMs: number;
  private readonly reconnectInitialMs: number;
  private readonly reconnectMaxMs: number;
  private readonly reconnectMaxAttempts: number;
  private readonly fenceTimeoutMs: number;
  private readonly now: () => number;
  private readonly createWebSocket: (url: string, options: WebSocketClientOptions) => DeckAgentTunnelSocket;
  private readonly channels = new Map<string, ChannelRecord>();
  private readonly pendingToolCalls = new Map<string, PendingToolCall>();
  private readonly defaultChannelKey: string;
  private readonly messageListeners = new Set<WireMessageListener>();
  private readonly closeListeners = new Set<WireCloseListener>();
  private readonly errorListeners = new Set<WireErrorListener>();
  private readonly openListeners = new Set<WireOpenListener>();
  /** Non-default channel consumers must opt in explicitly; never leak them onto the default wire. */
  private readonly channelMessageListeners = new Map<string, Set<WireMessageListener>>();

  private socket?: DeckAgentTunnelSocket;
  private state: DeckAgentConnectionState = "stopped";
  private bufferedData = "";
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private heartbeatTimeoutTimer?: ReturnType<typeof setTimeout>;
  private authTimeoutTimer?: ReturnType<typeof setTimeout>;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private reconnectDelay: number;
  private reconnectAttempts = 0;
  private shouldReconnect = true;
  private sessionId?: string;

  constructor(options: DeckAgentCarrierOptions) {
    const config = options.channelConfig ?? options.channel_config;
    this.workerUrl = requiredString(options.workerUrl ?? options.worker_url, "workerUrl");
    const endpoint = new URL(this.workerUrl);
    if (endpoint.protocol !== "wss:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
      throw new TypeError("DeckAgent internet carriers require a wss:// worker URL");
    }
    this.deviceId = requiredString(options.deviceId ?? options.device_id, "deviceId");
    this.token = requiredString(options.token, "token");
    this.daemonVersion = options.daemonVersion ?? options.daemon_version;
    this.protocolVersion = optionalNumber(options.protocolVersion ?? options.protocol_version, DECKAGENT_TUNNEL_PROTOCOL_VERSION, "protocolVersion");
    if (!Number.isSafeInteger(this.protocolVersion) || this.protocolVersion !== DECKAGENT_TUNNEL_PROTOCOL_VERSION) {
      throw new RangeError(`protocolVersion must be ${DECKAGENT_TUNNEL_PROTOCOL_VERSION}`);
    }
    this.heartbeatMs = optionalNumber(
      optionValue(options, config, "heartbeatMs", "heartbeat_ms", "heartbeatMs", "heartbeat_ms"),
      30_000,
      "heartbeatMs",
    );
    this.reconnectInitialMs = optionalNumber(
      optionValue(options, config, "reconnectInitialMs", "reconnect_initial_ms", "reconnectInitialMs", "reconnect_initial_ms"),
      DECKAGENT_RECONNECT_INITIAL_MS,
      "reconnectInitialMs",
    );
    this.reconnectMaxMs = optionalNumber(
      optionValue(options, config, "reconnectMaxMs", "reconnect_max_ms", "reconnectMaxMs", "reconnect_max_ms"),
      DECKAGENT_RECONNECT_MAX_MS,
      "reconnectMaxMs",
    );
    if (this.reconnectMaxMs < this.reconnectInitialMs) throw new RangeError("reconnectMaxMs must be at least reconnectInitialMs");
    this.reconnectMaxAttempts = optionalNumber(
      optionValue(options, config, "reconnectMaxAttempts", "reconnect_max_attempts", "reconnectMaxAttempts", "reconnect_max_attempts"),
      DECKAGENT_RECONNECT_MAX_ATTEMPTS,
      "reconnectMaxAttempts",
    );
    if (!Number.isSafeInteger(this.reconnectMaxAttempts)) throw new RangeError("reconnectMaxAttempts must be an integer");
    this.fenceTimeoutMs = optionalNumber(
      optionValue(options, config, "fenceTimeoutMs", "fence_timeout_ms", "fenceTimeoutMs", "fence_timeout_ms"),
      DECKAGENT_FENCE_TIMEOUT_MS,
      "fenceTimeoutMs",
    );
    this.now = options.now ?? Date.now;
    this.createWebSocket = options.createWebSocket ?? ((url, socketOptions) =>
      new WebSocket(url, socketOptions) as unknown as DeckAgentTunnelSocket);
    this.reconnectDelay = this.reconnectInitialMs;

    const identity = normalizeIdentity(options.channel);
    const key = channelKey(identity);
    this.defaultChannelKey = key;
    this.channels.set(key, this.newChannel(identity));
  }

  get isOpen(): boolean {
    return this.readyState === DeckAgentCarrier.OPEN;
  }

  getState(): DeckAgentConnectionState {
    return this.state;
  }

  /** Snapshot the default or a deliberately multiplexed channel. */
  getChannel(identity?: DeckAgentChannelIdentity): DeckAgentChannelSnapshot {
    const channel = this.channelFor(identity, false);
    if (!channel) throw new Error("DeckAgent virtual channel does not exist");
    return this.snapshot(channel);
  }

  /** Snapshot all channel leases without exposing mutable outbox records. */
  listChannels(): DeckAgentChannelSnapshot[] {
    return [...this.channels.values()].map((channel) => this.snapshot(channel));
  }

  /**
   * Inspect retained records without exposing the mutable outbox itself.
   * Records leave this list only after a matching durable receipt advances
   * `received_through`.
   */
  getOutbox(identity?: DeckAgentChannelIdentity): DeckAgentOutboxSnapshot[] {
    const channel = this.channelFor(identity, false);
    if (!channel) throw new Error("DeckAgent virtual channel does not exist");
    return [...channel.outbox.values()]
      .sort((left, right) => left.sequence - right.sequence)
      .map((record) => ({
        sequence: record.sequence,
        // parseWirePayload admitted only JSON, so cloning through JSON keeps
        // diagnostics from mutating replay state.
        envelope: JSON.parse(JSON.stringify(record.envelope)),
      }));
  }

  /**
   * Subscribe to one non-default virtual channel. The default channel also
   * emits the normal WireTransport `message` event; other channels are kept
   * isolated so one local agent cannot receive another agent's traffic.
   */
  onChannelMessage(
    identity: DeckAgentChannelIdentity,
    listener: WireMessageListener,
  ): () => void {
    const channel = this.channelFor(identity, true)!;
    const key = channelKey(channel.identity);
    const listeners = this.channelMessageListeners.get(key) ?? new Set<WireMessageListener>();
    listeners.add(listener);
    this.channelMessageListeners.set(key, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.channelMessageListeners.delete(key);
    };
  }

  /**
   * Start (or resume) the physical outbound WSS tunnel. The optional argument
   * exists solely to satisfy the historical WireTransport pairing surface;
   * virtual carriers intentionally do not use in-memory peers.
   */
  connect(_peer?: WireTransport): void {
    if (this.state === "connecting" || this.state === "authenticating" || this.state === "connected") return;
    // An explicit restart gets a fresh retry budget. Automatic backoff calls
    // openTunnel directly, preserving the exponential attempt sequence.
    if (this.reconnectAttempts >= this.reconnectMaxAttempts || this.readyState === DeckAgentCarrier.CLOSED) {
      this.reconnectAttempts = 0;
      this.reconnectDelay = this.reconnectInitialMs;
    }
    this.shouldReconnect = true;
    if (this.readyState === DeckAgentCarrier.CLOSED) this.readyState = DeckAgentCarrier.CONNECTING;
    this.clearReconnectTimer();
    this.openTunnel();
  }

  /** Open a virtual channel once the physical tunnel has authenticated. */
  openChannel(identity?: DeckAgentChannelIdentity): Promise<void> {
    const channel = this.channelFor(identity, true)!;
    if (channel.state === "ready") return Promise.resolve();
    if (!channel.opening || channel.opening.settled) channel.opening = deferred<void>();
    channel.state = "opening";
    if (this.state === "connected") this.sendChannelOpen(channel);
    else if (this.state === "stopped") this.connect();
    return channel.opening.promise;
  }

  /** Close just one virtual channel; the physical tunnel may host others. */
  closeChannel(identity?: DeckAgentChannelIdentity, code = 1000, reason = "channel closed"): void {
    const channel = this.channelFor(identity, false);
    if (!channel || channel.state === "closed") return;
    const wasDefault = channelKey(channel.identity) === this.defaultChannelKey;
    if (this.state === "connected" && channel.fence > 0) {
      const id = this.sendReservedTool({
        frame: this.channelFrame(channel, "pm.tunnel.close"),
      });
      if (id) this.trackPendingToolCall(id, { channelKey: channelKey(channel.identity), fence: channel.fence, kind: "close" });
    }
    this.clearFenceTimer(channel);
    channel.state = "closed";
    channel.opening?.reject(new Error(reason));
    channel.opening = undefined;
    channel.openingRequestId = undefined;
    if (wasDefault) this.finishVirtualClose(code, reason);
  }

  /** Send on a particular multiplexed channel rather than the default wire. */
  sendOnChannel(identity: DeckAgentChannelIdentity | undefined, data: WireData, callback?: (error?: Error) => void): void {
    const channel = this.channelFor(identity, false);
    if (!channel || channel.state !== "ready") {
      const error = new ProtocolError("TRANSPORT_CLOSED", "DeckAgent virtual channel is not ready", "routing", true);
      callback?.(error);
      this.emitError(error);
      throw error;
    }
    let envelope: unknown;
    try {
      envelope = this.parseWirePayload(data);
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      callback?.(error);
      this.emitError(error);
      throw error;
    }
    const record: OutboxRecord = { sequence: channel.nextSequence++, envelope };
    channel.outbox.set(record.sequence, record);
    try {
      this.dispatchOutboxRecord(channel, record);
      callback?.();
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      callback?.(error);
      this.emitError(error);
      throw error;
    }
  }

  /** WireTransport default-channel send method. */
  send(data: WireData, callback?: (error?: Error) => void): void {
    this.sendOnChannel(undefined, data, callback);
  }

  /** WebSocket-shaped close: it closes the default virtual channel. */
  close(code = 1000, reason = "carrier closed"): void {
    if (this.readyState === DeckAgentCarrier.CLOSED) return;
    this.readyState = DeckAgentCarrier.CLOSING;
    this.closeChannel(undefined, code, reason);
    // `close()` is the WireTransport terminal lifecycle operation. Individual
    // multiplexed channels use closeChannel(); a closed default transport must
    // not keep a tunnel, heartbeat, or reconnect loop alive behind its back.
    this.disconnect(code, reason);
  }

  terminate(): void {
    this.close(1000, "terminated");
  }

  /** Stop reconnecting, close the physical tunnel, and reject waiting opens. */
  disconnect(code = 1000, reason = "carrier shutdown"): void {
    this.shouldReconnect = false;
    this.clearReconnectTimer();
    this.clearAuthTimeout();
    this.stopHeartbeat();
    const socket = this.socket;
    this.socket = undefined;
    this.state = "stopped";
    this.sessionId = undefined;
    this.clearPendingToolCalls();
    for (const channel of this.channels.values()) {
      this.clearFenceTimer(channel);
      channel.state = "closed";
      channel.opening?.reject(new Error("DeckAgent carrier disconnected"));
      channel.opening = undefined;
      channel.openingRequestId = undefined;
    }
    if (socket) {
      try {
        socket.close?.(code, reason);
      } catch {
        socket.terminate?.();
      }
    }
    if (this.readyState !== DeckAgentCarrier.CLOSED) this.finishVirtualClose(code, reason);
  }

  on(event: "message", listener: WireMessageListener): this;
  on(event: "close", listener: WireCloseListener): this;
  on(event: "error", listener: WireErrorListener): this;
  on(event: "open", listener: WireOpenListener): this;
  on(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    if (event === "message") this.messageListeners.add(listener as WireMessageListener);
    else if (event === "close") this.closeListeners.add(listener as WireCloseListener);
    else if (event === "error") this.errorListeners.add(listener as WireErrorListener);
    else this.openListeners.add(listener as WireOpenListener);
    // PolyMeshClient waits on an `open` event when handed a CONNECTING
    // transport. Lazily begin the physical tunnel in that normal WebSocket
    // usage pattern instead of requiring a second, carrier-specific call.
    if (event === "open") this.ensureStarted();
    return this;
  }

  once(event: "message", listener: WireMessageListener): this;
  once(event: "close", listener: WireCloseListener): this;
  once(event: "error", listener: WireErrorListener): this;
  once(event: "open", listener: WireOpenListener): this;
  once(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    const wrapped = ((...args: unknown[]) => {
      if (event === "message") this.off("message", wrapped as WireMessageListener);
      else if (event === "close") this.off("close", wrapped as WireCloseListener);
      else if (event === "error") this.off("error", wrapped as WireErrorListener);
      else this.off("open", wrapped as WireOpenListener);
      (listener as (...values: unknown[]) => void)(...args);
    }) as WireMessageListener & WireCloseListener & WireErrorListener & WireOpenListener;
    if (event === "message") return this.on("message", wrapped as WireMessageListener);
    if (event === "close") return this.on("close", wrapped as WireCloseListener);
    if (event === "error") return this.on("error", wrapped as WireErrorListener);
    return this.on("open", wrapped as WireOpenListener);
  }

  off(event: "message", listener: WireMessageListener): this;
  off(event: "close", listener: WireCloseListener): this;
  off(event: "error", listener: WireErrorListener): this;
  off(event: "open", listener: WireOpenListener): this;
  off(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    if (event === "message") this.messageListeners.delete(listener as WireMessageListener);
    else if (event === "close") this.closeListeners.delete(listener as WireCloseListener);
    else if (event === "error") this.errorListeners.delete(listener as WireErrorListener);
    else this.openListeners.delete(listener as WireOpenListener);
    return this;
  }

  addEventListener(event: "message", listener: (event: WireMessageEvent) => void): void;
  addEventListener(event: "close", listener: (event: { code: number; reason: string }) => void): void;
  addEventListener(event: "error", listener: (event: { error: Error }) => void): void;
  addEventListener(event: "message" | "close" | "error", listener: ((event: WireMessageEvent) => void) | ((event: { code: number; reason: string }) => void) | ((event: { error: Error }) => void)): void {
    if (event === "message") this.on("message", (data) => (listener as (value: WireMessageEvent) => void)({ data }));
    else if (event === "close") this.on("close", (code, reason) => (listener as (value: { code: number; reason: string }) => void)({ code, reason: reason.toString("utf8") }));
    else this.on("error", (error) => (listener as (value: { error: Error }) => void)({ error }));
  }

  private newChannel(identity: NormalizedChannelIdentity): ChannelRecord {
    return {
      identity,
      state: "closed",
      fence: 0,
      receivedThrough: 0,
      inboundReceivedThrough: 0,
      nextSequence: 1,
      highestSentSequence: 0,
      outbox: new Map(),
    };
  }

  private channelFor(identity: DeckAgentChannelIdentity | undefined, create: boolean): ChannelRecord | undefined {
    if (identity === undefined) return this.channels.get(this.defaultChannelKey);
    const normalized = normalizeIdentity(identity);
    const key = channelKey(normalized);
    let channel = this.channels.get(key);
    if (!channel && create) {
      channel = this.newChannel(normalized);
      this.channels.set(key, channel);
    }
    return channel;
  }

  private snapshot(channel: ChannelRecord): DeckAgentChannelSnapshot {
    const { meshId, agentId, instanceId } = channel.identity;
    return {
      meshId,
      agentId,
      instanceId,
      mesh_id: meshId,
      agent_id: agentId,
      instance_id: instanceId,
      state: channel.state,
      fence: channel.fence,
      receivedThrough: channel.receivedThrough,
      received_through: channel.receivedThrough,
      inboundReceivedThrough: channel.inboundReceivedThrough,
      inbound_received_through: channel.inboundReceivedThrough,
      nextSequence: channel.nextSequence,
      outboxSize: channel.outbox.size,
    };
  }

  private openTunnel(): void {
    if (this.socket || !this.shouldReconnect) return;
    this.state = "connecting";
    this.bufferedData = "";
    if (this.readyState !== DeckAgentCarrier.CLOSED) this.readyState = DeckAgentCarrier.CONNECTING;
    let socket: DeckAgentTunnelSocket;
    try {
      const endpoint = new URL("/tunnel", this.workerUrl);
      endpoint.searchParams.set("device_id", this.deviceId);
      socket = this.createWebSocket(endpoint.toString(), {
        // The carrier is an internet transport. Keep redirects and implicit
        // compression out of this security boundary and require TLS 1.3.
        minVersion: "TLSv1.3",
        rejectUnauthorized: true,
        followRedirects: false,
        perMessageDeflate: false,
      });
    } catch (cause) {
      this.state = "stopped";
      this.emitError(cause instanceof Error ? cause : new Error(String(cause)));
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;
    this.bindSocket(socket);
    if (socket.readyState === SOCKET_OPEN) queueMicrotask(() => this.handleSocketOpen(socket));
  }

  private bindSocket(socket: DeckAgentTunnelSocket): void {
    const on = socket.on;
    if (typeof on !== "function") {
      this.handleSocketLoss(socket, new Error("DeckAgent WebSocket does not expose event listeners"));
      return;
    }
    on.call(socket, "open", () => this.handleSocketOpen(socket));
    on.call(socket, "message", (data: unknown, isBinary?: unknown) => this.handleSocketData(socket, data, isBinary === true));
    on.call(socket, "close", (code: unknown, reason: unknown) => this.handleSocketClose(socket, code, reason));
    on.call(socket, "error", (error: unknown) => this.handleSocketError(socket, error));
  }

  private handleSocketOpen(socket: DeckAgentTunnelSocket): void {
    if (socket !== this.socket || !this.shouldReconnect) return;
    this.state = "authenticating";
    this.sendTunnel({
      type: "auth",
      device_id: this.deviceId,
      token: this.token,
      protocol_version: this.protocolVersion,
      ...(this.daemonVersion === undefined ? {} : { daemon_version: this.daemonVersion }),
    });
    this.armAuthTimeout(socket);
  }

  private handleSocketData(socket: DeckAgentTunnelSocket, data: unknown, isBinary = false): void {
    if (socket !== this.socket) return;
    if (isBinary) {
      this.handleSocketLoss(socket, new Error("DeckAgent tunnel sent a binary record"));
      return;
    }
    const text = dataText(data);
    if (text === undefined) {
      this.emitError(new Error("DeckAgent tunnel sent a non-text record"));
      return;
    }
    this.bufferedData += text;
    if (Buffer.byteLength(this.bufferedData, "utf8") > MAX_FRAME_BYTES * 2) {
      this.handleSocketLoss(socket, new Error("DeckAgent tunnel line buffer exceeds its limit"));
      return;
    }
    let newline: number;
    while ((newline = this.bufferedData.indexOf("\n")) !== -1) {
      const line = this.bufferedData.slice(0, newline);
      this.bufferedData = this.bufferedData.slice(newline + 1);
      if (line.trim().length === 0) continue;
      if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) {
        this.handleSocketLoss(socket, new Error("DeckAgent tunnel record exceeds the protocol limit"));
        return;
      }
      const parsed = parseStrictJson(line, { maxBytes: MAX_FRAME_BYTES });
      if (!parsed.ok || !isRecord(parsed.value)) {
        this.handleSocketLoss(socket, new Error(parsed.ok ? "DeckAgent tunnel record must be an object" : parsed.error));
        return;
      }
      this.handleTunnelRecord(parsed.value);
    }
  }

  private handleSocketClose(socket: DeckAgentTunnelSocket, _code: unknown, reason: unknown): void {
    if (socket !== this.socket) return;
    this.handleSocketLoss(socket, new Error(eventReason(reason) || "DeckAgent tunnel closed"));
  }

  private handleSocketError(socket: DeckAgentTunnelSocket, error: unknown): void {
    if (socket !== this.socket) return;
    this.handleSocketLoss(socket, error instanceof Error ? error : new Error(String(error)));
  }

  private handleSocketLoss(socket: DeckAgentTunnelSocket, error: Error): void {
    if (socket !== this.socket) return;
    this.socket = undefined;
    try {
      socket.terminate?.();
    } catch {
      // The close/error callback is already handling the failed transport.
    }
    this.clearAuthTimeout();
    this.stopHeartbeat();
    this.state = "stopped";
    this.sessionId = undefined;
    this.clearPendingToolCalls();
    for (const channel of this.channels.values()) {
      this.clearFenceTimer(channel);
      if (channel.state === "ready" || channel.state === "opening") {
        channel.state = "opening";
        channel.openingRequestId = undefined;
        // A channel that was already ready has no caller waiting on a
        // promise. Re-open it after auth without manufacturing a rejected
        // promise during a later shutdown. An in-flight explicit open keeps
        // its original deferred and resolves after the replacement lease.
      }
    }
    if (this.readyState !== DeckAgentCarrier.CLOSED) this.readyState = DeckAgentCarrier.CONNECTING;
    this.emitError(error);
    if (this.shouldReconnect) this.scheduleReconnect();
  }

  private handleTunnelRecord(record: TunnelRecord): void {
    const type = record.type;
    if (type === "auth_ok") {
      this.handleAuthOk(record);
      return;
    }
    if (type === "auth_error") {
      const reason = typeof record.reason === "string" ? record.reason : "DeckAgent authentication failed";
      this.failAuthentication(reason);
      return;
    }
    if (type === "heartbeat_ack") {
      this.clearHeartbeatTimeout();
      return;
    }
    if (type === "tool_result") {
      this.handleToolResult(record);
      return;
    }
    if (type === "tool_error") {
      this.handleToolError(record);
      return;
    }
    if (type === "execute_tool") this.handleExecuteTool(record);
  }

  private handleAuthOk(record: TunnelRecord): void {
    if (this.state !== "authenticating") return;
    if (typeof record.session_id !== "string" || record.session_id.length === 0) {
      this.handleSocketLoss(this.socket!, new Error("DeckAgent auth_ok has no session ID"));
      return;
    }
    const minimumProtocol = this.nonnegativeInteger(record.min_protocol_version);
    if (minimumProtocol === undefined || minimumProtocol < 1 || minimumProtocol > this.protocolVersion) {
      this.failAuthentication("DeckAgent worker requires an unsupported tunnel protocol version");
      return;
    }
    this.clearAuthTimeout();
    this.sessionId = record.session_id;
    this.state = "connected";
    this.reconnectAttempts = 0;
    this.reconnectDelay = this.reconnectInitialMs;
    this.clearReconnectTimer();
    // DeckAgent's registry records the local reserved executor capability.
    // It remains a fixed protocol name and is never a user-supplied tool.
    this.sendTunnel({ type: "state_update", capabilities: [DECKAGENT_ENVELOPE_TOOL] });
    this.startHeartbeat();
    const defaultChannel = this.channels.get(this.defaultChannelKey);
    if (defaultChannel?.state === "closed") {
      // The public carrier itself is a transport for this channel, so it
      // should become usable after auth without an extra adapter-only call.
      void this.openChannel();
    }
    for (const channel of this.channels.values()) {
      if (channel.state === "opening") this.sendChannelOpen(channel);
    }
  }

  /** Fail authentication terminally; unlike a transport loss this never retries credentials. */
  private failAuthentication(reason: string): void {
    const socket = this.socket;
    this.socket = undefined;
    this.shouldReconnect = false;
    this.clearReconnectTimer();
    this.clearAuthTimeout();
    this.stopHeartbeat();
    this.state = "stopped";
    this.sessionId = undefined;
    this.clearPendingToolCalls();
    const error = new Error(reason);
    for (const channel of this.channels.values()) {
      this.clearFenceTimer(channel);
      channel.state = "closed";
      channel.opening?.reject(error);
      channel.opening = undefined;
      channel.openingRequestId = undefined;
    }
    try {
      socket?.close?.(1008, "auth_failed");
    } catch {
      socket?.terminate?.();
    }
    this.emitError(error);
    this.finishVirtualClose(1008, reason);
  }

  /** Bound the unauthenticated state so a black-holed tunnel cannot hang forever. */
  private armAuthTimeout(socket: DeckAgentTunnelSocket): void {
    this.clearAuthTimeout();
    if (socket !== this.socket || this.state !== "authenticating") return;
    this.authTimeoutTimer = setTimeout(() => {
      if (socket !== this.socket || this.state !== "authenticating") return;
      this.handleSocketLoss(socket, new Error("DeckAgent authentication timed out"));
    }, DECKAGENT_AUTH_TIMEOUT_MS);
    this.authTimeoutTimer.unref?.();
  }

  private clearAuthTimeout(): void {
    if (this.authTimeoutTimer) clearTimeout(this.authTimeoutTimer);
    this.authTimeoutTimer = undefined;
  }

  /** Track a reserved-tool request until its protocol-level result arrives. */
  private trackPendingToolCall(id: string, pending: PendingToolCall): void {
    this.clearPendingToolCall(id);
    pending.timer = setTimeout(() => {
      if (this.pendingToolCalls.get(id) !== pending) return;
      this.pendingToolCalls.delete(id);
      pending.timer = undefined;
      this.failPendingToolCall(pending, new Error("DeckAgent reserved tool timed out"));
    }, DECKAGENT_TOOL_TIMEOUT_MS);
    pending.timer.unref?.();
    this.pendingToolCalls.set(id, pending);
  }

  private takePendingToolCall(id: string): PendingToolCall | undefined {
    const pending = this.pendingToolCalls.get(id);
    if (!pending) return undefined;
    this.pendingToolCalls.delete(id);
    if (pending.timer) clearTimeout(pending.timer);
    pending.timer = undefined;
    return pending;
  }

  private clearPendingToolCall(id: string): void {
    const pending = this.pendingToolCalls.get(id);
    if (!pending) return;
    this.pendingToolCalls.delete(id);
    if (pending.timer) clearTimeout(pending.timer);
    pending.timer = undefined;
  }

  private clearPendingToolCalls(): void {
    for (const id of [...this.pendingToolCalls.keys()]) this.clearPendingToolCall(id);
  }

  /**
   * A `tool_result` is not a delivery receipt. Envelope failures retain their
   * outbox record and force a fresh fenced lease so it is replayed safely.
   */
  private failPendingToolCall(pending: PendingToolCall, error: Error): void {
    const channel = this.channels.get(pending.channelKey);
    if (pending.kind === "open") {
      if (channel && channel.fence === pending.fence) {
        this.clearFenceTimer(channel);
        channel.openingRequestId = undefined;
        const isDefault = channelKey(channel.identity) === this.defaultChannelKey;
        const socket = this.socket;
        // The default channel is the public WireTransport. A malformed or
        // timed-out lease response is indistinguishable from a broken tunnel
        // to its consumer, so reconnect under a fresh fence instead of
        // leaving a connected-looking but permanently unopened transport.
        if (isDefault && socket && this.state === "connected") {
          channel.state = "opening";
          this.handleSocketLoss(socket, error);
          return;
        }
        channel.state = "closed";
        channel.opening?.reject(error);
        channel.opening = undefined;
        if (isDefault) this.finishVirtualClose(1011, error.message);
      }
      this.emitError(error);
      return;
    }
    if (pending.kind === "envelope") {
      const socket = this.socket;
      if (socket && this.state === "connected") {
        this.handleSocketLoss(socket, error);
        return;
      }
    }
    this.emitError(error);
  }

  private handleToolResult(record: TunnelRecord): void {
    if (typeof record.id !== "string") return;
    const pending = this.takePendingToolCall(record.id);
    if (isRecord(record.result) && record.result.isError === true) {
      if (pending) this.failPendingToolCall(pending, new Error("DeckAgent reserved tool returned an error result"));
      return;
    }
    const payloads = this.toolResultPayloads(record);
    if (!pending) {
      // Tool results are correlated by their opaque request ID. A delayed or
      // forged result must never advance the active lease's receipt cursor.
      return;
    }
    const channel = this.channels.get(pending.channelKey);
    if (!channel || pending.fence !== channel.fence) return;
    if (pending.kind === "open") {
      const ready = payloads.find((payload) => payload.type === "pm.tunnel.ready");
      if (!ready) {
        this.failPendingToolCall(pending, new Error("DeckAgent virtual channel open did not return pm.tunnel.ready"));
        return;
      }
      this.acceptReady(channel, pending, ready);
      return;
    }
    if (pending.kind === "envelope") {
      const receipt = payloads.find((payload) =>
        payload.type === "pm.tunnel.delivery.receipt" &&
        this.matchesOptionalChannelFrame(channel, payload) &&
        payload.fence === pending.fence,
      );
      const receivedThrough = receipt === undefined ? undefined : this.nonnegativeInteger(receipt.received_through);
      if (
        receivedThrough === undefined || pending.sequence === undefined ||
        receivedThrough < pending.sequence || receivedThrough > channel.highestSentSequence
      ) {
        this.failPendingToolCall(pending, new Error("DeckAgent delivery did not return a durable receipt"));
        return;
      }
      this.acknowledgeOutbox(channel, receivedThrough);
      return;
    }
    // `pm.tunnel.close` is best-effort. A normal tool_result is sufficient;
    // a channel that is locally closed must not be resurrected by its reply.
  }

  private handleToolError(record: TunnelRecord): void {
    if (typeof record.id !== "string") return;
    const pending = this.takePendingToolCall(record.id);
    if (!pending) return;
    const message = isRecord(record.error) && typeof record.error.message === "string"
      ? record.error.message
      : "DeckAgent reserved tool failed";
    this.failPendingToolCall(pending, new Error(message));
  }

  private toolResultPayloads(record: TunnelRecord): TunnelRecord[] {
    const result = record.result;
    if (!isRecord(result) || !Array.isArray(result.content)) return [];
    const values: TunnelRecord[] = [];
    for (const content of result.content) {
      if (!isRecord(content) || typeof content.text !== "string") continue;
      const parsed = parseStrictJson(content.text, { maxBytes: MAX_FRAME_BYTES });
      // A normal DeckAgent tool may return arbitrary text. Only structured
      // reserved-tool frames are meaningful to the carrier.
      if (parsed.ok && isRecord(parsed.value)) values.push(parsed.value);
    }
    return values;
  }

  private acceptReady(channel: ChannelRecord, pending: PendingToolCall, frame: TunnelRecord): void {
    if (!this.matchesChannelFrame(channel, frame) || frame.fence !== pending.fence) {
      this.failPendingToolCall(pending, new Error("DeckAgent pm.tunnel.ready does not match the opening lease"));
      return;
    }
    const receivedThrough = this.nonnegativeInteger(frame.received_through);
    if (receivedThrough === undefined || receivedThrough > channel.highestSentSequence) {
      this.failPendingToolCall(pending, new Error("DeckAgent pm.tunnel.ready has an invalid received_through cursor"));
      return;
    }
    this.acknowledgeOutbox(channel, receivedThrough);
    this.clearFenceTimer(channel);
    channel.state = "ready";
    channel.openingRequestId = undefined;
    channel.opening?.resolve();
    channel.opening = undefined;
    if (channelKey(channel.identity) === this.defaultChannelKey) {
      this.readyState = DeckAgentCarrier.OPEN;
      this.emitOpen();
    }
    this.replayOutbox(channel);
  }

  private handleExecuteTool(record: TunnelRecord): void {
    if (record.tool !== DECKAGENT_ENVELOPE_TOOL || typeof record.id !== "string" || !isRecord(record.args)) return;
    const args = record.args;
    const frame = isRecord(args.frame) ? args.frame : undefined;
    if (!frame) return;
    const channel = this.channelFromFrame(frame);
    if (!channel || !this.matchesCurrentFence(channel, frame)) return;
    if (frame.type === "pm.tunnel.close") {
      this.handleTunnelFrame(frame, channel);
      // DeckAgent execute_tool requests must always conclude. Echo the
      // currently fenced close frame so a peer can retire its lease without
      // treating a normal virtual-channel close as a tool timeout.
      this.sendTunnel({
        type: "tool_result",
        id: record.id,
        result: {
          content: [{
            type: "text",
            text: JSON.stringify(this.channelFrame(channel, "pm.tunnel.close")),
          }],
        },
      });
      return;
    }
    if (frame.type !== "pm.tunnel.envelope") return;
    const sequence = this.nonnegativeInteger(frame.sequence);
    if (sequence === undefined || sequence === 0 || !("envelope" in args)) return;
    // received_through is a contiguous durable cursor. Never acknowledge a
    // gap, because doing so would let the relay discard an unseen envelope.
    if (sequence > channel.inboundReceivedThrough + 1) {
      this.sendInboundToolError(record.id, "OUT_OF_ORDER", "DeckAgent envelope sequence has a gap");
      return;
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(args.envelope as JsonValue);
    } catch {
      this.sendInboundToolError(record.id, "MALFORMED_ENVELOPE", "Reserved tool envelope is not JSON-serializable");
      return;
    }
    if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > MAX_FRAME_BYTES) {
      this.sendInboundToolError(record.id, "FRAME_TOO_LARGE", "Reserved tool envelope exceeds the PolyMesh frame limit");
      return;
    }
    if (sequence === channel.inboundReceivedThrough + 1) {
      try {
        // The cursor advances only after the local WireTransport consumer has
        // accepted the handoff. A durable v0.2 broker still emits its own
        // protocol receipt after committing its inbox; this tunnel result is
        // solely the carrier-level handoff acknowledgement.
        this.emitChannelMessage(channel, serialized, false);
        channel.inboundReceivedThrough = sequence;
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error(String(cause));
        this.emitError(error);
        this.sendInboundToolError(record.id, "LOCAL_DELIVERY_FAILED", "Local PolyMesh transport rejected the envelope");
        return;
      }
    }
    // An inbound execute_tool must always be concluded so the relay can
    // durably advance its own outbox. Duplicates are acknowledged but not
    // emitted a second time.
    this.sendTunnel({
      type: "tool_result",
      id: record.id,
      result: {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...this.channelFrame(channel, "pm.tunnel.delivery.receipt"),
            received_through: channel.inboundReceivedThrough,
          }),
        }],
      },
    });
  }

  private sendInboundToolError(id: string, code: string, message: string): void {
    this.sendTunnel({
      type: "tool_error",
      id,
      error: { code, message },
    });
  }

  private handleTunnelFrame(frame: TunnelRecord, hintedChannel?: ChannelRecord): void {
    const channel = hintedChannel ?? this.channelFromFrame(frame);
    if (!channel || !this.matchesOptionalChannelFrame(channel, frame) || frame.fence !== channel.fence) return;
    if (frame.type === "pm.tunnel.delivery.receipt") {
      if (channel.state !== "ready") return;
      const receivedThrough = this.nonnegativeInteger(frame.received_through);
      if (receivedThrough !== undefined) this.acknowledgeOutbox(channel, receivedThrough);
      return;
    }
    if (frame.type === "pm.tunnel.close") {
      if (channel.state === "closed") return;
      channel.state = "closed";
      this.clearFenceTimer(channel);
      channel.opening?.reject(new Error("DeckAgent channel closed by relay"));
      channel.opening = undefined;
      channel.openingRequestId = undefined;
      if (channelKey(channel.identity) === this.defaultChannelKey) this.finishVirtualClose(1000, "DeckAgent channel closed by relay");
    }
  }

  private sendChannelOpen(channel: ChannelRecord): void {
    if (this.state !== "connected" || channel.openingRequestId !== undefined) return;
    channel.fence += 1;
    const id = this.sendReservedTool({ frame: this.channelFrame(channel, "pm.tunnel.open") });
    if (!id) return;
    channel.openingRequestId = id;
    this.trackPendingToolCall(id, { channelKey: channelKey(channel.identity), fence: channel.fence, kind: "open" });
    this.clearFenceTimer(channel);
    channel.fenceTimer = setTimeout(() => {
      if (channel.state !== "opening" || channel.openingRequestId !== id) return;
      const pending = this.takePendingToolCall(id);
      if (pending) this.failPendingToolCall(pending, new Error("DeckAgent virtual channel lease timed out"));
    }, this.fenceTimeoutMs);
    channel.fenceTimer.unref?.();
  }

  private dispatchOutboxRecord(channel: ChannelRecord, record: OutboxRecord): void {
    if (this.state !== "connected" || channel.state !== "ready") {
      throw new ProtocolError("TRANSPORT_CLOSED", "DeckAgent channel cannot deliver while disconnected", "routing", true);
    }
    const id = this.sendReservedTool({
      envelope: record.envelope,
      frame: {
        ...this.channelFrame(channel, "pm.tunnel.envelope"),
        sequence: record.sequence,
      },
    });
    if (!id) throw new ProtocolError("TRANSPORT_CLOSED", "DeckAgent tunnel is not open", "routing", true);
    channel.highestSentSequence = Math.max(channel.highestSentSequence, record.sequence);
    this.trackPendingToolCall(id, {
      channelKey: channelKey(channel.identity),
      fence: channel.fence,
      kind: "envelope",
      sequence: record.sequence,
    });
  }

  private replayOutbox(channel: ChannelRecord): void {
    for (const record of [...channel.outbox.values()].sort((left, right) => left.sequence - right.sequence)) {
      if (record.sequence <= channel.receivedThrough) continue;
      try {
        this.dispatchOutboxRecord(channel, record);
      } catch (cause) {
        this.emitError(cause instanceof Error ? cause : new Error(String(cause)));
        return;
      }
    }
  }

  private acknowledgeOutbox(channel: ChannelRecord, receivedThrough: number): void {
    if (receivedThrough <= channel.receivedThrough) return;
    // A receipt may only settle records the local sender actually sequenced.
    // Treating a forged/faulty future cursor as authoritative would erase
    // unsent work and violate at-least-once replay guarantees.
    if (receivedThrough > channel.highestSentSequence) {
      this.emitError(new Error("DeckAgent receipt advances beyond the local outbox cursor"));
      return;
    }
    channel.receivedThrough = receivedThrough;
    for (const sequence of [...channel.outbox.keys()]) {
      if (sequence <= receivedThrough) channel.outbox.delete(sequence);
    }
    for (const [id, pending] of this.pendingToolCalls) {
      if (pending.channelKey === channelKey(channel.identity) && pending.kind === "envelope" &&
        pending.sequence !== undefined && pending.sequence <= receivedThrough) {
        this.clearPendingToolCall(id);
      }
    }
  }

  private channelFrame(channel: ChannelRecord, type: string): TunnelRecord {
    return {
      type,
      mesh_id: channel.identity.meshId,
      agent_id: channel.identity.agentId,
      instance_id: channel.identity.instanceId,
      fence: channel.fence,
      received_through: channel.receivedThrough,
    };
  }

  private channelFromFrame(frame: TunnelRecord): ChannelRecord | undefined {
    const meshId = frame.mesh_id;
    const agentId = frame.agent_id;
    const instanceId = frame.instance_id;
    if (typeof meshId !== "string" || typeof agentId !== "string" || typeof instanceId !== "string") return undefined;
    return this.channels.get(`${meshId}\0${agentId}\0${instanceId}`);
  }

  private matchesChannelFrame(channel: ChannelRecord, frame: TunnelRecord): boolean {
    return frame.mesh_id === channel.identity.meshId && frame.agent_id === channel.identity.agentId &&
      frame.instance_id === channel.identity.instanceId;
  }

  /** A correlated tool result may omit identity fields, but may not contradict them. */
  private matchesOptionalChannelFrame(channel: ChannelRecord, frame: TunnelRecord): boolean {
    return (frame.mesh_id === undefined || frame.mesh_id === channel.identity.meshId) &&
      (frame.agent_id === undefined || frame.agent_id === channel.identity.agentId) &&
      (frame.instance_id === undefined || frame.instance_id === channel.identity.instanceId);
  }

  /** Old-fence records are silently discarded; a newer lease must be opened locally first. */
  private matchesCurrentFence(channel: ChannelRecord, frame: TunnelRecord): boolean {
    return channel.state === "ready" && this.matchesChannelFrame(channel, frame) && frame.fence === channel.fence;
  }

  private nonnegativeInteger(value: unknown): number | undefined {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  }

  private parseWirePayload(data: WireData): unknown {
    let serialized: string;
    if (typeof data === "string") serialized = data;
    else if (Buffer.isBuffer(data) || data instanceof Uint8Array) serialized = Buffer.from(data).toString("utf8");
    else serialized = JSON.stringify(data);
    if (Buffer.byteLength(serialized, "utf8") > MAX_FRAME_BYTES) {
      throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${MAX_FRAME_BYTES} bytes`, "resource");
    }
    const parsed = parseStrictJson(serialized, { maxBytes: MAX_FRAME_BYTES });
    if (parsed.ok) return parsed.value;
    throw new ProtocolError(parsed.code, "DeckAgent carrier requires bounded strict JSON PolyMesh frames", parsed.code === "RESOURCE_EXHAUSTED" ? "resource" : "parse");
  }

  private sendReservedTool(args: TunnelRecord): string | undefined {
    const id = uuidv7(this.now());
    return this.sendTunnel({ type: "execute_tool", id, tool: DECKAGENT_ENVELOPE_TOOL, args }) ? id : undefined;
  }

  private sendTunnel(record: TunnelRecord): boolean {
    const socket = this.socket;
    if (!socket || socket.readyState !== undefined && socket.readyState !== SOCKET_OPEN) return false;
    let line: string;
    try {
      line = `${JSON.stringify(record)}\n`;
      if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) throw new Error("DeckAgent tunnel record exceeds the protocol limit");
      socket.send(line, (error) => {
        if (error && socket === this.socket) this.handleSocketLoss(socket, error);
      });
      return true;
    } catch (cause) {
      if (socket === this.socket) this.handleSocketLoss(socket, cause instanceof Error ? cause : new Error(String(cause)));
      return false;
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.sendHeartbeat();
    const period = Math.max(1, this.heartbeatMs - DECKAGENT_HEARTBEAT_GRACE_MS);
    this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), period);
    this.heartbeatTimer.unref?.();
  }

  private sendHeartbeat(): void {
    if (this.state !== "connected" || !this.sendTunnel({ type: "heartbeat", timestamp: this.now() })) return;
    // One outstanding acknowledgement covers any heartbeat retransmissions.
    // Resetting this watchdog on each 28s cadence would allow a silent peer
    // to keep a 45s timeout alive forever without acknowledging anything.
    if (this.heartbeatTimeoutTimer) return;
    this.heartbeatTimeoutTimer = setTimeout(() => {
      const socket = this.socket;
      if (!socket || this.state !== "connected") return;
      try {
        socket.terminate?.();
      } finally {
        this.handleSocketLoss(socket, new Error("DeckAgent heartbeat acknowledgement timed out"));
      }
    }, DECKAGENT_HEARTBEAT_ACK_TIMEOUT_MS);
    this.heartbeatTimeoutTimer.unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    this.clearHeartbeatTimeout();
  }

  private clearHeartbeatTimeout(): void {
    if (this.heartbeatTimeoutTimer) clearTimeout(this.heartbeatTimeoutTimer);
    this.heartbeatTimeoutTimer = undefined;
  }

  private scheduleReconnect(): void {
    if (!this.shouldReconnect || this.reconnectTimer) return;
    // The initial socket creation is attempt one. `reconnectAttempts` counts
    // only later scheduled retries, so permit at most N - 1 of those.
    if (this.reconnectAttempts >= this.reconnectMaxAttempts - 1) {
      this.shouldReconnect = false;
      this.state = "stopped";
      const error = new Error("DeckAgent reconnect attempt limit reached");
      for (const channel of this.channels.values()) {
        this.clearFenceTimer(channel);
        channel.state = "closed";
        channel.opening?.reject(error);
        channel.opening = undefined;
        channel.openingRequestId = undefined;
      }
      this.emitError(error);
      this.finishVirtualClose(1006, error.message);
      return;
    }
    const delay = this.reconnectDelay;
    this.reconnectAttempts += 1;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.reconnectMaxMs);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.openTunnel();
    }, delay);
    this.reconnectTimer.unref?.();
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
  }

  private clearFenceTimer(channel: ChannelRecord): void {
    if (channel.fenceTimer) clearTimeout(channel.fenceTimer);
    channel.fenceTimer = undefined;
  }

  private emitMessage(data: string, isBinary: boolean): void {
    for (const listener of this.messageListeners) listener(data, isBinary);
    this.onmessage?.({ data });
  }

  private emitChannelMessage(channel: ChannelRecord, data: string, isBinary: boolean): void {
    const key = channelKey(channel.identity);
    for (const listener of this.channelMessageListeners.get(key) ?? []) listener(data, isBinary);
    if (key === this.defaultChannelKey) this.emitMessage(data, isBinary);
  }

  private ensureStarted(): void {
    if (!this.shouldReconnect || this.socket || this.reconnectTimer || this.state !== "stopped") return;
    queueMicrotask(() => {
      if (this.shouldReconnect && !this.socket && !this.reconnectTimer && this.state === "stopped") this.connect();
    });
  }

  private emitOpen(): void {
    for (const listener of this.openListeners) listener();
  }

  private emitError(error: Error): void {
    for (const listener of this.errorListeners) listener(error);
    this.onerror?.({ error });
  }

  private finishVirtualClose(code: number, reason: string): void {
    if (this.readyState === DeckAgentCarrier.CLOSED) return;
    this.readyState = DeckAgentCarrier.CLOSED;
    const reasonBuffer = Buffer.from(reason);
    for (const listener of this.closeListeners) listener(code, reasonBuffer);
    this.onclose?.({ code, reason });
  }
}

export default DeckAgentCarrier;
