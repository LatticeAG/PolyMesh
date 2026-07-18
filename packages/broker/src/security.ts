/**
 * Security-sensitive transport primitives.
 *
 * Keeping these small helpers outside the WebSocket router makes the checks
 * easy to test without starting a listener.  None of the functions below
 * treat a bearer token as an agent identity; it is only loopback transport
 * admission material.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, rename, unlink } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import { basename, dirname, isAbsolute, join } from "node:path";

export const RUNTIME_TOKEN_BYTES = 32;
export const RUNTIME_TOKEN_BASE64URL_LENGTH = 43;
export const MAX_CLOSE_REASON_BYTES = 123;
export const POLYMESH_TLS_EXPORTER_LABEL = "EXPORTER-PolyMesh/0.1";

const RUNTIME_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const SENSITIVE_UPGRADE_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "upgrade",
  "connection",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-protocol",
  "sec-websocket-extensions",
  "origin",
  "x-polymesh-token",
  "authorization",
  "cookie",
]);

export interface TokenVerification {
  valid: boolean;
  /** The epoch of the token used to authenticate the session. */
  authEpoch?: number;
}

export interface TokenRotationOptions {
  /** Immediately invalidate the prior token and terminate old sessions. */
  hard?: boolean;
  /** Monotonic overlap for a normal rotation. Defaults to 30 seconds. */
  overlapMs?: number;
}

export interface RuntimeTokenFileOptions {
  /** Supply a token generated elsewhere; omitting it creates a new token. */
  token?: string;
}

export type UpgradeValidationResult =
  | { ok: true; token?: string; subprotocol?: string }
  | { ok: false; status: 400 | 403 | 426; statusText: string; headers?: Record<string, string> };

export interface StrictUpgradeOptions {
  path: string;
  /** Legacy one-profile form; it retains strict exact-header matching. */
  subprotocol?: string;
  /** Explicit opt-in profile set, used for separate v0.1/v0.2 sessions. */
  subprotocols?: readonly string[];
  allowedOrigins?: readonly string[];
}

interface TlsExporterSocket {
  encrypted?: boolean;
  getProtocol?: () => string | null;
  exportKeyingMaterial?: (length: number, label: string, context?: Buffer) => Buffer;
}

/**
 * Return a stable TLS 1.3 exporter binding for the current transport.  This
 * is intentionally best-effort only at the adapter boundary: a secure
 * identity handshake treats `undefined` as authentication failure rather
 * than replacing it with a session ID or nonce-derived surrogate.
 */
export function tlsChannelBinding(transport: unknown, exporterLabel = POLYMESH_TLS_EXPORTER_LABEL): string | undefined {
  const socket: TlsExporterSocket | undefined =
    typeof transport === "object" && transport !== null && "_socket" in transport
      ? (transport as { _socket?: TlsExporterSocket })._socket
      : transport as TlsExporterSocket | undefined;
  if (!socket || socket.encrypted !== true || socket.getProtocol?.() !== "TLSv1.3" || typeof socket.exportKeyingMaterial !== "function") {
    return undefined;
  }
  try {
    if (typeof exporterLabel !== "string" || exporterLabel.length === 0 || exporterLabel.length > 255) return undefined;
    const material = socket.exportKeyingMaterial(32, exporterLabel, Buffer.alloc(0));
    return Buffer.isBuffer(material) && material.byteLength === 32 ? material.toString("base64url") : undefined;
  } catch {
    return undefined;
  }
}

/** Decode only the canonical unpadded base64url encoding of 32 random bytes. */
export function decodeRuntimeToken(value: unknown): Buffer | undefined {
  if (typeof value !== "string" || !RUNTIME_TOKEN_RE.test(value)) return undefined;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === RUNTIME_TOKEN_BYTES && decoded.toString("base64url") === value
      ? decoded
      : undefined;
  } catch {
    return undefined;
  }
}

export function generateRuntimeToken(): string {
  return randomBytes(RUNTIME_TOKEN_BYTES).toString("base64url");
}

/**
 * Compare decoded, fixed-size token material in constant time.  Both compares
 * always run so malformed input cannot distinguish the current from previous
 * token through a simple timing oracle.
 */
export function verifyRuntimeToken(candidate: unknown, current: Buffer, previous?: Buffer): boolean {
  if (current.length !== RUNTIME_TOKEN_BYTES || (previous !== undefined && previous.length !== RUNTIME_TOKEN_BYTES)) {
    throw new TypeError("Runtime token state must contain 32-byte tokens");
  }
  const parsed = decodeRuntimeToken(candidate);
  const input = parsed ?? Buffer.alloc(RUNTIME_TOKEN_BYTES);
  const prior = previous ?? Buffer.alloc(RUNTIME_TOKEN_BYTES);
  const currentMatch = timingSafeEqual(input, current);
  const previousMatch = timingSafeEqual(input, prior);
  return parsed !== undefined && (currentMatch || previousMatch);
}

/**
 * In-memory token epochs.  Assignment is synchronous in Node's event loop,
 * so a caller never observes a partially rotated token state.  The file
 * helper below is intentionally separate because durable replacement has a
 * different failure model.
 */
export class RuntimeTokenAuthority {
  private current: Buffer;
  private previous?: Buffer;
  private previousUntil = 0;
  private readonly clock: () => number;
  private _authEpoch = 1;

  constructor(token: string, clock: () => number = Date.now) {
    const decoded = decodeRuntimeToken(token);
    if (!decoded) throw new TypeError("A runtime token must be exactly 32 random bytes encoded as base64url");
    this.current = decoded;
    this.clock = clock;
  }

  get authEpoch(): number {
    return this._authEpoch;
  }

  verify(candidate: unknown): TokenVerification {
    const now = this.clock();
    const priorActive = this.previous !== undefined && now < this.previousUntil;
    const parsed = decodeRuntimeToken(candidate);
    const input = parsed ?? Buffer.alloc(RUNTIME_TOKEN_BYTES);
    const prior = this.previous ?? Buffer.alloc(RUNTIME_TOKEN_BYTES);
    const currentMatch = timingSafeEqual(input, this.current);
    const previousMatch = timingSafeEqual(input, prior);
    if (parsed === undefined) return { valid: false };
    if (currentMatch) return { valid: true, authEpoch: this._authEpoch };
    if (previousMatch && priorActive) return { valid: true, authEpoch: this._authEpoch - 1 };
    return { valid: false };
  }

  rotate(token: string, options: TokenRotationOptions = {}): number {
    const next = decodeRuntimeToken(token);
    if (!next) throw new TypeError("A runtime token must be exactly 32 random bytes encoded as base64url");
    const hard = options.hard === true;
    const overlapMs = options.overlapMs ?? 30_000;
    if (!hard && (!Number.isFinite(overlapMs) || overlapMs < 0)) {
      throw new RangeError("Token overlap must be a non-negative finite duration");
    }
    const old = this.current;
    // One state transition: no listener can observe a new epoch with old
    // material or old epoch with new material.
    this.current = next;
    this.previous = hard ? undefined : old;
    this.previousUntil = hard ? 0 : this.clock() + overlapMs;
    this._authEpoch += 1;
    return this._authEpoch;
  }

  clearExpiredPrevious(): void {
    if (this.previous !== undefined && this.clock() >= this.previousUntil) {
      this.previous = undefined;
      this.previousUntil = 0;
    }
  }
}

/** Valid native WebSocket close codes, excluding reserved wire codes. */
export function isValidWebSocketCloseCode(value: unknown): value is number {
  if (typeof value !== "number" || !Number.isInteger(value)) return false;
  if (value >= 3000 && value <= 4999) return true;
  return [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014].includes(value);
}

/**
 * Normalize close metadata before it reaches callbacks or logs.  Close
 * reasons are transport diagnostics only and must never be interpreted as
 * protocol data or reconnect policy.
 */
export function sanitizeCloseReason(reason: unknown): string {
  return decodeCloseReason(reason).value;
}

function decodeCloseReason(reason: unknown): { valid: boolean; value: string } {
  const bytes = Buffer.isBuffer(reason)
    ? reason
    : typeof reason === "string"
      ? Buffer.from(reason, "utf8")
      : Buffer.alloc(0);
  if (bytes.byteLength > MAX_CLOSE_REASON_BYTES) return { valid: false, value: "invalid close reason" };
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { valid: true, value: decoded.replace(/[\u0000-\u001f\u007f]/g, "?") };
  } catch {
    return { valid: false, value: "invalid close reason" };
  }
}

export function normalizePeerClose(code: unknown, reason: unknown): { code: number; reason: string; valid: boolean } {
  const decoded = decodeCloseReason(reason);
  const valid = isValidWebSocketCloseCode(code) && decoded.valid;
  return {
    // 1002 is a local diagnostic for an invalid peer close; it is never sent
    // after an already-received close frame.
    code: isValidWebSocketCloseCode(code) ? code : 1002,
    reason: valid ? decoded.value : "invalid peer close",
    valid,
  };
}

/**
 * Validate a WebSocket upgrade from raw headers, before ws allocates a socket
 * or parses an extension.  Node's normalized `headers` object is deliberately
 * not used for duplicate-sensitive checks because it can merge values.
 */
export function validateWebSocketUpgrade(request: IncomingMessage, options: StrictUpgradeOptions): UpgradeValidationResult {
  const headers = rawHeaderMultimap(request.rawHeaders);
  if (request.method !== "GET" || request.httpVersion !== "1.1" || request.url !== options.path) {
    return badRequest();
  }
  for (const name of SENSITIVE_UPGRADE_HEADERS) {
    if ((headers.get(name)?.length ?? 0) > 1) return badRequest();
  }

  const host = onlyHeader(headers, "host");
  if (!host || !isValidHostHeader(host)) return badRequest();
  if (onlyHeader(headers, "upgrade")?.toLowerCase() !== "websocket") return badRequest();
  if (!hasSingleUpgradeConnectionToken(onlyHeader(headers, "connection"))) return badRequest();
  if (!isValidWebSocketKey(onlyHeader(headers, "sec-websocket-key"))) return badRequest();
  if (onlyHeader(headers, "sec-websocket-version") !== "13") return badRequest();
  const offeredHeader = onlyHeader(headers, "sec-websocket-protocol");
  const configured = options.subprotocols === undefined
    ? (options.subprotocol === undefined ? [] : [options.subprotocol])
    : [...options.subprotocols];
  if (configured.length === 0 || configured.some((protocol) => typeof protocol !== "string" || protocol.length === 0 || /[\s,]/.test(protocol))) {
    throw new TypeError("At least one valid WebSocket subprotocol is required");
  }
  let selected: string | undefined;
  if (options.subprotocols === undefined) {
    // Preserve the legacy endpoint's strict one-profile behaviour.
    selected = offeredHeader === options.subprotocol ? options.subprotocol : undefined;
  } else if (offeredHeader !== undefined) {
    const offered = offeredHeader.split(",").map((entry) => entry.trim());
    if (offered.length > 0 && offered.every((entry) => entry.length > 0) && new Set(offered).size === offered.length) {
      selected = configured.find((protocol) => offered.includes(protocol));
    }
  }
  if (selected === undefined) {
    return {
      ok: false,
      status: 426,
      statusText: "Upgrade Required",
      headers: { "Sec-WebSocket-Protocol": configured.join(", ") },
    };
  }
  if (headers.has("transfer-encoding") || (headers.has("content-length") && onlyHeader(headers, "content-length") !== "0")) {
    return badRequest();
  }
  // Extension negotiation is intentionally absent in the secure profile;
  // accepting an offer risks compression side channels and decompression DoS.
  if (headers.has("sec-websocket-extensions")) return badRequest();
  if (headers.has("authorization") || headers.has("cookie")) return badRequest();

  const origins = options.allowedOrigins ?? [];
  const origin = onlyHeader(headers, "origin");
  if (headers.has("origin") && (!origin || !origins.includes(origin))) {
    return { ok: false, status: 403, statusText: "Forbidden" };
  }

  return { ok: true, token: onlyHeader(headers, "x-polymesh-token"), subprotocol: selected };
}

/**
 * Durably replace a token file.  The parent must already be an owner-only,
 * non-symlinked runtime directory; unsafe paths fail closed rather than
 * weakening storage to a temporary directory.
 */
export async function writeRuntimeTokenAtomically(
  filePath: string,
  options: RuntimeTokenFileOptions = {},
): Promise<string> {
  if (!isAbsolute(filePath)) throw new TypeError("Runtime token path must be absolute");
  const directory = dirname(filePath);
  const fileName = basename(filePath);
  if (!fileName || fileName === "." || fileName === "..") throw new TypeError("Runtime token path is invalid");
  await assertOwnerOnlyDirectory(directory);
  const token = options.token ?? generateRuntimeToken();
  if (!decodeRuntimeToken(token)) throw new TypeError("A runtime token must be exactly 32 random bytes encoded as base64url");

  const temporary = join(directory, `.${fileName}.${randomBytes(16).toString("base64url")}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(token, "utf8");
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, filePath);
    await syncDirectory(directory);
    return token;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

function rawHeaderMultimap(rawHeaders: readonly string[]): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const rawName = rawHeaders[index];
    const rawValue = rawHeaders[index + 1];
    if (rawName === undefined || rawValue === undefined) continue;
    const name = rawName.toLowerCase();
    const values = result.get(name) ?? [];
    values.push(rawValue.trim());
    result.set(name, values);
  }
  return result;
}

function onlyHeader(headers: Map<string, string[]>, name: string): string | undefined {
  const values = headers.get(name);
  return values?.length === 1 ? values[0] : undefined;
}

function isValidHostHeader(value: string): boolean {
  return value.length > 0 && value.length <= 255 && !/[\s,\u0000-\u001f\u007f]/.test(value);
}

function hasSingleUpgradeConnectionToken(value: string | undefined): boolean {
  if (!value) return false;
  const tokens = value.split(",").map((token) => token.trim().toLowerCase());
  return tokens.length > 0 && tokens.every(Boolean) && tokens.filter((token) => token === "upgrade").length === 1;
}

function isValidWebSocketKey(value: string | undefined): boolean {
  if (!value || !/^[A-Za-z0-9+/]{22}==$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.byteLength === 16 && decoded.toString("base64") === value;
  } catch {
    return false;
  }
}

function badRequest(): UpgradeValidationResult {
  return { ok: false, status: 400, statusText: "Bad Request" };
}

async function assertOwnerOnlyDirectory(directory: string): Promise<void> {
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new TypeError("Runtime token directory must be a real directory");
  }
  if (typeof process.geteuid === "function" && metadata.uid !== process.geteuid()) {
    throw new TypeError("Runtime token directory must be owned by the current user");
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new TypeError("Runtime token directory must not be accessible by group or other users");
  }
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}
