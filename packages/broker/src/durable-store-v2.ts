/**
 * Small durable mailbox for the native `polymesh.0.2` profile.
 *
 * This store is intentionally independent from the legacy durable relay
 * tables.  It gives embedders that use the native profile a compact, stable
 * persistence boundary: an envelope and its target inbox entry are written in
 * one SQLite transaction, and SQLite's monotonically increasing `rowid` is
 * used as the replay cursor for SSE consumers.
 */

import Database from "better-sqlite3";

import {
  V2_PROTOCOL_VERSION,
  canonicalize,
  isJsonValue,
  type JsonObject,
  type JsonValue,
} from "./protocol.js";

export const V2_DURABLE_PROFILE = V2_PROTOCOL_VERSION;

export type V2InboxStatus = "pending" | "delivered" | "acknowledged" | "expired";

export interface V2EnvelopeRecord {
  id: string;
  mesh_id: string;
  profile: typeof V2_DURABLE_PROFILE;
  envelope: JsonObject;
  created_at: number;
}

export interface V2InboxRecord {
  /** SQLite rowid. It is a durable, opaque, increasing SSE cursor. */
  cursor: string;
  target: string;
  envelope_id: string;
  status: V2InboxStatus;
  delivered_at: number | null;
  envelope: V2EnvelopeRecord;
}

export interface V2TaskRecord {
  id: string;
  capability: string;
  input: JsonValue;
  status: string;
  executor: string | null;
  created_at: number;
}

/**
 * Input accepted by the atomic envelope + inbox operation.  Snake-case
 * fields mirror the wire/database names; camel-case aliases are accepted at
 * the public API boundary to make TypeScript callers less error-prone.
 */
export interface V2PersistEnvelopeInput {
  id: string;
  mesh_id?: string;
  meshId?: string;
  profile?: typeof V2_DURABLE_PROFILE;
  envelope: JsonObject;
  target: string;
  status?: V2InboxStatus;
  created_at?: number;
  createdAt?: number;
}

export interface V2PersistEnvelopeResult {
  disposition: "stored" | "duplicate";
  envelope: V2EnvelopeRecord;
  inbox: V2InboxRecord;
}

export interface V2InboxReplayOptions {
  target: string;
  /** Exclusive cursor: replay entries strictly after this cursor. */
  cursor?: string | number;
  limit?: number;
  statuses?: readonly V2InboxStatus[];
}

export interface V2InboxReplayPage {
  deliveries: readonly V2InboxRecord[];
  /** Cursor of the final returned entry; absent for an empty page. */
  next_cursor?: string;
}

export interface SqliteV2DurableStoreOptions {
  filename?: string;
  clock?: () => number;
}

type SqliteRow = Record<string, unknown>;

const INBOX_STATUSES = new Set<V2InboxStatus>(["pending", "delivered", "acknowledged", "expired"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyText(value: unknown, name: string, maximum = 1_024): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${name} must be a bounded non-empty string`);
  }
  return value;
}

function timestamp(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function inboxStatus(value: unknown): V2InboxStatus {
  if (typeof value !== "string" || !INBOX_STATUSES.has(value as V2InboxStatus)) {
    throw new TypeError("status is not a supported v2 inbox status");
  }
  return value as V2InboxStatus;
}

function jsonObject(value: unknown, name: string): JsonObject {
  if (!isRecord(value) || !isJsonValue(value)) throw new TypeError(`${name} must be a bounded JSON object`);
  // Canonicalize before persistence. This provides deterministic dedupe while
  // also stripping exotic prototypes/accessors from the stored value.
  try {
    const parsed = JSON.parse(canonicalize(value as JsonObject)) as unknown;
    if (!isRecord(parsed)) throw new TypeError(`${name} must be a JSON object`);
    return parsed as JsonObject;
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`${name} cannot be serialized as canonical JSON`);
  }
}

function jsonValue(value: unknown, name: string): JsonValue {
  if (!isJsonValue(value)) throw new TypeError(`${name} must be a bounded JSON value`);
  try {
    return JSON.parse(canonicalize(value as JsonValue)) as JsonValue;
  } catch {
    throw new TypeError(`${name} cannot be serialized as canonical JSON`);
  }
}

function parseCursor(value: string | number | undefined): number {
  if (value === undefined) return 0;
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new TypeError("cursor must be a non-negative SQLite rowid");
  return parsed;
}

function boundedLimit(value: number | undefined): number {
  if (value === undefined) return 100;
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000) throw new RangeError("limit must be an integer between 1 and 1000");
  return value;
}

function recordsEqual(left: V2EnvelopeRecord, right: V2EnvelopeRecord): boolean {
  return left.mesh_id === right.mesh_id &&
    left.profile === right.profile &&
    canonicalize(left.envelope) === canonicalize(right.envelope);
}

/**
 * SQLite implementation of the native v2 mailbox. Mutating calls use
 * `BEGIN IMMEDIATE`; a caller never observes a stored envelope without the
 * target inbox row that makes it replayable.
 */
export class SqliteV2DurableStore {
  private readonly db: Database.Database;
  private readonly clock: () => number;

  constructor(options: SqliteV2DurableStoreOptions | string = {}) {
    const normalized = typeof options === "string" ? { filename: options } : options;
    this.clock = normalized.clock ?? Date.now;
    this.db = new Database(normalized.filename ?? ":memory:");
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  /** Execute a synchronous operation in one immediate SQLite transaction. */
  async transaction<T>(operation: (store: this) => T): Promise<T> {
    return this.immediate(() => operation(this));
  }

  /**
   * Atomically write the canonical envelope and target inbox record. A repeat
   * of the same immutable envelope is a duplicate; reuse of its id with
   * different content fails closed.
   */
  async persistEnvelopeAndInbox(input: V2PersistEnvelopeInput): Promise<V2PersistEnvelopeResult> {
    const normalized = this.normalizePersistInput(input);
    return this.immediate(() => {
      const current = this.envelopeFromRow(this.db.prepare("SELECT * FROM v2_envelopes WHERE id = ?").get(normalized.id));
      if (current !== undefined && !recordsEqual(current, normalized)) {
        throw new V2DurableConflictError("V2_ENVELOPE_ID_CONFLICT", "Envelope id was reused with different immutable content");
      }
      if (current === undefined) {
        this.db.prepare(`INSERT INTO v2_envelopes (id, mesh_id, profile, envelope, created_at)
          VALUES (?, ?, ?, ?, ?)`).run(
          normalized.id,
          normalized.mesh_id,
          normalized.profile,
          canonicalize(normalized.envelope),
          normalized.created_at,
        );
      }

      const existingInbox = this.inboxFromRow(this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
        i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
        FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
        WHERE i.target = ? AND i.envelope_id = ?`).get(normalized.target, normalized.id));
      if (existingInbox !== undefined) {
        return { disposition: "duplicate" as const, envelope: current ?? normalized, inbox: existingInbox };
      }
      this.db.prepare(`INSERT INTO v2_inbox (target, envelope_id, status, delivered_at)
        VALUES (?, ?, ?, NULL)`).run(normalized.target, normalized.id, normalized.status);
      const inbox = this.inboxFromRow(this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
        i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
        FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
        WHERE i.target = ? AND i.envelope_id = ?`).get(normalized.target, normalized.id));
      if (!inbox) throw new Error("SQLite did not return the newly inserted v2 inbox row");
      return { disposition: "stored" as const, envelope: current ?? normalized, inbox };
    });
  }

  /** Friendly aliases for gateway/relay adapters. */
  async persistEnvelope(input: V2PersistEnvelopeInput): Promise<V2PersistEnvelopeResult> {
    return this.persistEnvelopeAndInbox(input);
  }

  async insertEnvelopeAndDeliver(input: V2PersistEnvelopeInput): Promise<V2PersistEnvelopeResult> {
    return this.persistEnvelopeAndInbox(input);
  }

  async getEnvelope(id: string): Promise<V2EnvelopeRecord | undefined> {
    return this.envelopeFromRow(this.db.prepare("SELECT * FROM v2_envelopes WHERE id = ?").get(nonEmptyText(id, "id")));
  }

  async getInbox(target: string, envelopeId: string): Promise<V2InboxRecord | undefined> {
    return this.inboxFromRow(this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
      i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
      FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
      WHERE i.target = ? AND i.envelope_id = ?`).get(
      nonEmptyText(target, "target"), nonEmptyText(envelopeId, "envelopeId"),
    ));
  }

  /**
   * Read durable target deliveries after an exclusive cursor. This is the
   * direct SSE replay primitive; callers can use `next_cursor` as the next
   * Last-Event-ID/cursor value without synthesizing an event sequence.
   */
  async replayInbox(options: V2InboxReplayOptions): Promise<V2InboxReplayPage> {
    const target = nonEmptyText(options.target, "target");
    const cursor = parseCursor(options.cursor);
    const limit = boundedLimit(options.limit);
    const statuses = options.statuses === undefined ? undefined : [...new Set(options.statuses.map(inboxStatus))];
    const where = ["i.target = ?", "i.rowid > ?"];
    const values: Array<string | number> = [target, cursor];
    if (statuses?.length) {
      where.push(`i.status IN (${statuses.map(() => "?").join(", ")})`);
      values.push(...statuses);
    }
    values.push(limit);
    const rows = this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
      i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
      FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
      WHERE ${where.join(" AND ")} ORDER BY i.rowid ASC LIMIT ?`).all(...values) as SqliteRow[];
    const deliveries = rows.map((row) => this.inboxFromRow(row)).filter((row): row is V2InboxRecord => row !== undefined);
    return {
      deliveries,
      ...(deliveries.length === 0 ? {} : { next_cursor: deliveries[deliveries.length - 1]!.cursor }),
    };
  }

  /** Aliases that read naturally from an SSE/gateway adapter. */
  async readEvents(options: V2InboxReplayOptions): Promise<V2InboxReplayPage> {
    return this.replayInbox(options);
  }

  async listInbox(options: V2InboxReplayOptions): Promise<readonly V2InboxRecord[]> {
    return (await this.replayInbox(options)).deliveries;
  }

  /** Mark one durable delivery observed by its target. */
  async markDelivered(target: string, envelopeId: string, deliveredAt = this.clock()): Promise<V2InboxRecord | undefined> {
    const safeTarget = nonEmptyText(target, "target");
    const safeEnvelopeId = nonEmptyText(envelopeId, "envelopeId");
    const at = timestamp(deliveredAt, "deliveredAt");
    return this.immediate(() => {
      this.db.prepare(`UPDATE v2_inbox SET status = 'delivered', delivered_at = COALESCE(delivered_at, ?)
        WHERE target = ? AND envelope_id = ? AND status IN ('pending', 'delivered')`).run(at, safeTarget, safeEnvelopeId);
      return this.inboxFromRow(this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
        i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
        FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
        WHERE i.target = ? AND i.envelope_id = ?`).get(safeTarget, safeEnvelopeId));
    });
  }

  async acknowledgeInbox(target: string, envelopeId: string, deliveredAt = this.clock()): Promise<V2InboxRecord | undefined> {
    const safeTarget = nonEmptyText(target, "target");
    const safeEnvelopeId = nonEmptyText(envelopeId, "envelopeId");
    const at = timestamp(deliveredAt, "deliveredAt");
    return this.immediate(() => {
      this.db.prepare(`UPDATE v2_inbox SET status = 'acknowledged', delivered_at = COALESCE(delivered_at, ?)
        WHERE target = ? AND envelope_id = ? AND status != 'expired'`).run(at, safeTarget, safeEnvelopeId);
      return this.inboxFromRow(this.db.prepare(`SELECT i.rowid AS cursor, i.target, i.envelope_id,
        i.status, i.delivered_at, e.id, e.mesh_id, e.profile, e.envelope, e.created_at
        FROM v2_inbox i JOIN v2_envelopes e ON e.id = i.envelope_id
        WHERE i.target = ? AND i.envelope_id = ?`).get(safeTarget, safeEnvelopeId));
    });
  }

  /** Upsert task lifecycle metadata without storing a second envelope body. */
  async putTask(record: Omit<V2TaskRecord, "executor" | "created_at"> & { executor?: string | null; created_at?: number; createdAt?: number }): Promise<V2TaskRecord> {
    const id = nonEmptyText(record.id, "task id");
    const capability = nonEmptyText(record.capability, "capability");
    const input = jsonValue(record.input, "task input");
    const status = nonEmptyText(record.status, "task status");
    const executor = record.executor === undefined || record.executor === null ? null : nonEmptyText(record.executor, "executor");
    const createdAt = timestamp(record.created_at ?? record.createdAt ?? this.clock(), "createdAt");
    return this.immediate(() => {
      this.db.prepare(`INSERT INTO v2_tasks (id, capability, input, status, executor, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET capability = excluded.capability, input = excluded.input,
          status = excluded.status, executor = excluded.executor`).run(
        id, capability, canonicalize(input), status, executor, createdAt,
      );
      const stored = this.taskFromRow(this.db.prepare("SELECT * FROM v2_tasks WHERE id = ?").get(id));
      if (!stored) throw new Error("SQLite did not return the stored v2 task");
      return stored;
    });
  }

  async createTask(record: Omit<V2TaskRecord, "executor" | "created_at"> & { executor?: string | null; created_at?: number; createdAt?: number }): Promise<V2TaskRecord> {
    return this.putTask(record);
  }

  async getTask(id: string): Promise<V2TaskRecord | undefined> {
    return this.taskFromRow(this.db.prepare("SELECT * FROM v2_tasks WHERE id = ?").get(nonEmptyText(id, "task id")));
  }

  /** Purge terminal/acknowledged delivery records up to a caller-owned TTL. */
  async compactAcknowledged(before: number): Promise<number> {
    const cutoff = timestamp(before, "before");
    return this.immediate(() => this.db.prepare(`DELETE FROM v2_inbox
      WHERE status = 'acknowledged' AND delivered_at IS NOT NULL AND delivered_at <= ?`).run(cutoff).changes);
  }

  private normalizePersistInput(input: V2PersistEnvelopeInput): V2EnvelopeRecord & { target: string; status: V2InboxStatus } {
    const id = nonEmptyText(input.id, "id");
    const meshId = input.mesh_id ?? input.meshId;
    const mesh_id = nonEmptyText(meshId, "mesh_id");
    const profile = input.profile ?? V2_DURABLE_PROFILE;
    if (profile !== V2_DURABLE_PROFILE) throw new TypeError(`profile must be ${V2_DURABLE_PROFILE}`);
    return {
      id,
      mesh_id,
      profile,
      envelope: jsonObject(input.envelope, "envelope"),
      created_at: timestamp(input.created_at ?? input.createdAt ?? this.clock(), "createdAt"),
      target: nonEmptyText(input.target, "target"),
      status: input.status === undefined ? "pending" : inboxStatus(input.status),
    };
  }

  private immediate<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      if (result && typeof (result as { then?: unknown }).then === "function") {
        throw new TypeError("SQLite v2 durable transactions cannot cross an await");
      }
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction is already closed */ }
      throw error;
    }
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v2_envelopes (
        id TEXT PRIMARY KEY,
        mesh_id TEXT NOT NULL,
        profile TEXT NOT NULL,
        envelope TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v2_inbox (
        target TEXT NOT NULL,
        envelope_id TEXT NOT NULL REFERENCES v2_envelopes(id) ON DELETE CASCADE,
        status TEXT NOT NULL,
        delivered_at INTEGER,
        UNIQUE (target, envelope_id)
      );
      CREATE TABLE IF NOT EXISTS v2_tasks (
        id TEXT PRIMARY KEY,
        capability TEXT NOT NULL,
        input TEXT NOT NULL,
        status TEXT NOT NULL,
        executor TEXT,
        created_at INTEGER NOT NULL
      );
      -- SQLite's implicit rowid is already ordered.  It cannot appear in an
      -- explicit index definition, so index the target filter only.
      CREATE INDEX IF NOT EXISTS idx_v2_inbox_target ON v2_inbox (target);
      CREATE INDEX IF NOT EXISTS idx_v2_envelopes_created ON v2_envelopes (mesh_id, created_at);
    `);
  }

  private envelopeFromRow(row: unknown): V2EnvelopeRecord | undefined {
    if (!isRecord(row)) return undefined;
    try {
      const envelope = JSON.parse(nonEmptyText(row.envelope, "stored envelope")) as unknown;
      return {
        id: nonEmptyText(row.id, "stored envelope id"),
        mesh_id: nonEmptyText(row.mesh_id, "stored mesh id"),
        profile: (() => {
          if (row.profile !== V2_DURABLE_PROFILE) throw new TypeError("stored profile is unsupported");
          return V2_DURABLE_PROFILE;
        })(),
        envelope: jsonObject(envelope, "stored envelope"),
        created_at: timestamp(row.created_at, "stored created_at"),
      };
    } catch {
      throw new TypeError("Stored v2 envelope is corrupt");
    }
  }

  private inboxFromRow(row: unknown): V2InboxRecord | undefined {
    if (!isRecord(row)) return undefined;
    const envelope = this.envelopeFromRow(row);
    if (!envelope) return undefined;
    const deliveredAt = row.delivered_at === null || row.delivered_at === undefined
      ? null
      : timestamp(row.delivered_at, "stored delivered_at");
    return {
      cursor: String(timestamp(typeof row.cursor === "number" ? row.cursor : Number(row.cursor), "stored cursor")),
      target: nonEmptyText(row.target, "stored target"),
      envelope_id: nonEmptyText(row.envelope_id, "stored envelope id"),
      status: inboxStatus(row.status),
      delivered_at: deliveredAt,
      envelope,
    };
  }

  private taskFromRow(row: unknown): V2TaskRecord | undefined {
    if (!isRecord(row)) return undefined;
    try {
      return {
        id: nonEmptyText(row.id, "stored task id"),
        capability: nonEmptyText(row.capability, "stored task capability"),
        input: jsonValue(JSON.parse(nonEmptyText(row.input, "stored task input")), "stored task input"),
        status: nonEmptyText(row.status, "stored task status"),
        executor: row.executor === null || row.executor === undefined ? null : nonEmptyText(row.executor, "stored task executor"),
        created_at: timestamp(row.created_at, "stored task created_at"),
      };
    } catch {
      throw new TypeError("Stored v2 task is corrupt");
    }
  }
}

/** Clear, discoverable aliases for consumers that do not care about SQLite. */
export const V2DurableStore = SqliteV2DurableStore;
/** Runtime implementation name; `NativeV2DurableStore` is the broker interface. */
export const NativeV2SqliteDurableStore = SqliteV2DurableStore;

export class V2DurableConflictError extends Error {
  readonly code: "V2_ENVELOPE_ID_CONFLICT";

  constructor(code: "V2_ENVELOPE_ID_CONFLICT", message: string) {
    super(message);
    this.name = "V2DurableConflictError";
    this.code = code;
  }
}
