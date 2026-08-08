/**
 * Adapter-local outbound idempotency / dedup store (§A.12).
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { A2ADialectError } from "./errors.js";
import { fingerprintPayload } from "./task-translator.js";
import type { OutboundResult } from "./types.js";
import { IDEMPOTENCY_RETENTION_MS } from "./types.js";

export const IDEMPOTENCY_MIN_RETENTION_MS = IDEMPOTENCY_RETENTION_MS;

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function payloadDigest(input: unknown): string {
  return createHash("sha256").update(canonicalJson(input ?? null), "utf8").digest("hex");
}

export interface IdempotencyRecord {
  dedup_key: string;
  key?: string;
  fingerprint: string;
  payload_digest: string;
  task_id: string;
  remote_task_id?: string;
  created_at: number;
  expires_at: number;
  result?: OutboundResult;
}

export class IdempotencyStore {
  private readonly map = new Map<string, IdempotencyRecord>();
  private readonly path?: string;
  readonly retentionMs: number;

  constructor(options?: { path?: string; filePath?: string; retentionMs?: number }) {
    this.path = options?.path ?? options?.filePath;
    this.retentionMs = Math.max(
      options?.retentionMs ?? IDEMPOTENCY_MIN_RETENTION_MS,
      IDEMPOTENCY_MIN_RETENTION_MS,
    );
    this.load();
  }

  static fingerprint(input: {
    principal_id?: string;
    capability_id: string;
    payload: unknown;
    task_id?: string;
    idempotency_key?: string;
  }): { dedup_key: string; fingerprint: string; payload_digest: string } {
    const includeTaskId = !input.idempotency_key;
    const fingerprint = fingerprintPayload({
      principal_id: input.principal_id,
      capability_id: input.capability_id,
      input: input.payload,
      task_id: input.task_id,
      includeTaskId,
    });
    const digest = payloadDigest(input.payload);
    const dedup_key = input.idempotency_key ?? fingerprint;
    return { dedup_key, fingerprint, payload_digest: digest };
  }

  lookup(dedupKey: string): IdempotencyRecord | undefined {
    this.purgeExpired();
    const rec = this.map.get(dedupKey);
    if (!rec) return undefined;
    if (rec.expires_at <= Date.now()) {
      this.map.delete(dedupKey);
      this.persist();
      return undefined;
    }
    return rec;
  }

  get(key: string, nowMs: number = Date.now()): IdempotencyRecord | undefined {
    const rec = this.map.get(key);
    if (!rec) return undefined;
    if (rec.expires_at <= nowMs) {
      this.map.delete(key);
      return undefined;
    }
    return rec;
  }

  put(record: IdempotencyRecord): void {
    this.map.set(record.dedup_key ?? record.key!, record);
    this.persist();
  }

  checkOrThrow(input: {
    principal_id?: string;
    capability_id: string;
    payload: unknown;
    task_id: string;
    idempotency_key?: string;
  }): { hit: IdempotencyRecord | null; meta: ReturnType<typeof IdempotencyStore.fingerprint> } {
    const meta = IdempotencyStore.fingerprint(input);
    const existing = this.lookup(meta.dedup_key);
    if (!existing) return { hit: null, meta };
    if (existing.payload_digest !== meta.payload_digest) {
      throw new A2ADialectError(
        "IDEMPOTENCY_CONFLICT",
        "idempotency key reused with different payload",
      );
    }
    return { hit: existing, meta };
  }

  store(
    meta: ReturnType<typeof IdempotencyStore.fingerprint>,
    taskId: string,
    remoteTaskId?: string,
  ): void {
    const now = Date.now();
    this.map.set(meta.dedup_key, {
      dedup_key: meta.dedup_key,
      key: meta.dedup_key,
      fingerprint: meta.fingerprint,
      payload_digest: meta.payload_digest,
      task_id: taskId,
      remote_task_id: remoteTaskId,
      created_at: now,
      expires_at: now + this.retentionMs,
    });
    this.persist();
  }

  complete(dedupKey: string, result: OutboundResult): void {
    const rec = this.map.get(dedupKey);
    if (!rec) return;
    rec.result = result;
    rec.remote_task_id = result.remote_task_id;
    this.persist();
  }

  size(): number {
    return this.map.size;
  }

  private purgeExpired(): void {
    const now = Date.now();
    let changed = false;
    for (const [k, v] of this.map) {
      if (v.expires_at <= now) {
        this.map.delete(k);
        changed = true;
      }
    }
    if (changed) this.persist();
  }

  private load(): void {
    if (!this.path || !existsSync(this.path)) return;
    try {
      const raw = JSON.parse(readFileSync(this.path, "utf8")) as IdempotencyRecord[];
      for (const rec of raw) this.map.set(rec.dedup_key ?? rec.key!, rec);
    } catch {
      // ignore
    }
  }

  private persist(): void {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify([...this.map.values()]));
  }
}

/** Alias retained for agent-written call sites. */
export class MemoryIdempotencyStore extends IdempotencyStore {}
