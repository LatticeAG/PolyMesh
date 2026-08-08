/**
 * Lifecycle translation between PolyMesh and A2A task states
 * (PM-V6-SPEC §A.6.3–§A.6.5, §A.9.3, §A.10.6, §A.17.4, §A.18).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

import { uuidv7 } from "@latticeag/polymesh-broker";

import { skillNameFromCapabilityName, fidelityClause } from "./card-mapper.js";
import { mapA2ATaskErrorToPolyMesh } from "./errors.js";
import type {
  A2AArtifact,
  A2ATask,
  A2ATaskState,
  PolyMeshTaskState,
} from "./types.js";
import { TERMINAL_A2A_STATES, TERMINAL_POLYMESH_STATES } from "./types.js";

/** §A.6.3 forward projection (PolyMesh → A2A). */
export const POLYMESH_TO_A2A_STATE: Readonly<Record<PolyMeshTaskState, A2ATaskState>> =
  Object.freeze({
    SUBMITTED: "submitted",
    REJECTED: "failed",
    ACCEPTED: "working",
    QUEUED: "working",
    RUNNING: "working",
    WAITING: "working",
    SUCCEEDED: "completed",
    FAILED: "failed",
    CANCELLED: "canceled",
  });

/**
 * §A.6.3 inverse used for outbound status consumption (§A.9.3).
 * `submitted` is treated as `ACCEPTED` once the send ack has been received.
 */
export const A2A_TO_POLYMESH_STATE: Readonly<Record<A2ATaskState, PolyMeshTaskState>> =
  Object.freeze({
    submitted: "ACCEPTED",
    working: "RUNNING",
    completed: "SUCCEEDED",
    failed: "FAILED",
    canceled: "CANCELLED",
  });

export function isTerminalA2AState(state: A2ATaskState): boolean {
  return TERMINAL_A2A_STATES.includes(state);
}

export function isTerminalPolyMeshState(state: PolyMeshTaskState): boolean {
  return TERMINAL_POLYMESH_STATES.includes(state);
}

/**
 * Monotonic ordering rank (§A.10.6). Terminal states share the top rank so a
 * stale poll can never move a task between two terminal outcomes.
 */
const STATE_RANK: Readonly<Record<PolyMeshTaskState, number>> = Object.freeze({
  SUBMITTED: 0,
  ACCEPTED: 1,
  QUEUED: 2,
  RUNNING: 3,
  WAITING: 3,
  REJECTED: 9,
  SUCCEEDED: 9,
  FAILED: 9,
  CANCELLED: 9,
});

export function polyMeshStateRank(state: PolyMeshTaskState): number {
  return STATE_RANK[state];
}

/**
 * Tracks last-applied state for one outbound task and rejects regressive or
 * post-terminal updates (§A.10.6).
 */
export class MonotonicStateTracker {
  private current: PolyMeshTaskState;

  constructor(initial: PolyMeshTaskState = "SUBMITTED") {
    this.current = initial;
  }

  get state(): PolyMeshTaskState {
    return this.current;
  }

  get terminal(): boolean {
    return isTerminalPolyMeshState(this.current);
  }

  /** Returns true when the update was applied; false when discarded as stale. */
  apply(next: PolyMeshTaskState): boolean {
    if (this.terminal) return false;
    if (polyMeshStateRank(next) < polyMeshStateRank(this.current)) return false;
    if (next === this.current) return false;
    this.current = next;
    return true;
  }
}

export interface TranslatedTaskEvent {
  state: PolyMeshTaskState;
  terminal: boolean;
  progress?: number;
  message?: string;
  result?: unknown;
  error?: ReturnType<typeof mapA2ATaskErrorToPolyMesh>;
}

/**
 * Translate one observed A2A task snapshot into a mesh-side lifecycle event
 * (§A.9.3). Artifact extraction prefers the first `data` part.
 */
export function translateTaskEvent(task: A2ATask): TranslatedTaskEvent {
  const state = A2A_TO_POLYMESH_STATE[task.status.state];
  const event: TranslatedTaskEvent = {
    state,
    terminal: isTerminalPolyMeshState(state),
  };
  if (typeof task.status.progress === "number") event.progress = task.status.progress;
  if (task.status.message) event.message = task.status.message;
  if (state === "SUCCEEDED") event.result = extractArtifactJson(task.artifacts);
  if (state === "FAILED") event.error = mapA2ATaskErrorToPolyMesh(task.status.error);
  return event;
}

/** `ExtractArtifactJson` (§A.9.3): first JSON data part, else first text part. */
export function extractArtifactJson(artifacts: readonly A2AArtifact[] | undefined): unknown {
  if (!artifacts || artifacts.length === 0) return undefined;
  for (const artifact of artifacts) {
    for (const part of artifact.parts ?? []) {
      if (part.type === "data" && part.data !== undefined) return part.data;
    }
  }
  for (const artifact of artifacts) {
    for (const part of artifact.parts ?? []) {
      if (part.type === "text" && part.text !== undefined) return part.text;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// §A.6.5 / §A.17.4 shared task id space
// ---------------------------------------------------------------------------

/** UUIDv7 shape, case-insensitive (§A.6.5). */
export const UUIDV7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isUuidV7(value: string): boolean {
  return UUIDV7_PATTERN.test(value);
}

/** Durable `local_task_id ↔ remote_task_id` bijection (§A.17.4). */
export interface TaskIdBijectionStore {
  getRemote(localTaskId: string): string | undefined;
  getLocal(remoteTaskId: string): string | undefined;
  bind(localTaskId: string, remoteTaskId: string): void;
  size(): number;
}

/**
 * In-memory bijection with an optional JSON file for durability across
 * adapter restarts. M2 keeps the file write synchronous and best-effort.
 */
export class MemoryTaskIdBijection implements TaskIdBijectionStore {
  private readonly localToRemote = new Map<string, string>();
  private readonly remoteToLocal = new Map<string, string>();
  private readonly filePath?: string;

  constructor(options?: { filePath?: string }) {
    this.filePath = options?.filePath;
    this.load();
  }

  getRemote(localTaskId: string): string | undefined {
    return this.localToRemote.get(localTaskId);
  }

  getLocal(remoteTaskId: string): string | undefined {
    return this.remoteToLocal.get(remoteTaskId);
  }

  bind(localTaskId: string, remoteTaskId: string): void {
    const existingRemote = this.localToRemote.get(localTaskId);
    if (existingRemote !== undefined && existingRemote !== remoteTaskId) {
      throw new Error(
        `task id bijection violated: ${localTaskId} already bound to ${existingRemote}`,
      );
    }
    const existingLocal = this.remoteToLocal.get(remoteTaskId);
    if (existingLocal !== undefined && existingLocal !== localTaskId) {
      throw new Error(
        `task id bijection violated: ${remoteTaskId} already bound to ${existingLocal}`,
      );
    }
    this.localToRemote.set(localTaskId, remoteTaskId);
    this.remoteToLocal.set(remoteTaskId, localTaskId);
    this.persist();
  }

  size(): number {
    return this.localToRemote.size;
  }

  entries(): Array<[string, string]> {
    return [...this.localToRemote.entries()];
  }

  private load(): void {
    if (!this.filePath) return;
    try {
      if (!existsSync(this.filePath)) return;
      const raw = JSON.parse(readFileSync(this.filePath, "utf8")) as Record<string, string>;
      for (const [local, remote] of Object.entries(raw)) {
        this.localToRemote.set(local, remote);
        this.remoteToLocal.set(remote, local);
      }
    } catch {
      // A corrupt store must not prevent adapter startup.
    }
  }

  private persist(): void {
    if (!this.filePath) return;
    try {
      writeFileSync(this.filePath, JSON.stringify(Object.fromEntries(this.localToRemote)), "utf8");
    } catch {
      // Best effort in M2.
    }
  }
}

/**
 * `MapOutboundTaskId` (§A.9.2 / §A.17.4). UUIDv7 local ids pass through
 * untouched; anything else is bound to a freshly minted UUIDv7 and reused on
 * every retry from the durable bijection.
 */
export function MapOutboundTaskId(
  localTaskId: string,
  store?: TaskIdBijectionStore,
  mint: () => string = uuidv7,
): string {
  if (isUuidV7(localTaskId)) return localTaskId;
  if (!store) return mint();
  const existing = store.getRemote(localTaskId);
  if (existing !== undefined) return existing;
  const minted = mint();
  store.bind(localTaskId, minted);
  return minted;
}

/** camelCase alias for call sites that prefer local naming conventions. */
export const mapOutboundTaskId = MapOutboundTaskId;


// ---------------------------------------------------------------------------
// Compatibility helpers used by adapter / idempotency / tests
// ---------------------------------------------------------------------------

export function polymeshStateToA2a(state: PolyMeshTaskState): A2ATaskState {
  return POLYMESH_TO_A2A_STATE[state];
}

export function a2aStateToPolymesh(state: A2ATaskState): PolyMeshTaskState {
  return A2A_TO_POLYMESH_STATE[state];
}

export function mayAdvanceState(prev: A2ATaskState | undefined, next: A2ATaskState): boolean {
  if (!prev) return true;
  if (prev === next) return true;
  if (isTerminalA2AState(prev)) return false;
  const rank: Record<A2ATaskState, number> = {
    submitted: 0,
    working: 1,
    completed: 9,
    failed: 9,
    canceled: 9,
  };
  return rank[next] >= rank[prev];
}

/** Adapter-friendly alias wrapping MemoryTaskIdBijection with get/set API. */
export class MemoryTaskIdMap {
  private readonly inner: MemoryTaskIdBijection;
  constructor(path?: string) {
    this.inner = new MemoryTaskIdBijection(path ? { filePath: path } : undefined);
  }
  get(local: string): string | undefined {
    return this.inner.getRemote(local);
  }
  set(local: string, remote: string): void {
    this.inner.bind(local, remote);
  }
  reverse(remote: string): string | undefined {
    return this.inner.getLocal(remote);
  }
  asStore(): TaskIdBijectionStore {
    return this.inner;
  }
}

export function buildTasksSendParams(input: {
  remoteTaskId: string;
  capability: string;
  payload: unknown;
  idempotency_key?: string;
  deadline?: string;
}): Record<string, unknown> {
  const skill = skillNameFromCapabilityName(input.capability);
  return {
    id: input.remoteTaskId,
    message: {
      role: "user",
      parts: [{ type: "data", data: input.payload }],
    },
    metadata: {
      skill,
      capability_id: input.capability,
      ...(input.idempotency_key ? { idempotency_key: input.idempotency_key } : {}),
      ...(input.deadline ? { deadline: input.deadline } : {}),
      skill_description: fidelityClause(input.capability),
    },
  };
}

export function fingerprintPayload(parts: {
  principal_id?: string;
  capability_id: string;
  input: unknown;
  task_id?: string;
  includeTaskId: boolean;
}): string {
  const body: Record<string, unknown> = {
    principal_id: parts.principal_id ?? "",
    capability_id: parts.capability_id,
    input: parts.input,
  };
  if (parts.includeTaskId && parts.task_id) body.task_id = parts.task_id;
  const canonical = JSON.stringify(sortKeysDeep(body));
  return createHash("sha256").update(canonical).digest("hex");
}

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) out[k] = sortKeysDeep(obj[k]);
  return out;
}
