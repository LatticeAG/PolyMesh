/**
 * Adapter-owned per-task event log (§A.17) — cap last N + terminal.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { AdapterEvent, PolyMeshTaskState } from "./types.js";
import { EVENT_LOG_CAP } from "./types.js";

export const DEFAULT_EVENT_LOG_CAP = EVENT_LOG_CAP;

export class AdapterEventLog {
  private readonly byTask = new Map<string, AdapterEvent[]>();
  private readonly seqByTask = new Map<string, number>();
  private readonly path?: string;
  private readonly cap: number;

  constructor(options?: { path?: string; filePath?: string; cap?: number }) {
    this.path = options?.path ?? options?.filePath;
    this.cap = options?.cap ?? EVENT_LOG_CAP;
    this.load();
  }

  ensure(taskId: string): void {
    if (!this.byTask.has(taskId)) {
      this.byTask.set(taskId, []);
      this.seqByTask.set(taskId, 0);
    }
  }

  contains(taskId: string): boolean {
    return this.byTask.has(taskId);
  }

  lastSeq(taskId: string): number {
    return this.seqByTask.get(taskId) ?? 0;
  }

  nextSeq(taskId: string): number {
    this.ensure(taskId);
    const next = (this.seqByTask.get(taskId) ?? 0) + 1;
    this.seqByTask.set(taskId, next);
    return next;
  }

  /**
   * Flexible append used by adapter + tests:
   * `append(taskId, type, opts)` or `append(taskId, { state, ... })`.
   */
  append(
    taskId: string,
    typeOrInput: string | { state: PolyMeshTaskState; terminal?: boolean; [k: string]: unknown },
    opts?: {
      state?: AdapterEvent["state"];
      payload?: unknown;
      terminal?: boolean;
      progress?: number;
      message?: string;
      result?: unknown;
    },
  ): AdapterEvent {
    this.ensure(taskId);
    const event_seq = this.nextSeq(taskId);
    const type = typeof typeOrInput === "string" ? typeOrInput : "status";
    const body = typeof typeOrInput === "string" ? opts ?? {} : typeOrInput;
    const event: AdapterEvent = {
      event_seq,
      task_id: taskId,
      type,
      state: (body.state as AdapterEvent["state"]) ?? undefined,
      payload: (body as { payload?: unknown }).payload,
      progress: (body as { progress?: number }).progress,
      message: (body as { message?: string }).message,
      result: (body as { result?: unknown }).result,
      at: new Date().toISOString(),
      observed_at: new Date().toISOString(),
      terminal: Boolean((body as { terminal?: boolean }).terminal),
    };
    const list = this.byTask.get(taskId)!;
    list.push(event);
    this.trim(taskId);
    this.persist();
    return event;
  }

  get(taskId: string): AdapterEvent[] {
    return [...(this.byTask.get(taskId) ?? [])];
  }

  /** Keep last `cap` non-terminal events + the terminal event (§A.17.5). */
  private trim(taskId: string): void {
    const list = this.byTask.get(taskId);
    if (!list || list.length === 0) return;
    const terminal = list.filter((e) => e.terminal);
    const nonTerminal = list.filter((e) => !e.terminal);
    const keptNon = nonTerminal.length > this.cap ? nonTerminal.slice(-this.cap) : nonTerminal;
    const lastTerminal = terminal.length > 0 ? [terminal[terminal.length - 1]!] : [];
    const merged = [...keptNon, ...lastTerminal].sort((a, b) => a.event_seq - b.event_seq);
    const seen = new Set<number>();
    const out: AdapterEvent[] = [];
    for (const e of merged) {
      if (seen.has(e.event_seq)) continue;
      seen.add(e.event_seq);
      out.push(e);
    }
    this.byTask.set(taskId, out);
  }

  private load(): void {
    if (!this.path || !existsSync(this.path)) return;
    try {
      const raw = JSON.parse(readFileSync(this.path, "utf8")) as Record<
        string,
        { events: AdapterEvent[]; seq: number }
      >;
      for (const [taskId, body] of Object.entries(raw)) {
        this.byTask.set(taskId, body.events);
        this.seqByTask.set(taskId, body.seq);
      }
    } catch {
      // ignore
    }
  }

  private persist(): void {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    const obj: Record<string, { events: AdapterEvent[]; seq: number }> = {};
    for (const [taskId, events] of this.byTask) {
      obj[taskId] = { events, seq: this.seqByTask.get(taskId) ?? 0 };
    }
    writeFileSync(this.path, JSON.stringify(obj));
  }
}
