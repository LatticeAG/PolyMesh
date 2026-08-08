/**
 * A2AAdapter — outbound orchestration (§A.9). Inbound deferred to M3.
 */

import type { A2AOutboundBridge } from "@latticeag/polymesh-client/router";

import { A2AAuthBoundary } from "./auth-boundary.js";
import {
  type A2AAdapterConfig,
  loadA2AAdapterConfig,
  normalizeTrustedEndpoints,
} from "./config.js";
import { AdapterEventLog } from "./event-log.js";
import { A2ADialectError } from "./errors.js";
import { IdempotencyStore } from "./idempotency.js";
import { OutboundClient } from "./outbound-client.js";
import { pollUntilTerminal, type SleepFn } from "./poller.js";
import {
  MemoryTaskIdMap,
  MonotonicStateTracker,
  buildTasksSendParams,
  mapOutboundTaskId,
} from "./task-translator.js";
import type { AdapterEvent, OutboundExecuteInput, OutboundResult } from "./types.js";

export interface A2AAdapterOptions {
  config?: Partial<A2AAdapterConfig>;
  fetchImpl?: typeof fetch;
  onRequest?: (info: { url: string; headers: Record<string, string>; body: string }) => void;
  sleep?: SleepFn;
  now?: () => number;
  random?: () => number;
}

export class A2AAdapter {
  readonly config: A2AAdapterConfig;
  readonly auth: A2AAuthBoundary;
  readonly eventLog: AdapterEventLog;
  readonly idempotency: IdempotencyStore;
  readonly taskIdMap: MemoryTaskIdMap;
  readonly client: OutboundClient;
  private readonly sleep?: SleepFn;
  private readonly now: () => number;
  private readonly random?: () => number;
  private readonly redactionLog: string[] = [];

  constructor(options: A2AAdapterOptions | Partial<A2AAdapterConfig> = {}) {
    const opts: A2AAdapterOptions = isAdapterOptions(options) ? options : { config: options };
    this.config = loadA2AAdapterConfig(process.env, opts.config ?? {});
    this.auth = new A2AAuthBoundary({
      trustedEndpoints: normalizeTrustedEndpoints(this.config.trusted_endpoints),
      defaultAuth: this.config.auth,
      onRedaction: (ev) => {
        this.redactionLog.push(ev.pattern);
      },
    });
    this.eventLog = new AdapterEventLog({ path: this.config.event_log_path });
    this.idempotency = new IdempotencyStore({ path: this.config.idempotency_store_path });
    this.taskIdMap = new MemoryTaskIdMap(this.config.task_id_map_path);
    this.client = new OutboundClient({
      config: this.config,
      auth: this.auth,
      fetchImpl: opts.fetchImpl,
      onRequest: opts.onRequest,
    });
    this.sleep = opts.sleep;
    this.now = opts.now ?? Date.now;
    this.random = opts.random;
  }

  createOutboundBridge(): A2AOutboundBridge {
    return {
      send: async (input) => {
        await this.executeOutbound({
          a2a_url: input.a2a_url,
          capability: input.capability,
          payload: input.payload,
          task_id: input.task_id,
          signal: input.signal,
        });
      },
    };
  }

  getEventLog(taskId: string): AdapterEvent[] {
    return this.eventLog.get(taskId);
  }

  getRedactionLog(): string[] {
    return [...this.redactionLog];
  }

  async executeOutbound(input: OutboundExecuteInput): Promise<OutboundResult> {
    this.auth.assertTrustedEndpoint(input.a2a_url);

    const { hit, meta } = this.idempotency.checkOrThrow({
      principal_id: input.principal_id,
      capability_id: input.capability,
      payload: input.payload,
      task_id: input.task_id,
      idempotency_key: input.idempotency_key,
    });
    if (hit?.result) {
      return { ...hit.result, from_cache: true };
    }

    this.eventLog.ensure(input.task_id);
    this.eventLog.append(input.task_id, "outbound.begin", { state: "SUBMITTED" });

    const remoteId = mapOutboundTaskId(input.task_id, this.taskIdMap.asStore());
    const hygiene = this.auth.sanitizeOutboundPayload(input.payload, input.task_id);
    if (hygiene.redactions.length > 0) {
      this.eventLog.append(input.task_id, "outbound.payload_redacted", {
        payload: { redactions: hygiene.redactions },
      });
    }

    const deadlineIso =
      typeof input.deadline === "string"
        ? input.deadline
        : typeof input.deadline === "number"
          ? new Date(input.deadline).toISOString()
          : undefined;

    const params = buildTasksSendParams({
      remoteTaskId: remoteId,
      capability: input.capability,
      payload: hygiene.value,
      idempotency_key: input.idempotency_key,
      deadline: deadlineIso,
    });

    if (!hit) this.idempotency.store(meta, input.task_id, remoteId);

    let remoteTask;
    try {
      remoteTask = await this.client.tasksSend(input.a2a_url, params, input.signal);
    } catch (err) {
      this.eventLog.append(input.task_id, "outbound.send_failed", {
        state: "FAILED",
        terminal: true,
        payload: err instanceof A2ADialectError ? err.toJSON() : String(err),
      });
      throw err;
    }

    const boundRemote = remoteTask.id || remoteId;
    this.taskIdMap.set(input.task_id, boundRemote);
    this.eventLog.append(input.task_id, "outbound.accepted", { state: "ACCEPTED" });

    const deadlineMs = resolveDeadlineMs(input.deadline, this.now);
    const tracker = new MonotonicStateTracker("ACCEPTED");

    try {
      const outcome = await pollUntilTerminal({
        getTask: (signal) => this.client.tasksGet(input.a2a_url, boundRemote, signal),
        deadlineMs,
        signal: input.signal,
        sleep: this.sleep,
        now: this.now,
        random: this.random,
        maxDelayMs: this.config.poll_max_ms,
        tracker,
        onEvent: (event) => {
          this.eventLog.append(input.task_id, "outbound.status", {
            state: event.state,
            terminal: event.terminal,
          });
        },
      });

      const localResult: OutboundResult = {
        task_id: input.task_id,
        remote_task_id: boundRemote,
        status: outcome.event.state,
        result: outcome.event.result,
        error: outcome.event.error
          ? {
              code: outcome.event.error.code,
              message: outcome.event.error.message,
              jsonrpc_code: outcome.event.error.jsonRpcCode,
              retryable: outcome.event.error.retryable,
            }
          : undefined,
        poll_count: outcome.poll_count,
      };
      this.eventLog.append(input.task_id, "outbound.terminal", {
        state: localResult.status,
        terminal: true,
        payload: localResult.result ?? localResult.error,
      });
      this.idempotency.complete(meta.dedup_key, localResult);
      return localResult;
    } catch (err) {
      if (err instanceof A2ADialectError && err.code === "DEADLINE") {
        this.eventLog.append(input.task_id, "outbound.deadline", {
          state: "FAILED",
          terminal: true,
        });
      }
      throw err;
    }
  }

  async cancelOutbound(a2aUrl: string, taskId: string, signal?: AbortSignal): Promise<void> {
    this.auth.assertTrustedEndpoint(a2aUrl);
    const remote = this.taskIdMap.get(taskId) ?? taskId;
    await this.client.tasksCancel(a2aUrl, remote, signal);
  }
}

function isAdapterOptions(value: unknown): value is A2AAdapterOptions {
  if (!value || typeof value !== "object") return false;
  return (
    "config" in value ||
    "fetchImpl" in value ||
    "onRequest" in value ||
    "sleep" in value ||
    "now" in value ||
    "random" in value
  );
}

function resolveDeadlineMs(deadline: string | number | undefined, now: () => number): number {
  if (deadline == null) return now() + 60_000;
  if (typeof deadline === "number") return deadline;
  const ms = Date.parse(deadline);
  return Number.isFinite(ms) ? ms : now() + 60_000;
}

export function createA2AAdapter(options?: A2AAdapterOptions): A2AAdapter {
  return new A2AAdapter(options ?? {});
}
