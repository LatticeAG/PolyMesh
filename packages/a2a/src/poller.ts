/**
 * Outbound status polling with bounded exponential backoff
 * (PM-V6-SPEC §A.10.2–§A.10.3, §A.10.6).
 */
import { A2ADialectError } from "./errors.js";
import { MonotonicStateTracker, isTerminalA2AState, translateTaskEvent } from "./task-translator.js";
import type { TranslatedTaskEvent } from "./task-translator.js";
import type { A2ATask } from "./types.js";

/** Initial delay unit before jitter (§A.10.2). */
export const POLL_BASE_MS = 500;
/** Backoff cap before jitter (§A.10.2). */
export const POLL_MAX_MS = 15_000;
/** Jitter fraction; delay is base ± 20% (§A.10.2). */
export const POLL_JITTER_FRACTION = 0.2;

/**
 * `base = min(500 * 2^n, 15000); jitter = base * Uniform(-0.20, +0.20);
 * delay = max(0, base + jitter)` (§A.10.2).
 *
 * `random` MUST return a value in `[0, 1)`; injecting it makes the schedule
 * deterministic for conformance tests.
 */
export function computePollDelay(
  n: number,
  random: () => number = Math.random,
  maxMs: number = POLL_MAX_MS,
): number {
  const attempt = Math.max(0, Math.floor(n));
  const uncapped = POLL_BASE_MS * Math.pow(2, Math.min(attempt, 52));
  const base = Math.min(uncapped, maxMs);
  const jitter = base * ((random() * 2 - 1) * POLL_JITTER_FRACTION);
  return Math.max(0, base + jitter);
}

/** Capped base for attempt `n`, ignoring jitter (§A.10.2 table). */
export function pollBaseDelay(n: number, maxMs: number = POLL_MAX_MS): number {
  const attempt = Math.max(0, Math.floor(n));
  return Math.min(POLL_BASE_MS * Math.pow(2, Math.min(attempt, 52)), maxMs);
}

export type SleepFn = (ms: number, signal?: AbortSignal) => Promise<void>;

/** Interruptible sleep; cancel MUST interrupt the wait early (§A.10.2). */
export const defaultSleep: SleepFn = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(pollCancelledError());
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      cleanup();
      reject(pollCancelledError());
    };
    function cleanup(): void {
      signal?.removeEventListener("abort", onAbort);
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });

export function pollCancelledError(): A2ADialectError {
  return new A2ADialectError("CANCELLED", "Outbound A2A poll cancelled by caller");
}

export function pollDeadlineError(): A2ADialectError {
  return new A2ADialectError("DEADLINE", "Outbound A2A task exceeded mesh deadline");
}

export interface PollUntilTerminalOptions {
  /** Issues one `tasks/get` against the remote. */
  getTask: (signal?: AbortSignal) => Promise<A2ATask>;
  /** Epoch-ms deadline; max poll duration equals the mesh task deadline (§A.10.2). */
  deadlineMs?: number;
  signal?: AbortSignal;
  now?: () => number;
  sleep?: SleepFn;
  random?: () => number;
  /** Backoff cap override (`poll_max_ms`, §E.13.1). */
  maxDelayMs?: number;
  /** Invoked for every accepted (non-stale) status transition. */
  onEvent?: (event: TranslatedTaskEvent, task: A2ATask) => void;
  /** Pre-seeded tracker so send-time ACCEPTED participates in monotonicity. */
  tracker?: MonotonicStateTracker;
}

export interface PollOutcome {
  task: A2ATask;
  event: TranslatedTaskEvent;
  poll_count: number;
  tracker: MonotonicStateTracker;
}

/**
 * `PollUntilTerminal` (§A.10.3). Stops on the first terminal A2A state,
 * throws `DEADLINE` at the deadline and `CANCELLED` on abort.
 */
export async function pollUntilTerminal(options: PollUntilTerminalOptions): Promise<PollOutcome> {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;
  const tracker = options.tracker ?? new MonotonicStateTracker("ACCEPTED");
  const signal = options.signal;

  let n = 0;
  let pollCount = 0;

  for (;;) {
    if (signal?.aborted) throw pollCancelledError();
    if (options.deadlineMs !== undefined && now() >= options.deadlineMs) throw pollDeadlineError();

    const task = await options.getTask(signal);
    pollCount += 1;
    const event = translateTaskEvent(task);

    // §A.10.6: never regress; discard stale updates after terminal.
    const applied = tracker.apply(event.state);
    if (applied) options.onEvent?.(event, task);

    if (isTerminalA2AState(task.status.state) && applied) {
      return { task, event, poll_count: pollCount, tracker };
    }
    if (tracker.terminal) {
      return { task, event, poll_count: pollCount, tracker };
    }

    let delay = computePollDelay(n, random, options.maxDelayMs ?? POLL_MAX_MS);
    if (options.deadlineMs !== undefined) {
      const remaining = options.deadlineMs - now();
      if (remaining <= 0) throw pollDeadlineError();
      delay = Math.min(delay, remaining);
    }
    await sleep(delay, signal);
    n += 1;
  }
}
