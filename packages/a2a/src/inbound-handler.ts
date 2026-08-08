/**
 * Inbound A2A ingress (`tasks/send`, `tasks/get`, `tasks/cancel`) — §A.8, §E.1.2.
 *
 * M2 ships the outbound adapter only. This module exists so the §E.1 package
 * tree is complete; every entry point fails closed until M3 implements it.
 */
import { A2ADialectError } from "./errors.js";
import type { A2ATask } from "./types.js";

export const INBOUND_NOT_IMPLEMENTED = "M3 not implemented: A2A inbound handler";

function notImplemented(method: string): never {
  throw new A2ADialectError("UNSUPPORTED_METHOD", `${INBOUND_NOT_IMPLEMENTED} (${method})`);
}

export interface InboundHandlerOptions {
  inbound_enabled: boolean;
}

export class A2AInboundHandler {
  constructor(_options?: InboundHandlerOptions) {
    void _options;
  }

  async handleTasksSend(): Promise<A2ATask> {
    return notImplemented("tasks/send");
  }

  async handleTasksGet(): Promise<A2ATask> {
    return notImplemented("tasks/get");
  }

  async handleTasksCancel(): Promise<A2ATask> {
    return notImplemented("tasks/cancel");
  }

  async start(): Promise<never> {
    return notImplemented("start");
  }

  async stop(): Promise<never> {
    return notImplemented("stop");
  }
}

/** Barrel-facing name for the M3 ingress handler (§E.1.2). */
export { A2AInboundHandler as InboundHandler };

export function createInboundHandler(options?: InboundHandlerOptions): A2AInboundHandler {
  return new A2AInboundHandler(options);
}
