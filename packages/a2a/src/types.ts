/**
 * PolyMesh v6 A2A dialect types (PM-V6-SPEC Part A §A.6, §A.7, §E.1).
 */

export type A2ATaskState = "submitted" | "working" | "completed" | "failed" | "canceled";

export type PolyMeshTaskState =
  | "SUBMITTED"
  | "ACCEPTED"
  | "QUEUED"
  | "RUNNING"
  | "WAITING"
  | "REJECTED"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED";

export type AuthMode = "none" | "bearer" | "api_key_header";

export const TERMINAL_POLYMESH_STATES: readonly PolyMeshTaskState[] = Object.freeze([
  "REJECTED",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
]);

export const TERMINAL_A2A_STATES: readonly A2ATaskState[] = Object.freeze([
  "completed",
  "failed",
  "canceled",
]);

export const EVENT_LOG_CAP = 1000;
export const IDEMPOTENCY_RETENTION_MS = 24 * 60 * 60 * 1000;
export const INLINE_RESULT_MAX_BYTES = 1_048_576;
export const ORG_POLYMESH_PREFIX = "org.polymesh.";

export interface A2AErrorObject {
  code: string;
  message?: string;
  data?: unknown;
}

export interface A2ATaskStatus {
  state: A2ATaskState;
  progress?: number;
  message?: string;
  error?: A2AErrorObject;
  timestamp?: string;
}

export interface A2AArtifactPart {
  type: "data" | "text" | "file";
  data?: unknown;
  text?: string;
  mimeType?: string;
}

export interface A2AArtifact {
  name?: string;
  parts: A2AArtifactPart[];
  index?: number;
  data?: unknown;
}

export interface A2AMessagePart {
  type: "data" | "text" | "file";
  data?: unknown;
  text?: string;
}

export interface A2AMessage {
  role?: "user" | "agent" | string;
  parts: A2AMessagePart[];
}

export interface A2ATask {
  id: string;
  sessionId?: string;
  status: A2ATaskStatus;
  artifacts?: A2AArtifact[];
  metadata?: Record<string, unknown>;
}

export interface TasksSendParams {
  id: string;
  skill?: string;
  message: A2AMessage;
  metadata?: Record<string, unknown>;
}

export interface A2ASkill {
  id?: string;
  name: string;
  description: string;
  tags?: string[];
  inputModes?: string[];
  outputModes?: string[];
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface PolyMeshCapability {
  name: string;
  description?: string;
  version?: string;
  input_schema?: Record<string, unknown>;
  result_schema?: Record<string, unknown>;
  idempotency?: "pure" | "idempotent" | "sensitive";
  side_effects?: "none" | "read" | "write" | "network" | "approval";
  approval?: string;
  cancellation?: "supported" | "best_effort" | "unsupported";
  timeout_ceiling_seconds?: number;
  scope?: string;
  dialect?: "native" | "a2a";
  a2a_url?: string;
}

export interface OutboundErrorSummary {
  code: string;
  message: string;
  jsonrpc_code: number;
  retryable: boolean;
  data?: unknown;
}

export interface OutboundResult {
  status: PolyMeshTaskState;
  result?: unknown;
  error?: OutboundErrorSummary;
  remote_task_id: string;
  task_id: string;
  poll_count?: number;
  from_cache?: boolean;
}

export interface OutboundExecuteInput {
  a2a_url: string;
  capability: string;
  payload: unknown;
  task_id: string;
  idempotency_key?: string;
  deadline?: string | number;
  signal?: AbortSignal;
  principal_id?: string;
}

export interface AdapterEvent {
  task_id: string;
  event_seq: number;
  type?: string;
  state?: PolyMeshTaskState | A2ATaskState;
  terminal?: boolean;
  progress?: number;
  message?: string;
  result?: unknown;
  error?: OutboundErrorSummary;
  payload?: unknown;
  observed_at?: string;
  at?: string;
}
