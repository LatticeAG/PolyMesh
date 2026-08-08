/**
 * Public surface for `@latticeag/polymesh-a2a` (§E.1.5).
 */

export { A2AAdapter, createA2AAdapter, type A2AAdapterOptions } from "./adapter.js";
export {
  loadA2AAdapterConfig,
  assertSafeToLogConfig,
  normalizeTrustedEndpoints,
  type A2AAdapterConfig,
  type A2AAuthConfig,
  type TrustedEndpoint,
} from "./config.js";
export {
  mapCardToA2a,
  mapCardFromA2a,
  map_card_to_a2a,
  map_card_from_a2a,
  skillNameFromCapabilityName,
  skill_name_from_capability_name,
  skillDescriptionFromCapability,
  mapCapabilityToSkill,
  mapCapabilitiesToSkills,
  isPublishableSkill,
  fidelityClause,
  capabilityToA2ASkill,
  INBOUND_PUBLISH_DENYLIST,
} from "./card-mapper.js";
export {
  translateTaskEvent,
  mapOutboundTaskId,
  MapOutboundTaskId,
  isUuidV7,
  MemoryTaskIdMap,
  MemoryTaskIdBijection,
  MonotonicStateTracker,
  polymeshStateToA2a,
  a2aStateToPolymesh,
  mayAdvanceState,
  buildTasksSendParams,
  extractArtifactJson,
  fingerprintPayload,
} from "./task-translator.js";
export {
  computePollDelay,
  pollBaseDelay as computePollBase,
  pollUntilTerminal,
  defaultSleep,
  POLL_BASE_MS,
  POLL_MAX_MS,
} from "./poller.js";
export {
  A2AAuthBoundary,
  redactCredentialPatterns,
  REDACTED,
  mapToMeshTrustScope,
  MESH_CREDENTIAL_HEADERS,
} from "./auth-boundary.js";
export {
  A2AError,
  A2ADialectError,
  A2A_ERROR_TABLE,
  ERROR_TABLE,
  mapJsonRpcErrorToPolymesh,
  mapJsonRpcErrorToPolyMesh,
  mapHttpTransportError,
  mapHttpStatusToPolyMesh,
  mapTransportErrorToPolyMesh,
  lookupErrorMapping,
} from "./errors.js";
export { OutboundClient } from "./outbound-client.js";
export { IdempotencyStore } from "./idempotency.js";
export { AdapterEventLog } from "./event-log.js";
export {
  InboundHandler,
  createInboundHandler,
  projectMeshToA2aTask,
  CAPABILITIES_LIST,
} from "./inbound-handler.js";
export {
  RateLimit,
  createRateLimit,
  TokenBucket,
  HierarchicalRateLimiter,
  KeyedRateLimiter,
  IP_CAPACITY,
  IP_REFILL_PER_SEC,
  PRINCIPAL_CAPACITY,
  PRINCIPAL_REFILL_PER_SEC,
  CAPABILITY_CAPACITY,
  CAPABILITY_REFILL_PER_SEC,
} from "./rate-limit.js";
export {
  buildJsonRpcRequest,
  buildJsonRpcResult,
  buildJsonRpcError,
  parseJsonRpcBody as parseJsonRpcResponse,
  unwrapJsonRpcResult,
} from "./jsonrpc.js";
export type * from "./types.js";
export { createMockA2AServer, forceMockTaskState } from "./mock-server.js";
