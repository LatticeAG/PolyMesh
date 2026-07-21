/** Public surface for the PolyMesh reference broker package. */

import { deriveV2SessionId as deriveNormativeV2SessionId } from "./protocol.js";
import { deriveV2SessionId as deriveLegacyV2SessionId } from "./v2.js";

export * from "./protocol.js";
export * from "./registry.js";
export * from "./durable-store.js";
export * from "./durable-store-v2.js";
export * from "./security.js";
// v2.ts is retained for the pre-Ultra broker implementation.  The public
// barrel names the normative protocol declarations; callers that still need
// the previous partial surface have deliberate Legacy aliases instead of an
// accidental export-star override.
export {
  V2_PROTOCOL_VERSION,
  V2_HANDSHAKE_VERSION,
  V2_SUBPROTOCOL,
  type V2HelloFrame,
} from "./protocol.js";
export {
  deriveV2SessionId as deriveLegacyV2SessionId,
  type V2HelloFrame as LegacyV2HelloFrame,
} from "./v2.js";

/**
 * Normative v2 SID derivation takes the transport channel binding.  The
 * two-argument branch is kept solely for existing in-memory pre-Ultra test
 * adapters; remote and relay code must always pass the third argument.
 */
export function deriveV2SessionId(
  initiatorNonce: string | Uint8Array,
  responderNonce: string | Uint8Array,
  channelBindingHash?: string | Uint8Array,
): string {
  return channelBindingHash === undefined
    ? deriveLegacyV2SessionId(
      typeof initiatorNonce === "string" ? initiatorNonce : Buffer.from(initiatorNonce).toString("base64url"),
      typeof responderNonce === "string" ? responderNonce : Buffer.from(responderNonce).toString("base64url"),
    )
    : deriveNormativeV2SessionId(initiatorNonce, responderNonce, channelBindingHash);
}

export * from "./v2.js";
export * from "./routing.js";
export * from "./rate-limit.js";
export * from "./compression.js";
export * from "./broker.js";

export { Broker as default } from "./broker.js";
