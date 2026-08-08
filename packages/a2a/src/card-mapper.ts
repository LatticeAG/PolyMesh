/**
 * PolyMesh capability ↔ A2A skill mapping (PM-V6-SPEC §A.5.1–§A.5.3).
 *
 * Outbound M2 only needs the forward direction (skill naming + fidelity
 * clause); the reverse helper is provided for M3 inbound advertisement import.
 */
import type { A2ASkill, PolyMeshCapability } from "./types.js";

export const POLYMESH_CAPABILITY_PREFIX = "org.polymesh.";

/** Fidelity clause prefix that MUST appear in every projected description. */
export const FIDELITY_CLAUSE_PREFIX = "PolyMesh capability id: ";

/**
 * §A.5.1 strip rule. Only the `org.polymesh.` prefix is stripped; every other
 * reverse-DNS id passes through unchanged.
 */
export function skillNameFromCapabilityName(name: string): string {
  if (name.startsWith(POLYMESH_CAPABILITY_PREFIX)) {
    return name.slice(POLYMESH_CAPABILITY_PREFIX.length);
  }
  return name;
}

/** Alias matching the spec pseudocode identifier. */
export const skill_name_from_capability_name = skillNameFromCapabilityName;

/** Build the fidelity clause the description MUST contain (§A.5.1). */
export function fidelityClause(capabilityName: string): string {
  return `${FIDELITY_CLAUSE_PREFIX}${capabilityName}`;
}

/** True when `description` carries the fidelity clause for `capabilityName`. */
export function hasFidelityClause(description: string, capabilityName: string): boolean {
  return description.includes(fidelityClause(capabilityName));
}

/**
 * Extract the full PolyMesh capability id from a skill description
 * (reverse lookup, §A.5.2). Returns `undefined` when the clause is absent.
 */
export function capabilityIdFromDescription(description: string): string | undefined {
  const index = description.indexOf(FIDELITY_CLAUSE_PREFIX);
  if (index < 0) return undefined;
  const rest = description.slice(index + FIDELITY_CLAUSE_PREFIX.length);
  const match = /^[A-Za-z0-9_.:-]+/.exec(rest.trimStart());
  return match ? match[0] : undefined;
}

/** Project a PolyMesh capability contract onto an A2A skill (§A.5.1). */
export function capabilityToA2ASkill(capability: PolyMeshCapability): A2ASkill {
  const name = skillNameFromCapabilityName(capability.name);
  const base = capability.description?.trim();
  const description = base
    ? `${base} (${fidelityClause(capability.name)})`
    : fidelityClause(capability.name);

  const tags: string[] = [];
  if (capability.idempotency) tags.push(`idempotency=${capability.idempotency}`);
  if (capability.side_effects) tags.push(`side_effects=${capability.side_effects}`);
  if (capability.version) tags.push(`version=${capability.version}`);

  const metadata: Record<string, unknown> = {};
  if (capability.idempotency) metadata.idempotency = capability.idempotency;
  if (capability.side_effects) metadata.side_effects = capability.side_effects;
  if (capability.approval) metadata.approval = capability.approval;
  if (capability.cancellation) metadata.cancellation = capability.cancellation;
  if (capability.timeout_ceiling_seconds !== undefined) {
    metadata.timeout_ceiling_seconds = capability.timeout_ceiling_seconds;
  }

  return {
    id: capability.name,
    name,
    description,
    tags,
    inputModes: ["application/json"],
    outputModes: ["application/json"],
    ...(capability.input_schema ? { inputSchema: capability.input_schema } : {}),
    ...(capability.result_schema ? { outputSchema: capability.result_schema } : {}),
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
  };
}

const REVERSE_DNS_PREFIX = /^(org|com|io|net|dev|custom)\./;

/**
 * Reverse mapping (§A.5.2): resolve the PolyMesh capability name advertised by
 * a remote A2A skill. Prefers the fidelity clause; otherwise re-attaches the
 * `org.polymesh.` prefix only for non reverse-DNS skill names.
 */
export function capabilityNameFromSkill(skill: {
  name: string;
  description?: string;
  origin?: string;
}): { name: string; origin: "polymesh" | "a2a_native" } {
  const declared = skill.description ? capabilityIdFromDescription(skill.description) : undefined;
  if (declared && (skill.origin === undefined || skill.origin === "polymesh")) {
    return { name: declared, origin: "polymesh" };
  }
  if (!REVERSE_DNS_PREFIX.test(skill.name)) {
    return { name: `${POLYMESH_CAPABILITY_PREFIX}${skill.name}`, origin: "a2a_native" };
  }
  return { name: skill.name, origin: "a2a_native" };
}

/** Capabilities that MUST NOT be published inbound without operator opt-in (§A.5.3). */
export const INBOUND_PUBLISH_DENYLIST: readonly string[] = Object.freeze([
  "org.polymesh.shell.exec",
  "org.polymesh.file.write",
]);

/** §A.5.3 publish gate. Inbound-only, retained here for M3 reuse. */
export function isPublishableSkill(capability: PolyMeshCapability): boolean {
  if (INBOUND_PUBLISH_DENYLIST.includes(capability.name)) return false;
  if (capability.approval === "always") return false;
  if (capability.side_effects === "approval") return false;
  return true;
}

/** Project a set of capabilities onto A2A skills, applying the §A.5.3 gate. */
export function mapCapabilitiesToSkills(
  capabilities: readonly PolyMeshCapability[],
  options?: { enforcePublishGate?: boolean },
): A2ASkill[] {
  const gate = options?.enforcePublishGate ?? true;
  return capabilities
    .filter((c) => (gate ? isPublishableSkill(c) : true))
    .map((c) => capabilityToA2ASkill(c));
}

export function skillDescriptionFromCapability(
  name: string,
  description?: string,
  version?: string,
): string {
  let desc = `${fidelityClause(name)}. `;
  if (description) desc += description;
  if (version) desc += (desc.endsWith(" ") ? "" : " ") + `version=${version}`;
  return desc.trim();
}

export function mapCapabilityToSkill(capability: PolyMeshCapability): A2ASkill {
  return capabilityToA2ASkill(capability);
}

export function mapCardToA2a(
  card: Record<string, unknown>,
  options?: { enforcePublishGate?: boolean },
): Record<string, unknown> {
  const caps = Array.isArray(card.capabilities)
    ? (card.capabilities as PolyMeshCapability[])
    : [];
  return {
    name: card.agent_id,
    version: card.card_version ?? "0.0.0",
    skills: mapCapabilitiesToSkills(caps, {
      enforcePublishGate: options?.enforcePublishGate ?? false,
    }),
  };
}

export function mapCardFromA2a(card: Record<string, unknown>): Record<string, unknown> {
  const skills = Array.isArray(card.skills) ? (card.skills as A2ASkill[]) : [];
  return {
    agent_id: card.name,
    card_version: card.version ?? "0.0.0-a2a",
    capabilities: skills.map((s) => ({
      name: capabilityNameFromSkill(s),
      description: s.description,
      dialect: "a2a" as const,
      a2a_url: typeof card.url === "string" ? card.url : undefined,
    })),
  };
}

export const map_card_to_a2a = mapCardToA2a;
export const map_card_from_a2a = mapCardFromA2a;
