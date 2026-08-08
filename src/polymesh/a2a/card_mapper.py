"""PolyMesh AgentCard <-> A2A AgentCard mapping (§A.5).

M2 only needs the outbound direction (capability id -> skill name), so the card
level mappers are intentionally thin.  The skill naming rules are the normative
ones and are shared with the inbound work in M3.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .types import A2AAgentCard, A2ASkill

POLYMESH_CAPABILITY_PREFIX = "org.polymesh."

#: Fidelity clause appended to skill descriptions so inbound can round-trip.
FIDELITY_CLAUSE = "PolyMesh capability id: "

#: Reverse-DNS-looking prefixes that must never be re-prefixed on the way back.
REVERSE_DNS_PREFIXES = ("org.", "com.", "io.", "net.", "dev.", "custom.")

#: Capabilities that MUST NOT be published inbound without operator opt-in (§A.5.3).
INBOUND_PUBLISH_DENYLIST: frozenset[str] = frozenset(
    {
        "org.polymesh.shell.exec",
        "org.polymesh.file.write",
    }
)


def is_publishable_skill(capability: Mapping[str, Any]) -> bool:
    """§A.5.3 publish gate for inbound AgentCard skills."""

    name = str(capability.get("name") or capability.get("capability") or "")
    if name in INBOUND_PUBLISH_DENYLIST:
        return False
    if capability.get("approval") == "always":
        return False
    if capability.get("side_effects") == "approval":
        return False
    return True


def map_capabilities_to_skills(
    capabilities: Sequence[Mapping[str, Any]],
    *,
    enforce_publish_gate: bool = True,
) -> list[A2ASkill]:
    skills: list[A2ASkill] = []
    for capability in capabilities:
        if enforce_publish_gate and not is_publishable_skill(capability):
            continue
        skills.append(map_capability_to_skill(capability))
    return skills


def skill_name_from_capability_name(name: str) -> str:
    """Strip the ``org.polymesh.`` prefix only (§A.5.1 normative algorithm)."""

    if not isinstance(name, str):
        raise TypeError("capability name must be a string")
    if name.startswith(POLYMESH_CAPABILITY_PREFIX):
        return name[len(POLYMESH_CAPABILITY_PREFIX) :]
    return name


def capability_name_from_skill_name(
    skill_name: str,
    *,
    description: str | None = None,
    origin: str | None = None,
) -> str:
    """Reverse the strip rule, preferring the fidelity clause (§A.5.1)."""

    if isinstance(description, str) and FIDELITY_CLAUSE in description:
        tail = description.split(FIDELITY_CLAUSE, 1)[1].strip()
        candidate = tail.split()[0].rstrip(".,;") if tail else ""
        if candidate:
            return candidate
    if origin not in (None, "polymesh"):
        return skill_name
    if skill_name.startswith(REVERSE_DNS_PREFIXES):
        return skill_name
    return POLYMESH_CAPABILITY_PREFIX + skill_name


def _skill_description(capability: Mapping[str, Any], capability_id: str) -> str:
    base = capability.get("description")
    text = str(base).strip() if isinstance(base, str) and base.strip() else capability_id
    if FIDELITY_CLAUSE in text:
        return text
    return f"{text} ({FIDELITY_CLAUSE}{capability_id})"


def map_capability_to_skill(capability: Mapping[str, Any]) -> A2ASkill:
    """Project one PolyMesh capability advertisement onto an A2A skill."""

    capability_id = str(capability.get("name") or capability.get("capability") or "")
    if not capability_id:
        raise ValueError("capability advertisement requires a name")
    skill: A2ASkill = {
        "name": skill_name_from_capability_name(capability_id),
        "description": _skill_description(capability, capability_id),
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    }
    input_schema = capability.get("input_schema")
    if isinstance(input_schema, Mapping):
        skill["inputSchema"] = dict(input_schema)
    result_schema = capability.get("result_schema")
    if isinstance(result_schema, Mapping):
        skill["outputSchema"] = dict(result_schema)
    metadata: dict[str, Any] = {"polymesh_capability_id": capability_id}
    for field in ("version", "idempotency", "side_effects", "cancellation", "timeout_ceiling_seconds"):
        value = capability.get(field)
        if value is not None:
            metadata[field] = value
    skill["metadata"] = metadata
    return skill


def map_card_to_a2a(
    card: Mapping[str, Any],
    *,
    url: str | None = None,
    enforce_publish_gate: bool = False,
) -> A2AAgentCard:
    """Minimal PolyMesh AgentCard -> A2A AgentCard projection.

    Mesh topology, scope, and room membership are never copied (§A.16.3).
    Pass ``enforce_publish_gate=True`` for inbound AgentCard publishing (§A.5.3).
    """

    capabilities = card.get("capabilities")
    skills: list[A2ASkill] = []
    if isinstance(capabilities, Sequence) and not isinstance(capabilities, (str, bytes)):
        caps = [c for c in capabilities if isinstance(c, Mapping)]
        skills = map_capabilities_to_skills(caps, enforce_publish_gate=enforce_publish_gate)
    a2a_card: A2AAgentCard = {
        "name": str(card.get("display_name") or card.get("agent_id") or "polymesh-agent"),
        "description": str(card.get("description") or "PolyMesh agent exposed over the A2A dialect"),
        "version": str(card.get("version") or "1.0.0"),
        "capabilities": {"streaming": bool(card.get("sse_enabled", False))},
        "skills": skills,
    }
    resolved_url = url or card.get("a2a_url")
    if isinstance(resolved_url, str) and resolved_url:
        a2a_card["url"] = resolved_url
    return a2a_card


def map_card_from_a2a(card: Mapping[str, Any], *, a2a_url: str | None = None) -> dict[str, Any]:
    """Minimal A2A AgentCard -> PolyMesh advertisement projection (§A.5.2).

    Imported skills fail closed: ``sensitive`` idempotency, ``network`` side
    effects, and the ``a2a`` dialect tag with its ``a2a_url``.
    """

    resolved_url = a2a_url or card.get("url")
    skills = card.get("skills")
    capabilities: list[dict[str, Any]] = []
    if isinstance(skills, Sequence) and not isinstance(skills, (str, bytes)):
        for skill in skills:
            if not isinstance(skill, Mapping):
                continue
            skill_name = str(skill.get("name") or "")
            if not skill_name:
                continue
            description = skill.get("description")
            capability_id = capability_name_from_skill_name(
                skill_name,
                description=description if isinstance(description, str) else None,
                origin="polymesh" if isinstance(description, str) and FIDELITY_CLAUSE in description else "a2a_native",
            )
            entry: dict[str, Any] = {
                "name": capability_id,
                "description": str(description) if isinstance(description, str) else capability_id,
                "version": "1.0.0",
                "idempotency": "sensitive",
                "side_effects": "network",
                "dialect": "a2a",
                "input_schema": dict(skill["inputSchema"]) if isinstance(skill.get("inputSchema"), Mapping) else {"type": "object"},
                "result_schema": dict(skill["outputSchema"]) if isinstance(skill.get("outputSchema"), Mapping) else {"type": "object"},
            }
            if isinstance(resolved_url, str) and resolved_url:
                entry["a2a_url"] = resolved_url
            capabilities.append(entry)
    advertisement: dict[str, Any] = {
        "agent_id": str(card.get("name") or "a2a-remote"),
        "display_name": str(card.get("name") or "a2a-remote"),
        "capabilities": capabilities,
        "dialect": "a2a",
    }
    if isinstance(resolved_url, str) and resolved_url:
        advertisement["a2a_url"] = resolved_url
    return advertisement


__all__ = [
    "FIDELITY_CLAUSE",
    "INBOUND_PUBLISH_DENYLIST",
    "POLYMESH_CAPABILITY_PREFIX",
    "REVERSE_DNS_PREFIXES",
    "capability_name_from_skill_name",
    "is_publishable_skill",
    "map_capabilities_to_skills",
    "map_capability_to_skill",
    "map_card_from_a2a",
    "map_card_to_a2a",
    "skill_name_from_capability_name",
]
