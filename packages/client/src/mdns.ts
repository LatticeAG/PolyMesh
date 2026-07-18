/** Minimal, deliberately non-authoritative mDNS/DNS-SD adapter for PolyMesh. */
import Bonjour from "bonjour-service";

export const POLYMESH_SERVICE_TYPE = "polymesh";
export const POLYMESH_SERVICE_PROTOCOL = "tcp";

export interface MdnsAdvertiseOptions {
  agentId: string;
  port: number;
  name?: string;
  tls?: boolean;
}

export interface MdnsPeer {
  agentId: string;
  host: string;
  port: number;
  addresses: string[];
  tls: boolean;
  name: string;
}

export interface MdnsHandle {
  stop(): void;
}

type BonjourLike = {
  publish(options: Record<string, unknown>): { stop?: () => void };
  find(options: Record<string, unknown>, onUp: (service: Record<string, unknown>) => void): { stop?: () => void };
  destroy(): void;
};

function makeBonjour(): BonjourLike {
  return new Bonjour() as unknown as BonjourLike;
}

/** Publish only the v0.1 discovery hints mandated by the specification. */
export function advertiseMdns(options: MdnsAdvertiseOptions): MdnsHandle {
  if (!options.agentId || !Number.isInteger(options.port) || options.port <= 0 || options.port > 65_535) {
    throw new TypeError("agentId and a valid TCP port are required for mDNS advertisement");
  }
  const bonjour = makeBonjour();
  const service = bonjour.publish({
    name: options.name ?? options.agentId,
    type: POLYMESH_SERVICE_TYPE,
    protocol: POLYMESH_SERVICE_PROTOCOL,
    port: options.port,
    // Never put a card, endpoint path, capability list, or secret in TXT.
    txt: { v: "0.1", id: options.agentId, ...(options.tls ? { tls: "1" } : {}) },
  });
  let stopped = false;
  return {
    stop() {
      if (stopped) return;
      stopped = true;
      try {
        service.stop?.();
      } finally {
        bonjour.destroy();
      }
    },
  };
}

/** Discover hints; callers must authenticate and validate the peer card after connecting. */
export function discoverMdns(onPeer: (peer: MdnsPeer) => void): MdnsHandle {
  const bonjour = makeBonjour();
  const browser = bonjour.find(
    { type: POLYMESH_SERVICE_TYPE, protocol: POLYMESH_SERVICE_PROTOCOL },
    (service) => {
      const txt = service.txt;
      const version = txt && typeof txt === "object" ? (txt as Record<string, unknown>).v : undefined;
      const agentId = txt && typeof txt === "object" ? (txt as Record<string, unknown>).id : undefined;
      if (version !== "0.1" || typeof agentId !== "string" || typeof service.port !== "number") return;
      const tls = (txt as Record<string, unknown>).tls === "1";
      const addresses = Array.isArray(service.addresses)
        ? service.addresses.filter((value): value is string => typeof value === "string")
        : [];
      onPeer({
        agentId,
        host: typeof service.host === "string" ? service.host : addresses[0] ?? "",
        port: service.port,
        addresses,
        tls,
        name: typeof service.name === "string" ? service.name : agentId,
      });
    },
  );
  let stopped = false;
  return {
    stop() {
      if (stopped) return;
      stopped = true;
      try {
        browser.stop?.();
      } finally {
        bonjour.destroy();
      }
    },
  };
}

export const publishMdns = advertiseMdns;
export const browseMdns = discoverMdns;
