/**
 * Minimal, deliberately non-authoritative mDNS/DNS-SD adapter for PolyMesh.
 *
 * Advertisements are endpoint hints only.  They never enroll an identity,
 * change a certificate pin, or cause a connection themselves.  The adapter
 * returns only bounded private-LAN literal addresses so a later connector can
 * apply its WSS, pinning, and explicit-enrollment policy without a second
 * unconstrained DNS lookup.
 */
import { isIP } from "node:net";
import Bonjour from "bonjour-service";

export const POLYMESH_SERVICE_TYPE = "polymesh";
export const POLYMESH_SERVICE_PROTOCOL = "tcp";
export const MDNS_MAX_CANDIDATES = 128;
export const MDNS_MAX_ADDRESSES_PER_PEER = 8;
export const MDNS_MIN_CALLBACK_INTERVAL_MS = 1_000;

const DISCOVERY_AGENT_ID_RE = /^[A-Za-z][A-Za-z0-9._-]*$/;
const MAX_AGENT_ID_BYTES = 128;
const MAX_SERVICE_NAME_BYTES = 63;
const MAX_HOST_BYTES = 253;
const MAX_RAW_ADDRESSES = 32;

export interface MdnsAdvertiseOptions {
  agentId: string;
  port: number;
  name?: string;
  /**
   * Retained for source compatibility. mDNS is WSS-only, so `false` is
   * rejected and the value is never emitted in the TXT record.
   */
  tls?: boolean;
}

export interface MdnsDiscoveryOptions {
  maxCandidates?: number;
  maxAddressesPerPeer?: number;
  minCallbackIntervalMs?: number;
}

export interface MdnsPeer {
  agentId: string;
  /** A validated private-LAN literal IP, never a discovered hostname. */
  host: string;
  port: number;
  addresses: string[];
  /** Always true: LAN PolyMesh discovery requires WSS. */
  tls: true;
  name: string;
}

export interface MdnsHandle {
  stop(): void;
}

export interface BonjourLike {
  publish(options: Record<string, unknown>): { stop?: () => void };
  find(options: Record<string, unknown>, onUp: (service: Record<string, unknown>) => void): { stop?: () => void };
  destroy(): void;
}

export interface MdnsDependencies {
  createBonjour?: () => BonjourLike;
  now?: () => number;
}

interface CandidateState {
  fingerprint: string;
  callbackAt: number;
}

function makeBonjour(): BonjourLike {
  return new Bonjour() as unknown as BonjourLike;
}

/**
 * Publish WSS discovery hints.  Cards, capabilities, secrets, paths, and a
 * TLS flag are intentionally omitted: TLS is mandatory and discovery cannot
 * authenticate an endpoint.
 */
export function advertiseMdns(options: MdnsAdvertiseOptions, dependencies: MdnsDependencies = {}): MdnsHandle {
  if (!isDiscoveryAgentId(options.agentId) || !isValidPort(options.port)) {
    throw new TypeError("agentId and a valid TCP port are required for mDNS advertisement");
  }
  if (options.tls === false) {
    throw new TypeError("mDNS advertisement requires WSS; plaintext LAN discovery is disabled");
  }
  const name = options.name ?? options.agentId;
  if (!isValidServiceName(name)) throw new TypeError("mDNS service name must be a bounded DNS-SD label");

  const bonjour = (dependencies.createBonjour ?? makeBonjour)();
  const service = bonjour.publish({
    name,
    type: POLYMESH_SERVICE_TYPE,
    protocol: POLYMESH_SERVICE_PROTOCOL,
    port: options.port,
    // Never put a card, endpoint path, capability list, TLS switch, or secret
    // in TXT. TLS is mandatory and identity comes from enrollment later.
    txt: { v: "0.1", id: options.agentId },
  });
  return onceStopped(service, bonjour);
}

/**
 * Discover bounded WSS endpoint hints.  The callback receives no hostname and
 * this module never creates a socket; callers must explicitly choose whether
 * to attempt a pinned, enrolled WSS connection.
 */
export function discoverMdns(
  onPeer: (peer: MdnsPeer) => void,
  options: MdnsDiscoveryOptions = {},
  dependencies: MdnsDependencies = {},
): MdnsHandle {
  if (typeof onPeer !== "function") throw new TypeError("onPeer must be a function");
  const maxCandidates = boundedPositiveInteger(options.maxCandidates, MDNS_MAX_CANDIDATES, "maxCandidates");
  const maxAddresses = boundedPositiveInteger(options.maxAddressesPerPeer, MDNS_MAX_ADDRESSES_PER_PEER, "maxAddressesPerPeer");
  const minCallbackIntervalMs = boundedNonNegativeFinite(options.minCallbackIntervalMs, MDNS_MIN_CALLBACK_INTERVAL_MS, "minCallbackIntervalMs");
  const now = dependencies.now ?? Date.now;
  const candidates = new Map<string, CandidateState>();
  const bonjour = (dependencies.createBonjour ?? makeBonjour)();
  const browser = bonjour.find(
    { type: POLYMESH_SERVICE_TYPE, protocol: POLYMESH_SERVICE_PROTOCOL },
    (service) => {
      const record = parseServiceRecord(service, maxAddresses);
      if (!record) return;
      const key = `${record.agentId}\u0000${record.name}\u0000${serviceInterfaceKey(service)}`;
      const fingerprint = `${record.port}\u0000${record.addresses.join("\u0000")}`;
      const timestamp = now();
      const prior = candidates.get(key);
      if (!prior && candidates.size >= maxCandidates) return;
      if (prior && prior.fingerprint === fingerprint) return;
      if (prior && timestamp - prior.callbackAt < minCallbackIntervalMs) {
        candidates.set(key, { fingerprint, callbackAt: prior.callbackAt });
        return;
      }
      candidates.set(key, { fingerprint, callbackAt: timestamp });
      onPeer({
        agentId: record.agentId,
        // Bind consumers to a validated literal selected from the discovery
        // record, never its mutable hostname.
        host: record.addresses[0]!,
        port: record.port,
        addresses: record.addresses,
        tls: true,
        name: record.name,
      });
    },
  );
  return onceStopped(browser, bonjour);
}

function parseServiceRecord(service: Record<string, unknown>, maxAddresses: number): {
  agentId: string;
  name: string;
  port: number;
  addresses: string[];
} | undefined {
  const agentId = parseMinimalTxt(service.txt);
  if (!agentId || !isValidPort(service.port)) return undefined;
  const name = typeof service.name === "string" ? service.name : agentId;
  if (!isValidServiceName(name)) return undefined;
  if (service.host !== undefined && (typeof service.host !== "string" || !isValidHostHint(service.host))) return undefined;
  if (!Array.isArray(service.addresses) || service.addresses.length > MAX_RAW_ADDRESSES) return undefined;
  const addresses = [...new Set(service.addresses
    .filter((value): value is string => typeof value === "string" && value.length <= 45)
    .filter(isPrivateLanAddress))].slice(0, maxAddresses);
  return addresses.length > 0 ? { agentId, name, port: service.port, addresses } : undefined;
}

/** Only the required, minimal TXT keys are accepted. */
function parseMinimalTxt(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "id" || keys[1] !== "v") return undefined;
  if (value.v !== "0.1" || !isDiscoveryAgentId(value.id)) return undefined;
  return value.id;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDiscoveryAgentId(value: unknown): value is string {
  return typeof value === "string" &&
    Buffer.byteLength(value, "utf8") <= MAX_AGENT_ID_BYTES &&
    DISCOVERY_AGENT_ID_RE.test(value);
}

function isValidPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65_535;
}

function isValidServiceName(value: string): boolean {
  return Buffer.byteLength(value, "utf8") > 0 &&
    Buffer.byteLength(value, "utf8") <= MAX_SERVICE_NAME_BYTES &&
    !/[\u0000-\u001f\u007f]/.test(value);
}

function isValidHostHint(value: string): boolean {
  return Buffer.byteLength(value, "utf8") > 0 &&
    Buffer.byteLength(value, "utf8") <= MAX_HOST_BYTES &&
    !/[\s\u0000-\u001f\u007f]/.test(value);
}

/** Reject public, loopback, link-local, metadata, and IPv4-mapped IPv6 IPs. */
function isPrivateLanAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const octets = address.split(".").map(Number);
    return octets[0] === 10 ||
      (octets[0] === 172 && octets[1] !== undefined && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168);
  }
  // Unique-local IPv6 only (fc00::/7). Link-local fe80::/10 is intentionally
  // excluded because an interface index is needed to use it safely.
  return family === 6 && /^(fc|fd)[0-9a-f]{2}:/i.test(address);
}

function serviceInterfaceKey(service: Record<string, unknown>): string {
  if (typeof service.interfaceIndex === "number" && Number.isInteger(service.interfaceIndex)) return `index:${service.interfaceIndex}`;
  const referer = isRecord(service.referer) ? service.referer : undefined;
  if (referer && typeof referer.address === "string") return `address:${referer.address}`;
  return "unknown-interface";
}

function boundedPositiveInteger(value: number | undefined, fallback: number, name: string): number {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < 1 || result > fallback) throw new RangeError(`${name} must be an integer between 1 and ${fallback}`);
  return result;
}

function boundedNonNegativeFinite(value: number | undefined, fallback: number, name: string): number {
  const result = value ?? fallback;
  if (!Number.isFinite(result) || result < 0 || result > 60_000) throw new RangeError(`${name} must be a finite duration between 0 and 60000`);
  return result;
}

function onceStopped(service: { stop?: () => void }, bonjour: BonjourLike): MdnsHandle {
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

export const publishMdns = advertiseMdns;
export const browseMdns = discoverMdns;
