import { describe, expect, it } from "vitest";

import {
  DRAINING,
  HEALTHY,
  OFFLINE,
  SUSPECT,
  UNHEALTHY,
  HealthTransitionEvent,
  transitionHealthState,
} from "../packages/broker/src/routing.js";

describe("v2 health-state transitions", () => {
  it("follows the normal healthy → suspect → unhealthy → draining → offline progression", () => {
    const suspect = transitionHealthState({
      state: HEALTHY,
      event: HealthTransitionEvent.SOFT_DEADLINE_MISSED,
    });
    expect(suspect).toEqual({ ok: true, state: SUSPECT, changed: true });

    const unhealthy = transitionHealthState({
      state: suspect.state,
      event: HealthTransitionEvent.HARD_DEADLINE_MISSED,
    });
    expect(unhealthy).toEqual({ ok: true, state: UNHEALTHY, changed: true });

    const draining = transitionHealthState({
      state: unhealthy.state,
      event: HealthTransitionEvent.RECOVERY_DRAIN,
    });
    expect(draining).toEqual({ ok: true, state: DRAINING, changed: true });

    expect(transitionHealthState({
      state: draining.state,
      event: HealthTransitionEvent.DRAIN_DEADLINE_ELAPSED,
    })).toEqual({ ok: true, state: OFFLINE, changed: true });
  });

  it("only restores suspect through fresh proof and admits administrator drain from every allowed state", () => {
    expect(transitionHealthState({
      state: SUSPECT,
      event: HealthTransitionEvent.FRESH_AUTHENTICATED_PROOF,
    })).toEqual({ ok: true, state: HEALTHY, changed: true });

    for (const state of [HEALTHY, SUSPECT, UNHEALTHY] as const) {
      expect(transitionHealthState({
        state,
        event: HealthTransitionEvent.ADMIN_DRAIN,
      })).toEqual({ ok: true, state: DRAINING, changed: true });
    }

    expect(transitionHealthState({
      state: UNHEALTHY,
      event: HealthTransitionEvent.FRESH_AUTHENTICATED_PROOF,
    })).toEqual({ ok: false, state: UNHEALTHY, code: "INVALID_HEALTH_TRANSITION" });
    expect(transitionHealthState({
      state: DRAINING,
      event: HealthTransitionEvent.FRESH_AUTHENTICATED_PROOF,
    })).toEqual({ ok: false, state: DRAINING, code: "INVALID_HEALTH_TRANSITION" });
  });

  it("requires a strictly higher authenticated registration fence to revive offline", () => {
    expect(transitionHealthState({
      state: OFFLINE,
      event: HealthTransitionEvent.AUTHENTICATED_REGISTRATION,
      registrationFence: 7,
      nextRegistrationFence: 7,
    })).toEqual({ ok: false, state: OFFLINE, code: "REGISTRATION_FENCE_REQUIRED" });
    expect(transitionHealthState({
      state: OFFLINE,
      event: HealthTransitionEvent.AUTHENTICATED_REGISTRATION,
      registrationFence: 7,
      nextRegistrationFence: 6,
    })).toEqual({ ok: false, state: OFFLINE, code: "REGISTRATION_FENCE_REQUIRED" });
    expect(transitionHealthState({
      state: OFFLINE,
      event: HealthTransitionEvent.FRESH_AUTHENTICATED_PROOF,
    })).toEqual({ ok: false, state: OFFLINE, code: "INVALID_HEALTH_TRANSITION" });
    expect(transitionHealthState({
      state: OFFLINE,
      event: HealthTransitionEvent.AUTHENTICATED_REGISTRATION,
      registrationFence: 7,
      nextRegistrationFence: 8,
    })).toEqual({ ok: true, state: HEALTHY, changed: true });
  });

  it("allows any live state to become offline on an ended session or lease", () => {
    for (const state of [HEALTHY, SUSPECT, UNHEALTHY, DRAINING] as const) {
      expect(transitionHealthState({
        state,
        event: HealthTransitionEvent.SESSION_OR_LEASE_ENDED,
      })).toEqual({ ok: true, state: OFFLINE, changed: true });
    }
    expect(transitionHealthState({
      state: OFFLINE,
      event: HealthTransitionEvent.SESSION_OR_LEASE_ENDED,
    })).toEqual({ ok: false, state: OFFLINE, code: "INVALID_HEALTH_TRANSITION" });
  });
});
