import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { recheckFinding, STATUS } from "./recheck.js";

// ---------------------------------------------------------------------------
// Orchestrator timeouts and messaging (task 4.5)
//
//   The orchestrator (`recheckFinding`) wraps every mapped check in a per-check
//   `withTimeout` budget (DNS 6s, SSL 8s, headers 9s, robots 6s, file 6s) and the
//   whole call in an overall 30s `withTimeout`. A check that never settles must
//   therefore never hang the re-check: the timeout fires, the observation collapses
//   to the failure sentinel, and the family predicate maps that to `indeterminate`.
//
//   These are example/edge unit tests (no fast-check). We drive the real timers in
//   `withTimeout` with vi.useFakeTimers(), inject a never-resolving check, and
//   advance fake time to trip the fallback — so the assertions run instantly with no
//   real waiting.
//
//   Validates: Requirements 1.8, 3.14, 4.2, 4.3
// ---------------------------------------------------------------------------

// A promise that never settles — models a check whose network call hangs forever.
function neverResolves() {
  return new Promise(() => {});
}

// Build a `deps` object where every check primitive hangs forever. Whatever family
// the routed Finding_Id invokes, its mapped dependency never settles, so only the
// timeout fallback can resolve the re-check.
function buildHangingDeps() {
  const asyncHang = () => neverResolves();
  // analyze* are synchronous in the real module; they should never be reached because
  // the headers fetch that precedes them hangs, but provide safe no-ops just in case.
  const syncNoop = () => ({});
  return {
    checkDns: asyncHang,
    checkSsl: asyncHang,
    checkHeaders: asyncHang,
    checkRobotsSitemap: asyncHang,
    checkFileStatus: asyncHang,
    analyzeCookies: syncNoop,
    analyzeMixedContent: syncNoop,
  };
}

describe("Recheck_Router orchestrator — timeouts and messaging", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("yields indeterminate when a check never resolves, at the per-check budget (DNS 6s)", async () => {
    // "spf-missing" routes to the DNS check, whose per-check budget is 6s.
    const deps = buildHangingDeps();

    const pending = recheckFinding({ domain: "example.com", findingId: "spf-missing" }, deps);

    // Advance fake time past the 6s DNS per-check budget to trip the withTimeout
    // fallback (Requirements 3.14, 4.2). advanceTimersByTimeAsync also flushes the
    // microtasks chained after the timer so the orchestrator can settle.
    await vi.advanceTimersByTimeAsync(6000);

    const result = await pending;

    expect(result.findingId).toBe("spf-missing");
    expect(result.status).toBe(STATUS.INDETERMINATE);
    // Honest messaging: it states the result could not be confirmed and invites a retry
    // (Requirement 4.3). The orchestrator's RETRY_HINT is "You can run the re-check
    // again in a moment."
    expect(result.message.toLowerCase()).toMatch(/could not be confirmed|couldn't be confirmed/);
    expect(result.message).toMatch(/run the re-check again/i);
    expect(result.message.length).toBeGreaterThan(0);
    expect(result.message.length).toBeLessThanOrEqual(500);
  });

  it("does not settle before the per-check budget elapses", async () => {
    // Guards against a regression where the fallback fires too early (which would make
    // the timeout meaningless). Before the 6s budget the re-check must still be pending.
    const deps = buildHangingDeps();

    let settled = false;
    const pending = recheckFinding({ domain: "example.com", findingId: "spf-missing" }, deps).then(
      (r) => {
        settled = true;
        return r;
      }
    );

    // Advance to just before the 6s DNS budget.
    await vi.advanceTimersByTimeAsync(5000);
    expect(settled).toBe(false);

    // Crossing the budget lets it resolve.
    await vi.advanceTimersByTimeAsync(1000);
    const result = await pending;
    expect(settled).toBe(true);
    expect(result.status).toBe(STATUS.INDETERMINATE);
  });

  it("yields indeterminate within the overall 30s cap when a check never resolves", async () => {
    // Overall behavior (Requirement 1.8): even allowing fake time to run all the way to
    // and past the 30s overall cap, a never-resolving check produces a bounded,
    // indeterminate result — the orchestrator never hangs and never guesses "fixed".
    const deps = buildHangingDeps();

    const pending = recheckFinding({ domain: "example.com", findingId: "hdr-hsts" }, deps);

    // Run every scheduled timer (the per-check budget and the 30s overall cap) to
    // completion, then let the orchestrator settle.
    await vi.advanceTimersByTimeAsync(30000);

    const result = await pending;

    expect(result.findingId).toBe("hdr-hsts");
    expect(result.status).toBe(STATUS.INDETERMINATE);
    expect(result.status).not.toBe(STATUS.RESOLVED);
    expect(result.status).not.toBe(STATUS.UNRESOLVED);
    // Indeterminate messaging invites a retry (Requirement 4.3).
    expect(result.message).toMatch(/run the re-check again/i);
    expect(result.message.length).toBeLessThanOrEqual(500);
  });

  it("uses the SSL per-check budget (8s) for ssl-* findings", async () => {
    // Confirms the per-check budget is family-specific (SSL is 8s, longer than the 6s
    // DNS budget) — advancing only 6s must NOT yet settle an ssl-* re-check.
    const deps = buildHangingDeps();

    let settled = false;
    const pending = recheckFinding({ domain: "example.com", findingId: "ssl-expired" }, deps).then(
      (r) => {
        settled = true;
        return r;
      }
    );

    await vi.advanceTimersByTimeAsync(6000);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(2000); // now at the 8s SSL budget
    const result = await pending;
    expect(settled).toBe(true);
    expect(result.findingId).toBe("ssl-expired");
    expect(result.status).toBe(STATUS.INDETERMINATE);
    expect(result.message).toMatch(/run the re-check again/i);
  });
});
