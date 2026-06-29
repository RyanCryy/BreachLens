import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { withTimeout } from "./checks.js";
import { runScan, CHECK_IDS, CHECK_TIMEOUTS, RESULT_TYPE } from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 5: Bounded completion time
//
// For any assignment of check behaviors, including checks that NEVER resolve,
// `runScan` SHALL settle within the largest configured `Check_Timeout` plus a
// 2-second aggregation allowance.
//
// **Validates: Requirements 2.6**
//
// The global watchdog budget is `max(CHECK_TIMEOUTS) + 2000 ms`. We exercise the
// bound by drawing each injected primitive's behavior from a fast-check arbitrary:
//   - resolve-quick : resolves immediately (a microtask)
//   - resolve-slow  : resolves after a setTimeout-driven delay (possibly beyond
//                     the per-check budget, so the per-check timeout fires first)
//   - hang          : never resolves — the per-check timeout / global watchdog
//                     must still bound the scan
//   - reject        : rejects — failure isolation, still bounded
//
// All time is virtual: `vi.useFakeTimers()` fakes both timers AND `Date.now()`, and
// the injected deps use the REAL `withTimeout` from `checks.js` (a `setTimeout`-based
// helper) so fake timers drive every timeout path. `vi.runAllTimersAsync()` then
// flushes every scheduled timer instantly, so 100+ iterations stay fast and never
// touch the real network or wall-clock. The fake clock value captured the instant
// `runScan` settles is the virtual time the scan took to complete; we assert it
// never exceeds the budget.
// ---------------------------------------------------------------------------

// The bounded-completion budget the engine guarantees (Requirement 2.6). Computed
// from the exported timeouts so the test tracks any future timeout change.
const WATCHDOG_BUDGET_MS = Math.max(...Object.values(CHECK_TIMEOUTS)) + 2000;

// Every injected primitive whose behavior we vary. The 8 async primitives plus the
// 3 derived analyzers (which the registry awaits inside the dependent checks).
const DEP_FNS = [
  "checkDns",
  "lookupCaa",
  "checkSsl",
  "checkSubdomains",
  "checkHeaders",
  "checkRobotsSitemap",
  "checkSensitiveFiles",
  "inferProvider",
  "analyzeCookies",
  "analyzeMixedContent",
  "fingerprintTech",
];

// A single primitive's behavior on a run. Delays range well past the largest
// per-check timeout so "resolve-slow" regularly trips the per-check timeout too.
const behaviorArb = fc.oneof(
  fc.record({ kind: fc.constant("resolve-quick") }),
  fc.record({ kind: fc.constant("resolve-slow"), delay: fc.integer({ min: 1, max: 15000 }) }),
  fc.record({ kind: fc.constant("hang") }),
  fc.record({ kind: fc.constant("reject") })
);

// One independent behavior per primitive.
const behaviorsArb = fc.record(
  Object.fromEntries(DEP_FNS.map((name) => [name, behaviorArb]))
);

// Turn a generated behavior into a primitive implementation. The resolved value is
// irrelevant to bounded completion, so we return a minimal object; dependent checks
// read missing fields defensively and fall back to safe defaults.
function makeFn(behavior) {
  return () => {
    switch (behavior.kind) {
      case "reject":
        return Promise.reject(new Error("simulated rejection"));
      case "hang":
        return new Promise(() => {}); // never resolves
      case "resolve-slow":
        return new Promise((resolve) => setTimeout(() => resolve({}), behavior.delay));
      case "resolve-quick":
      default:
        return Promise.resolve({});
    }
  };
}

// Build a full `deps` object from the generated behaviors. The REAL `withTimeout`
// is injected so its `setTimeout`-based timers are driven by the fake clock.
function makeDeps(behaviors) {
  const deps = { withTimeout, env: {} };
  for (const name of DEP_FNS) {
    deps[name] = makeFn(behaviors[name]);
  }
  return deps;
}

describe("Feature: passive-scan-engine, Property 5: Bounded completion time", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("settles within max(Check_Timeout) + 2000 ms for any check behaviors, including never-resolving checks", async () => {
    await fc.assert(
      fc.asyncProperty(behaviorsArb, async (behaviors) => {
        const deps = makeDeps(behaviors);

        // Capture the virtual clock the instant the scan settles. Under fake timers
        // `Date.now()` advances only as scheduled timers fire, so the difference is
        // exactly the virtual time the scan took to complete.
        const start = Date.now();
        let settledAt = null;
        const pending = runScan("example.com", deps).then((result) => {
          settledAt = Date.now();
          return result;
        });

        // Flush every scheduled timer (per-check timeouts, slow-resolve delays, and
        // the global watchdog) instantly — never-resolving checks settle via their
        // timeout fallbacks rather than hanging the test.
        await vi.runAllTimersAsync();
        const result = await pending;

        // The scan actually resolved (it never hung).
        expect(settledAt).not.toBeNull();
        const elapsed = settledAt - start;

        // Bounded completion: settled within the budget (Requirement 2.6).
        expect(elapsed).toBeLessThanOrEqual(WATCHDOG_BUDGET_MS);

        // And it returned a complete Scan_Result with one outcome per defined check.
        expect(result.type).toBe(RESULT_TYPE.SCAN);
        expect(result.outcomes).toHaveLength(CHECK_IDS.length);
      }),
      { numRuns: 100 }
    );
  });
});
