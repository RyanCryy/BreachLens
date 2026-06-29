import { describe, it, beforeEach, afterEach, expect, vi } from "vitest";
import fc from "fast-check";
import { runScan, CHECK_IDS, CHECK_STATUS } from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 7: Progress-event invariants
//
// For any scan that resolves to a Scan_Result, the engine SHALL emit exactly one
// Progress_Event per defined check (the multiset of event check ids equals
// CHECK_IDS, each once); each event SHALL name a check in CHECK_IDS with a status
// matching that check's final Check_Outcome; and events SHALL be emitted in the
// actual order in which checks resolve, with strictly increasing `seq` values.
//
// **Validates: Requirements 4.1, 4.2, 4.3**
//
// All check primitives are injected via `deps`, so no real network is touched.
// Each check's underlying primitive resolves on a fake timer at a distinct,
// permutation-driven delay, so we drive the order in which checks settle. The
// final dependency of every check pushes its id into `actualOrder` at the moment
// it resolves — `vi.runAllTimersAsync()` flushes all microtasks between timer
// firings, so the engine's full emission chain for a settling check completes
// before the next check's timer fires. `actualOrder` is therefore the true
// resolution order, and the engine's emission order must match it exactly.
//
// Shared primitives are handled with care: `headers` is fetched once and reused by
// cookies / mixed-content / tech, and `dns` is reused by provider. So `headers`
// and `dns` always resolve successfully (otherwise their dependents would never
// invoke their final dependency and never record a resolution), while their own
// Success/Empty status and every other check's behavior still vary freely.
// ---------------------------------------------------------------------------

const ALL_STATUSES = [
  CHECK_STATUS.SUCCESS,
  CHECK_STATUS.EMPTY,
  CHECK_STATUS.UNAVAILABLE,
];

// Spacing between successive resolution slots (ms). Distinct ranks => distinct
// delays => an unambiguous resolution order. Even the latest dependent check
// (prereq delay + own delay) settles well within the 6000ms minimum Check_Timeout.
const STEP = 50;

// Shared primitives must always succeed so their dependents reach their final dep.
const SHARED_BEHAVIORS = fc.constantFrom("success", "empty");
// Every other check may also be Unavailable (error).
const STANDALONE_BEHAVIORS = fc.constantFrom("success", "empty", "error");

// One behavior per defined check.
const behaviorsArb = fc.record({
  dns: SHARED_BEHAVIORS,
  headers: SHARED_BEHAVIORS,
  caa: STANDALONE_BEHAVIORS,
  tls: STANDALONE_BEHAVIORS,
  subdomains: STANDALONE_BEHAVIORS,
  cookies: STANDALONE_BEHAVIORS,
  "mixed-content": STANDALONE_BEHAVIORS,
  tech: STANDALONE_BEHAVIORS,
  robots: STANDALONE_BEHAVIORS,
  "exposed-files": STANDALONE_BEHAVIORS,
  provider: STANDALONE_BEHAVIORS,
});

// A full permutation of [0..N-1]: rank[i] is the resolution slot for CHECK_IDS[i].
const ranksArb = fc.shuffledSubarray([...Array(CHECK_IDS.length).keys()], {
  minLength: CHECK_IDS.length,
  maxLength: CHECK_IDS.length,
});

// The expected Check_Outcome status implied by a behavior (for the status-match
// assertion). "error" maps to Unavailable; success/empty map to themselves.
function expectedStatus(behavior) {
  if (behavior === "error") return CHECK_STATUS.UNAVAILABLE;
  if (behavior === "success") return CHECK_STATUS.SUCCESS;
  return CHECK_STATUS.EMPTY;
}

// Raw observation shapes per check so the engine's pure `toFindings` classifies
// each "success" as >= 1 finding and each "empty" as 0 findings.
const SUCCESS_VALUE = {
  dns: { spf: true, nameservers: ["ns1.example.com"] },
  headers: {
    hsts: true,
    setCookies: ["sid=1"],
    body: "<html></html>",
    servedHttps: true,
    server: "nginx",
    poweredBy: null,
  },
  caa: { status: "present", records: ["0 issue \"letsencrypt.org\""] },
  tls: { validTo: "2030-01-01T00:00:00.000Z", valid: true },
  subdomains: { subdomains: ["dev.example.com"] },
  cookies: { missingSecure: ["sid"] },
  "mixed-content": { applicable: true, count: 2, samples: ["http://x/y.js"] },
  tech: { detected: ["nginx"] },
  robots: { sitemapPresent: true, sitemapUrlCount: 3 },
  "exposed-files": [{ path: "/.env", status: 200, exposed: true }],
  provider: "Cloudflare",
};

const EMPTY_VALUE = {
  // dns resolves but nothing notable -> Empty. nameservers kept for provider reuse.
  dns: { nameservers: ["ns1.example.com"] },
  // headers present but no security headers -> Empty. Fields kept for dependents.
  headers: {
    setCookies: ["sid=1"],
    body: "<html></html>",
    servedHttps: true,
    server: "nginx",
    poweredBy: null,
  },
  caa: { status: "missing" },
  tls: {},
  subdomains: { subdomains: [] },
  cookies: {},
  "mixed-content": { applicable: false, count: 0 },
  tech: { detected: [] },
  robots: {},
  "exposed-files": [],
  provider: "",
};

describe("Feature: passive-scan-engine, Property 7: Progress-event invariants", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("emits exactly one event per check, with matching status, in resolution order with strictly increasing seq", async () => {
    await fc.assert(
      fc.asyncProperty(
        behaviorsArb,
        ranksArb,
        fc.string({ minLength: 1 }), // domain (ignored by the fake deps)
        async (behaviors, ranks, domain) => {
          // The actual resolution order, recorded by each check's FINAL dependency
          // at the instant it settles. This is the oracle for emission order.
          const actualOrder = [];

          // Delay (ms) for each check id, derived from the permutation so every
          // check settles at a distinct slot.
          const delayOf = {};
          CHECK_IDS.forEach((id, i) => {
            delayOf[id] = (ranks[i] + 1) * STEP;
          });

          // A timer-backed resolution: records the check id when it fires, then
          // resolves with `value` (or rejects, to drive an Unavailable outcome).
          const settleAfter = (id, value, reject = false) =>
            new Promise((resolve, rej) => {
              setTimeout(() => {
                actualOrder.push(id);
                if (reject) rej(new Error(`simulated ${id} failure`));
                else resolve(value);
              }, delayOf[id]);
            });

          // For a standalone check, pick the value/behavior for its final dep.
          const standalone = (id) => {
            const b = behaviors[id];
            if (b === "error") return settleAfter(id, undefined, true);
            return settleAfter(id, b === "success" ? SUCCESS_VALUE[id] : EMPTY_VALUE[id]);
          };

          // Shared primitives always succeed (their dependents must reach their
          // own final dep), but their own Success/Empty status still varies.
          const sharedValue = (id) =>
            behaviors[id] === "success" ? SUCCESS_VALUE[id] : EMPTY_VALUE[id];

          const deps = {
            // --- shared primitives (always resolve) ---------------------------
            checkDns: () => settleAfter("dns", sharedValue("dns")),
            checkHeaders: () => settleAfter("headers", sharedValue("headers")),

            // --- standalone primitives ---------------------------------------
            lookupCaa: () => standalone("caa"),
            checkSsl: () => standalone("tls"),
            checkSubdomains: () => standalone("subdomains"),
            checkRobotsSitemap: () => standalone("robots"),
            checkSensitiveFiles: () => standalone("exposed-files"),

            // --- dependent final deps (invoked after their shared prereq) -----
            // These run only after headers/dns resolve, so their recorded slot is
            // (prereq delay + own delay); the resulting order is still captured
            // faithfully by `actualOrder`.
            analyzeCookies: () => standalone("cookies"),
            analyzeMixedContent: () => standalone("mixed-content"),
            fingerprintTech: () => standalone("tech"),
            inferProvider: () => standalone("provider"),

            // Fake-timer-friendly timeout wrapper: the loser is the sentinel.
            withTimeout: (promise, ms, sentinel) =>
              new Promise((resolve) => {
                let done = false;
                const timer = setTimeout(() => {
                  if (!done) {
                    done = true;
                    resolve(sentinel);
                  }
                }, ms);
                Promise.resolve(promise).then(
                  (v) => {
                    if (!done) {
                      done = true;
                      clearTimeout(timer);
                      resolve(v);
                    }
                  },
                  () => {
                    if (!done) {
                      done = true;
                      clearTimeout(timer);
                      resolve(sentinel);
                    }
                  }
                );
              }),

            env: {},
          };

          // Capture every emitted Progress_Event in emission order.
          const events = [];
          const emit = (evt) => events.push(evt);

          const pending = runScan(domain, deps, emit);
          // Drain all fake timers so every check settles deterministically, one
          // distinct slot at a time, with microtasks flushed between firings.
          await vi.runAllTimersAsync();
          const result = await pending;

          // The scan resolved to a Scan_Result (Property 7 precondition).
          expect(result.type).toBe("scan");

          // --- (a) exactly one event per defined check ----------------------
          expect(events).toHaveLength(CHECK_IDS.length);
          const eventChecks = events.map((e) => e.check);
          // Multiset of event check ids equals CHECK_IDS exactly (each once).
          expect([...eventChecks].sort()).toEqual([...CHECK_IDS].sort());
          expect(new Set(eventChecks).size).toBe(CHECK_IDS.length);

          // Every event is a well-formed progress event naming a known check.
          for (const e of events) {
            expect(e.type).toBe("progress");
            expect(CHECK_IDS).toContain(e.check);
            expect(ALL_STATUSES).toContain(e.status);
          }

          // --- (b) emitted in actual resolution order -----------------------
          expect(eventChecks).toEqual(actualOrder);

          // --- (c) strictly increasing seq in emission order ----------------
          for (let i = 0; i < events.length; i++) {
            expect(events[i].seq).toBe(i);
            if (i > 0) {
              expect(events[i].seq).toBeGreaterThan(events[i - 1].seq);
            }
          }

          // --- (d) each event's status matches its final Check_Outcome ------
          const outcomeStatusById = new Map(
            result.outcomes.map((o) => [o.id, o.status])
          );
          for (const e of events) {
            expect(e.status).toBe(outcomeStatusById.get(e.check));
            // And the engine derived the status we intended for that behavior.
            expect(e.status).toBe(expectedStatus(behaviors[e.check]));
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});
