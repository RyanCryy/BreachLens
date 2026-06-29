import { describe, it, beforeEach, afterEach, vi, expect } from "vitest";
import fc from "fast-check";
import { runScan, CHECK_IDS } from "./scan-engine.js";
import { withTimeout } from "./checks.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 1: All checks start concurrently
//
// For any set of defined checks, when `runScan` is invoked, every defined check
// SHALL have started before any check has resolved (i.e., the engine launches
// all checks before awaiting any of them).
//
// **Validates: Requirements 1.1**
//
// Framing — what "every defined check" means at the primitive level:
// Several of the 11 defined checks are *derived* from a single shared primitive
// rather than issuing their own request (preserving the passive single-fetch
// behavior):
//   - `headers` is fetched ONCE; `cookies`, `mixed-content`, and `tech` reuse
//     that already-fetched headers/body via the shared `checkHeaders` call.
//   - `provider` is inferred from the `dns` result, reusing the shared `checkDns`
//     call rather than re-resolving.
// So the 11 checks compose exactly these 7 *independent* underlying primitives,
// each launched by the engine and each invoked at most once:
//   checkDns, lookupCaa, checkSsl, checkSubdomains, checkHeaders,
//   checkRobotsSitemap, checkSensitiveFiles.
// The dependent primitives (inferProvider / analyzeCookies / analyzeMixedContent
// / fingerprintTech) intentionally run *after* their shared primitive resolves,
// so concurrency is asserted at the level the design intends: every independent
// underlying primitive is invoked before any of them resolves.
//
// Method: inject deps whose primitives record their start order the instant they
// are invoked, and only resolve after a per-primitive timer fires. fast-check
// randomizes each primitive's resolution delay (and therefore its resolution
// ordering). At the moment the FIRST primitive resolves, we snapshot the set of
// already-started primitives and assert it contains all 7 — proving the engine
// launched everything before awaiting any of it. Fake timers keep every
// iteration instant.
// ---------------------------------------------------------------------------

// The independent underlying primitives the engine launches (one invocation each).
const INDEPENDENT_PRIMITIVES = [
  "checkDns",
  "lookupCaa",
  "checkSsl",
  "checkSubdomains",
  "checkHeaders",
  "checkRobotsSitemap",
  "checkSensitiveFiles",
];

// A per-primitive resolution delay (ms). Randomizing these independently
// randomizes the order in which primitives resolve, so the "started before any
// resolved" invariant is exercised across many different resolution orderings.
const delaysArb = fc.record(
  Object.fromEntries(
    INDEPENDENT_PRIMITIVES.map((name) => [name, fc.integer({ min: 1, max: 200 })])
  )
);

describe("Feature: passive-scan-engine, Property 1: All checks start concurrently — every defined check has started before any check has resolved", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("invokes every independent underlying primitive before any of them resolves, for any per-primitive resolution ordering", async () => {
    await fc.assert(
      fc.asyncProperty(
        delaysArb,
        fc.string({ minLength: 1 }), // domain (opaque to the fake deps)
        async (delays, domain) => {
          const startedSet = new Set();
          const invocationCounts = Object.create(null);
          // Snapshot of which primitives had already STARTED at the instant the
          // first primitive RESOLVES. Captured exactly once.
          let startedAtFirstResolution = null;

          // Build a primitive that records its start synchronously on invocation,
          // then resolves to `returnValue` only after its randomized timer fires.
          const makePrimitive = (name, returnValue) => () => {
            startedSet.add(name);
            invocationCounts[name] = (invocationCounts[name] || 0) + 1;
            return new Promise((resolve) => {
              setTimeout(() => {
                if (startedAtFirstResolution === null) {
                  startedAtFirstResolution = new Set(startedSet);
                }
                resolve(returnValue);
              }, delays[name]);
            });
          };

          const deps = {
            // --- independent primitives (monitored) -------------------------
            checkDns: makePrimitive("checkDns", {
              nameservers: [],
              spf: false,
              dmarc: false,
              mx: [],
            }),
            lookupCaa: makePrimitive("lookupCaa", { status: "missing", records: [] }),
            checkSsl: makePrimitive("checkSsl", {}),
            checkSubdomains: makePrimitive("checkSubdomains", { subdomains: [] }),
            checkHeaders: makePrimitive("checkHeaders", {
              setCookies: [],
              body: "",
              servedHttps: true,
              server: null,
              poweredBy: null,
            }),
            checkRobotsSitemap: makePrimitive("checkRobotsSitemap", {}),
            checkSensitiveFiles: makePrimitive("checkSensitiveFiles", []),
            // --- dependent (downstream) primitives: run after a shared resolve.
            // Pure/synchronous; not part of the concurrency assertion.
            inferProvider: () => "",
            analyzeCookies: () => ({
              missingSecure: [],
              missingHttpOnly: [],
              missingSameSite: [],
            }),
            analyzeMixedContent: () => ({ applicable: false, count: 0, samples: [] }),
            fingerprintTech: () => ({ detected: [] }),
            withTimeout,
            env: {},
          };

          // Launch the scan. `launchChecks` runs before any await, so independent
          // primitives are kicked off immediately; the shared dns/headers factories
          // fire on a microtask. Draining timers flushes those microtasks first,
          // then runs the resolution timers in delay order.
          const pending = runScan(domain, deps);
          await vi.runAllTimersAsync();
          await pending;

          // The first resolution must have observed ALL independent primitives as
          // already started — the engine launched every check before awaiting any.
          if (startedAtFirstResolution === null) {
            throw new Error("no primitive ever resolved");
          }
          for (const name of INDEPENDENT_PRIMITIVES) {
            if (!startedAtFirstResolution.has(name)) {
              throw new Error(
                `primitive "${name}" had not started when the first check resolved; ` +
                  `started: [${[...startedAtFirstResolution].join(", ")}]`
              );
            }
          }
          // Exactly the 7 independent primitives, all started before any resolution.
          expect(startedAtFirstResolution.size).toBe(INDEPENDENT_PRIMITIVES.length);

          // Shared primitives are composed by multiple checks but invoked once each.
          expect(invocationCounts.checkHeaders).toBe(1); // headers/cookies/mixed/tech
          expect(invocationCounts.checkDns).toBe(1); // dns/provider
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Sanity guard: the 11 defined checks compose the 7 independent primitives above.
describe("Feature: passive-scan-engine, Property 1 (setup): defined-check / primitive composition", () => {
  it("declares all 11 defined checks", () => {
    expect(CHECK_IDS).toHaveLength(11);
  });
});
