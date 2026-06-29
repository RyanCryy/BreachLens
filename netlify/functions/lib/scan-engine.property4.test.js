import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { withTimeout } from "./checks.js";
import {
  runScan,
  CHECK_IDS,
  CHECK_STATUS,
  RESULT_TYPE,
} from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 4: Partial-failure isolation
//
// For any subset of checks designated to fail (throw, reject, hang, or exceed
// their Check_Timeout), the scan SHALL still resolve to a complete Scan_Result
// in which every failing check is Unavailable and every non-failing check
// retains the status implied by its own result.
//
// **Validates: Requirements 2.1, 2.2, 2.3**
//
// All check primitives are injected via `deps`, so no real network is touched.
// Hang/timeout behaviors run instantly under vi.useFakeTimers(): the engine's
// per-check `withTimeout` (and the global watchdog) are driven by fake timers,
// and `vi.runAllTimersAsync()` trips every budget so 100+ iterations stay fast.
//
// Behavior assignment is done at the *independent primitive* level (the design's
// option for shared primitives), and the expected per-check status is derived
// from there. This faithfully models the engine's sharing:
//   - `checkDns`     feeds both `dns` and `provider` (inferProvider over its NS),
//   - `checkHeaders` feeds `headers`, `cookies`, `mixed-content`, and `tech`
//     (the single passive fetch reused by the dependent checks).
// So a single primitive failure correctly takes down every check derived from it,
// while checks fed by healthy primitives keep the status implied by their result.
// ---------------------------------------------------------------------------

// The six per-primitive behaviors the property quantifies over.
const behaviorArb = fc.constantFrom(
  "success-with-findings",
  "success-empty",
  "throw",
  "reject",
  "hang",
  "timeout"
);

// One behavior per independent network primitive. The pure transforms
// (inferProvider / analyzeCookies / analyzeMixedContent / fingerprintTech) never
// fail on their own — failures originate strictly from these network primitives.
const primitiveBehaviorsArb = fc.record({
  dns: behaviorArb, // feeds `dns` + `provider`
  caa: behaviorArb, // feeds `caa`
  ssl: behaviorArb, // feeds `tls`
  subdomains: behaviorArb, // feeds `subdomains`
  headers: behaviorArb, // feeds `headers` + `cookies` + `mixed-content` + `tech`
  robots: behaviorArb, // feeds `robots`
  files: behaviorArb, // feeds `exposed-files`
});

const FAIL_BEHAVIORS = new Set(["throw", "reject", "hang", "timeout"]);

// A delay comfortably larger than any per-check Check_Timeout (6000–8000 ms) and
// the global watchdog, so a "timeout" primitive always loses the race to the
// engine's withTimeout fallback and is recorded Unavailable.
const LATE_MS = 60000;

// Map a primitive behavior to the status it implies for the checks it feeds.
function statusFor(behavior) {
  if (behavior === "success-with-findings") return CHECK_STATUS.SUCCESS;
  if (behavior === "success-empty") return CHECK_STATUS.EMPTY;
  return CHECK_STATUS.UNAVAILABLE; // throw / reject / hang / timeout
}

// Build a network primitive that exhibits `behavior`, producing `findingsValue`
// on the success-with-findings path and `emptyValue` on the success-empty path.
function makePrimitive(behavior, findingsValue, emptyValue) {
  switch (behavior) {
    case "success-with-findings":
      return async () => findingsValue;
    case "success-empty":
      return async () => emptyValue;
    case "throw":
      // Synchronous throw — normalized to a rejection by the launch wrapper.
      return () => {
        throw new Error("synchronous primitive failure");
      };
    case "reject":
      return () => Promise.reject(new Error("async primitive rejection"));
    case "hang":
      // Never settles — only the per-check withTimeout can resolve it.
      return () => new Promise(() => {});
    case "timeout":
      // Settles, but well past the Check_Timeout, so withTimeout fires first.
      return () =>
        new Promise((resolve) => setTimeout(() => resolve(findingsValue), LATE_MS));
    default:
      throw new Error(`unknown behavior: ${behavior}`);
  }
}

// Raw success shapes per primitive. The "findings" shape drives the registry's
// toFindings to a non-empty array (-> Success); the "empty" shape drives it to an
// empty array (-> Empty). For the shared `headers` fetch, the findings shape must
// satisfy ALL four dependent checks at once (and the empty shape none of them).
const FINDINGS = {
  dns: { spf: true, dmarc: true, mx: [{ exchange: "mail.example.com" }], nameservers: ["ns1.example.com"] },
  caa: { status: "present", records: ['0 issue "letsencrypt.org"'] },
  ssl: { validTo: "2030-01-01", issuer: "X", subject: "Y", validFrom: "2020-01-01", expiresInDays: 365, valid: true },
  subdomains: { subdomains: ["api.example.com", "www.example.com"] },
  headers: {
    hsts: true,
    csp: true,
    xfo: "DENY",
    xcto: "nosniff",
    setCookies: ["sid=abc"],
    body: '<img src="http://insecure.example.com/x.png">',
    servedHttps: true,
    server: "nginx",
    poweredBy: "PHP/8.2",
  },
  robots: { sensitiveDisallows: ["/admin"], sitemapPresent: true, sitemapUrlCount: 5 },
  files: [{ path: "/.env", status: 200, exposed: true }],
};

const EMPTY = {
  dns: { spf: false, dmarc: false, mx: [], nameservers: [] },
  caa: { status: "missing", records: [] },
  ssl: { validTo: null },
  subdomains: { subdomains: [] },
  headers: {
    hsts: false,
    csp: false,
    xfo: null,
    xcto: null,
    referrerPolicy: null,
    permissionsPolicy: null,
    setCookies: [],
    body: "",
    servedHttps: true,
    server: null,
    poweredBy: null,
  },
  robots: { sensitiveDisallows: [], sitemapPresent: false },
  files: [{ path: "/.env", status: 404, exposed: false }],
};

// Build a full `deps` object from the per-primitive behavior assignment. The four
// pure transforms are deterministic and content-driven so they always succeed and
// faithfully turn the shared raw shapes into findings vs empty for each dependent
// check.
function buildDeps(behaviors) {
  return {
    checkDns: makePrimitive(behaviors.dns, FINDINGS.dns, EMPTY.dns),
    lookupCaa: makePrimitive(behaviors.caa, FINDINGS.caa, EMPTY.caa),
    checkSsl: makePrimitive(behaviors.ssl, FINDINGS.ssl, EMPTY.ssl),
    checkSubdomains: makePrimitive(behaviors.subdomains, FINDINGS.subdomains, EMPTY.subdomains),
    checkHeaders: makePrimitive(behaviors.headers, FINDINGS.headers, EMPTY.headers),
    checkRobotsSitemap: makePrimitive(behaviors.robots, FINDINGS.robots, EMPTY.robots),
    checkSensitiveFiles: makePrimitive(behaviors.files, FINDINGS.files, EMPTY.files),

    // Deterministic, content-driven transforms (never the source of a failure).
    inferProvider: (nameservers) =>
      Array.isArray(nameservers) && nameservers.length > 0 ? "ExampleDNS" : "",
    analyzeCookies: (setCookies) =>
      Array.isArray(setCookies) && setCookies.length > 0
        ? { missingSecure: ["sid"], missingHttpOnly: [], missingSameSite: [] }
        : { missingSecure: [], missingHttpOnly: [], missingSameSite: [] },
    analyzeMixedContent: (body, servedHttps) =>
      servedHttps && typeof body === "string" && body.includes("http://")
        ? { applicable: true, count: 1, samples: ["http://insecure.example.com/x.png"] }
        : { applicable: false, count: 0, samples: [] },
    fingerprintTech: (server) =>
      server ? { detected: [server] } : { detected: [] },

    // Real bounded-timeout helper so fake timers drive the per-check budgets.
    withTimeout,
    env: {},
  };
}

// Derive the expected final status for every defined check from the per-primitive
// behavior assignment.
function expectedStatuses(b) {
  return {
    dns: statusFor(b.dns),
    provider: statusFor(b.dns),
    caa: statusFor(b.caa),
    tls: statusFor(b.ssl),
    subdomains: statusFor(b.subdomains),
    headers: statusFor(b.headers),
    cookies: statusFor(b.headers),
    "mixed-content": statusFor(b.headers),
    tech: statusFor(b.headers),
    robots: statusFor(b.robots),
    "exposed-files": statusFor(b.files),
  };
}

describe("Feature: passive-scan-engine, Property 4: Partial-failure isolation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("isolates failing checks as Unavailable while non-failing checks keep their implied status", async () => {
    await fc.assert(
      fc.asyncProperty(primitiveBehaviorsArb, async (behaviors) => {
        const deps = buildDeps(behaviors);

        const pending = runScan("example.com", deps);
        // Trip every per-check withTimeout (and the global watchdog), and flush the
        // microtasks chained after them so the scan can settle.
        await vi.runAllTimersAsync();
        const result = await pending;

        // A failing check never aborts its siblings: the scan still resolves to a
        // complete Scan_Result, never a thrown error or a Resolution_Failure.
        expect(result.type).toBe(RESULT_TYPE.SCAN);
        expect(result.domain).toBe("example.com");

        // Exactly one Check_Outcome per defined check — no omissions, no
        // duplicates (Req 2.3).
        const ids = result.outcomes.map((o) => o.id);
        expect(ids).toHaveLength(CHECK_IDS.length);
        expect(new Set(ids)).toEqual(new Set(CHECK_IDS));

        const expected = expectedStatuses(behaviors);
        const byId = new Map(result.outcomes.map((o) => [o.id, o]));

        for (const id of CHECK_IDS) {
          const outcome = byId.get(id);
          // Every check retains the status implied by its (or its primitive's) result.
          expect(outcome.status).toBe(expected[id]);

          if (expected[id] === CHECK_STATUS.UNAVAILABLE) {
            // Failing checks are Unavailable with no findings and a sanitized,
            // non-empty reason (Req 2.1, 2.2).
            expect(outcome.findings).toEqual([]);
            expect(typeof outcome.error).toBe("string");
            expect(outcome.error.length).toBeGreaterThan(0);
          } else {
            // Non-failing checks carry no error.
            expect(outcome.error).toBeNull();
            if (expected[id] === CHECK_STATUS.SUCCESS) {
              expect(outcome.findings.length).toBeGreaterThan(0);
            } else {
              expect(outcome.findings).toEqual([]);
            }
          }
        }
      }),
      { numRuns: 100 }
    );
  });
});
