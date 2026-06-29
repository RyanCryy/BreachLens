import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { withTimeout } from "./checks.js";
import { runScan, CHECK_IDS, RESULT_TYPE } from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 2: Result completeness
//
// For any assignment of behaviors (success, empty, error, rejection, or timeout)
// to the defined checks, when the scan resolves to a Scan_Result, the set of
// Check_Outcome ids SHALL equal CHECK_IDS exactly — one outcome per defined
// check, with no omissions and no duplicates.
//
// **Validates: Requirements 1.2, 2.3**
//
// All check primitives are injected via `deps`, so no real network is touched.
// Hang/timeout behaviors run instantly under vi.useFakeTimers(): the engine's
// per-check `withTimeout` (and the global watchdog) are driven by fake timers,
// and `vi.runAllTimersAsync()` trips every budget so 100+ iterations stay fast.
//
// Behavior assignment is done at the *independent primitive* level, faithfully
// modelling the engine's primitive sharing:
//   - `checkDns`     feeds both `dns` and `provider`,
//   - `checkHeaders` feeds `headers`, `cookies`, `mixed-content`, and `tech`.
// So a single primitive's behavior fans out to every check derived from it,
// while the property remains over arbitrary per-check behavior combinations.
//
// IMPORTANT — keeping the property about Scan_Result completeness: the engine's
// DNS-resolution gate diverts to a Resolution_Failure (NOT a Scan_Result) ONLY
// when the dns observation positively reports `resolves === false` AND the site
// is unreachable. To ensure `runScan` always returns a Scan_Result here (so the
// completeness invariant is exercised on every iteration), the dns success
// shapes carry `resolves: true`. When the dns primitive instead fails (throw /
// reject / hang / timeout) it yields NO observation, so the gate cannot fire on
// `resolves === false` either. Hence the gate never diverts and `runScan`
// always resolves to a Scan_Result, no matter the behavior assignment.
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

// A delay comfortably larger than any per-check Check_Timeout (6000–8000 ms) and
// the global watchdog, so a "timeout" primitive always loses the race to the
// engine's withTimeout fallback and is recorded Unavailable.
const LATE_MS = 60000;

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

// Raw success shapes per primitive. Both the findings and empty dns shapes carry
// `resolves: true` so the DNS-resolution gate never diverts to a
// Resolution_Failure — `runScan` always resolves to a Scan_Result regardless of
// the behavior assignment, keeping the property about Scan_Result completeness.
const FINDINGS = {
  dns: {
    resolves: true,
    spf: true,
    dmarc: true,
    mx: [{ exchange: "mail.example.com" }],
    nameservers: ["ns1.example.com"],
  },
  caa: { status: "present", records: ['0 issue "letsencrypt.org"'] },
  ssl: { validTo: "2030-01-01", issuer: "X", subject: "Y", validFrom: "2020-01-01", expiresInDays: 365, valid: true },
  subdomains: { subdomains: ["api.example.com", "www.example.com"] },
  headers: {
    reachable: true,
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
  dns: { resolves: true, spf: false, dmarc: false, mx: [], nameservers: [] },
  caa: { status: "missing", records: [] },
  ssl: { validTo: null },
  subdomains: { subdomains: [] },
  headers: {
    reachable: true,
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
// pure transforms are deterministic and content-driven so they always succeed.
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
    fingerprintTech: (server) => (server ? { detected: [server] } : { detected: [] }),

    // Real bounded-timeout helper so fake timers drive the per-check budgets.
    withTimeout,
    env: {},
  };
}

describe("Feature: passive-scan-engine, Property 2: Result completeness", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns a Scan_Result whose Check_Outcome ids equal CHECK_IDS exactly — one per defined check, no omissions, no duplicates", async () => {
    await fc.assert(
      fc.asyncProperty(primitiveBehaviorsArb, async (behaviors) => {
        const deps = buildDeps(behaviors);

        const pending = runScan("example.com", deps);
        // Trip every per-check withTimeout (and the global watchdog), and flush the
        // microtasks chained after them so the scan can settle.
        await vi.runAllTimersAsync();
        const result = await pending;

        // For any behavior assignment, the scan resolves to a full Scan_Result —
        // the DNS-resolution gate never diverts (dns success shapes resolve, and a
        // failing dns yields no observation to trip the gate).
        expect(result.type).toBe(RESULT_TYPE.SCAN);

        const ids = result.outcomes.map((o) => o.id);

        // One outcome per defined check — no omissions (length matches CHECK_IDS).
        expect(ids).toHaveLength(CHECK_IDS.length);

        // No duplicates — the id multiset has no repeats.
        expect(new Set(ids).size).toBe(ids.length);

        // The SET of ids equals CHECK_IDS exactly — no omissions, no extras.
        expect(new Set(ids)).toEqual(new Set(CHECK_IDS));

        // Every defined check is present exactly once.
        for (const id of CHECK_IDS) {
          expect(ids.filter((x) => x === id)).toHaveLength(1);
        }
      }),
      { numRuns: 100 }
    );
  });
});
