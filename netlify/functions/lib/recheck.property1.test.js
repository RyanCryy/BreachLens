import { describe, it, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { recheckFinding, STATUS } from "./recheck.js";

// Property-based test for the Recheck_Router result contract.
//
// Design property (finding-recheck, Property 1):
//   For ANY Finding_Id (arbitrary strings + constructed valid family ids) and ANY
//   observation outcome, recheckFinding() returns a status in {resolved, unresolved,
//   indeterminate}, echoes back the requested findingId unchanged, and includes a
//   non-empty message no longer than 500 characters.
//
//   Validates: Requirements 1.2, 1.3, 1.4
//
// The orchestrator's check dependencies are fully injected (`deps`) so NO real network
// is ever touched. The fake deps return fast-check-generated values — including
// well-formed observations, malformed shapes, null/undefined, synchronous throws,
// rejected promises, and never-resolving (hanging) promises that exercise the per-check
// and overall timeout paths. Fake timers + runAllTimersAsync keep the hanging cases
// instant, so 100+ iterations stay fast.

const VALID_STATUSES = [STATUS.RESOLVED, STATUS.UNRESOLVED, STATUS.INDETERMINATE];

// Known recheckable / known family Finding_Ids the router understands (plus a couple of
// dynamic-prefix and explicitly non-recheckable ids), per the design mapping table.
const KNOWN_FINDING_IDS = [
  "spf-missing",
  "dmarc-missing",
  "caa-missing",
  "hdr-hsts",
  "hdr-csp",
  "hdr-xfo",
  "hdr-xcto",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "mixed-content",
  "robots-sensitive",
  "ssl-expired",
  "exposed-file-/.env",
  "subdomain-dev",
];

// A "rich" observation whose fields cover every family's reader, so generated values
// regularly reach the resolved/unresolved branches (not just the failure → indeterminate
// branch). Whichever check the router runs, it finds plausible fields here.
const richObservation = fc.record({
  // DNS-backed families (spf / dmarc / caa)
  spf: fc.boolean(),
  dmarc: fc.boolean(),
  caa: fc.record({ status: fc.constantFrom("present", "missing", "unknown", "weird") }),
  // SSL family — boundary-rich days incl. negatives, 0, 30, 31, and null
  expiresInDays: fc.oneof(fc.integer({ min: -100, max: 400 }), fc.constant(null)),
  error: fc.oneof(fc.constant(null), fc.string()),
  // headers / cookie / mixed-content families
  reachable: fc.boolean(),
  hsts: fc.boolean(),
  csp: fc.boolean(),
  xfo: fc.boolean(),
  xcto: fc.boolean(),
  setCookies: fc.array(fc.string()),
  body: fc.string(),
  servedHttps: fc.boolean(),
  count: fc.integer({ min: 0, max: 10 }),
  missingSecure: fc.array(fc.string()),
  missingHttpOnly: fc.array(fc.string()),
  missingSameSite: fc.array(fc.string()),
  // robots family
  sensitiveDisallows: fc.array(fc.string()),
  // exposed-file family
  status: fc.oneof(fc.integer({ min: 100, max: 599 }), fc.constant(null)),
});

// The value a "resolving" dependency yields: a mix of rich well-formed observations,
// completely arbitrary shapes (malformed), and null/undefined.
const dependencyValue = fc.oneof(
  { arbitrary: richObservation, weight: 4 },
  { arbitrary: fc.anything(), weight: 2 },
  { arbitrary: fc.constant(null), weight: 1 },
  { arbitrary: fc.constant(undefined), weight: 1 }
);

// How a dependency behaves on a given run.
const dependencyBehavior = fc.oneof(
  { arbitrary: fc.record({ kind: fc.constant("value"), value: dependencyValue }), weight: 6 },
  { arbitrary: fc.record({ kind: fc.constant("throw") }), weight: 1 },
  { arbitrary: fc.record({ kind: fc.constant("reject") }), weight: 1 },
  { arbitrary: fc.record({ kind: fc.constant("hang") }), weight: 1 }
);

// Build a `deps` object whose every check exhibits the generated behavior. Async checks
// (checkDns/checkSsl/checkHeaders/checkRobotsSitemap/checkFileStatus) return promises;
// the analysis helpers (analyzeCookies/analyzeMixedContent) are synchronous.
function makeDeps(behavior) {
  const asyncFn = () => {
    switch (behavior.kind) {
      case "throw":
        throw new Error("simulated synchronous check failure");
      case "reject":
        return Promise.reject(new Error("simulated rejected check"));
      case "hang":
        return new Promise(() => {}); // never resolves — exercises the timeout path
      default:
        return Promise.resolve(behavior.value);
    }
  };
  const syncFn = () => {
    if (behavior.kind === "throw") throw new Error("simulated synchronous analysis failure");
    // For reject/hang there is no synchronous analog; fall back to the generated value.
    return behavior.kind === "value" ? behavior.value : undefined;
  };
  return {
    checkDns: asyncFn,
    checkSsl: asyncFn,
    checkHeaders: asyncFn,
    checkRobotsSitemap: asyncFn,
    checkFileStatus: asyncFn,
    analyzeCookies: syncFn,
    analyzeMixedContent: syncFn,
  };
}

describe("Feature: finding-recheck, Property 1: Re-check result always satisfies the result contract", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns status in the enum, echoes findingId, and a non-empty message <= 500 chars for any id and any observation outcome", async () => {
    await fc.assert(
      fc.asyncProperty(
        // findingId: arbitrary strings AND constructed valid family ids.
        fc.oneof(fc.string(), fc.constantFrom(...KNOWN_FINDING_IDS)),
        fc.string({ minLength: 1 }), // domain (ignored by the fake deps)
        dependencyBehavior,
        async (findingId, domain, behavior) => {
          const deps = makeDeps(behavior);

          // Start the re-check, drain all (faked) timers so hanging deps hit their
          // per-check / overall timeout instantly, then await the settled result.
          const pending = recheckFinding({ domain, findingId }, deps);
          await vi.runAllTimersAsync();
          const result = await pending;

          // status ∈ {resolved, unresolved, indeterminate} (Requirement 1.2)
          if (!VALID_STATUSES.includes(result.status)) {
            throw new Error(`status not in enum: ${JSON.stringify(result.status)}`);
          }
          // echoes the requested findingId unchanged (Requirement 1.3)
          if (result.findingId !== findingId) {
            throw new Error(
              `findingId not echoed: expected ${JSON.stringify(findingId)}, got ${JSON.stringify(result.findingId)}`
            );
          }
          // non-empty message no longer than 500 chars (Requirement 1.4)
          if (typeof result.message !== "string" || result.message.length === 0) {
            throw new Error(`message empty or not a string: ${JSON.stringify(result.message)}`);
          }
          if (result.message.length > 500) {
            throw new Error(`message exceeds 500 chars: length ${result.message.length}`);
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
