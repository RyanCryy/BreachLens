import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { withTimeout } from "./checks.js";
import {
  runScan,
  resolutionFailureMessage,
  RESULT_TYPE,
} from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 8: Resolution-failure error state
//
// For any dependency configuration in which DNS resolution yields no usable
// address (modeled as the dns primitive returning an observation with
// `resolves === false`) AND the site is unreachable (the headers primitive
// returning an observation with `reachable === false`), `runScan` SHALL return a
// distinct `Resolution_Failure` error state rather than a `Scan_Result`, carrying
// a non-empty human-readable message that contains no stack traces or internal
// error details — even when OTHER underlying dependencies throw Errors with
// populated, multi-line stacks.
//
// **Validates: Requirements 5.1, 5.2, 5.3**
//
// All check primitives are injected via `deps`, so no real network is touched.
// The dns primitive is pinned to a `resolves === false` observation and the
// headers primitive to a `reachable === false` observation, so the engine's
// DNS-resolution gate (`!dnsRes.resolves && !hdrRes.reachable`) always fires.
// Every OTHER primitive is randomized — including primitives that throw or reject
// Errors carrying stacky, multi-line `.stack` strings (and primitives that hang
// or overrun their Check_Timeout). Hang/timeout behaviors run instantly under
// vi.useFakeTimers() + vi.runAllTimersAsync(), so 100+ iterations stay fast.
//
// The key sanitization assertion: regardless of what those other dependencies
// throw, the returned `Resolution_Failure.message` must remain the fixed,
// friendly, domain-parameterized string with NO stack markers leaked into it.
// ---------------------------------------------------------------------------

// Stack-frame / internal-detail markers that must NEVER appear in the
// user-facing Resolution_Failure message (Req 5.3).
const STACK_MARKERS = [
  "\n", // a multi-line message would betray a serialized stack
  "    at ", // V8 stack frame marker
  "\tat ", // tab-indented stack frame marker
  "Error:", // serialized Error prefix
  ".js:", // a source file:line marker
  "node:internal", // node internal module path
  "/Users/", // an absolute filesystem path
  "checks.js", // an internal module name
];

// Build an Error that carries a populated, multi-line stack with classic frame
// markers, plus a stacky message — the worst case for message leakage.
function stackyError(label) {
  const err = new Error(
    `Error: ${label} blew up at runtime\n    at Object.run (/Users/dev/project/netlify/functions/lib/checks.js:42:13)`
  );
  err.stack = [
    `Error: ${label} blew up`,
    "    at Object.run (/Users/dev/project/netlify/functions/lib/checks.js:42:13)",
    "    at async runScan (/Users/dev/project/netlify/functions/lib/scan-engine.js:512:5)",
    "    at processTicksAndRejections (node:internal/process/task_queues:95:5)",
  ].join("\n");
  return err;
}

// The behaviors the OTHER (non-dns, non-headers) primitives quantify over. The
// `throw`/`reject` variants carry stacky Errors; `hang`/`timeout` exercise the
// per-check withTimeout + global watchdog under fake timers.
const otherBehaviorArb = fc.constantFrom(
  "success",
  "throw",
  "reject",
  "hang",
  "timeout"
);

// One behavior per OTHER independent network primitive. `dns` and `headers` are
// intentionally NOT randomized: they are pinned to drive the resolution gate.
const otherPrimitiveBehaviorsArb = fc.record({
  caa: otherBehaviorArb,
  ssl: otherBehaviorArb,
  subdomains: otherBehaviorArb,
  robots: otherBehaviorArb,
  files: otherBehaviorArb,
});

// A delay comfortably larger than any per-check Check_Timeout (6000–8000 ms) and
// the global watchdog, so a "timeout" primitive always loses to withTimeout.
const LATE_MS = 60000;

// A benign success observation for an OTHER primitive (shape is irrelevant — the
// gate fires before aggregation, so these checks' outcomes are never assembled).
const OK = { ok: true };

// Build a primitive exhibiting `behavior`. Failing variants throw/reject Errors
// that carry stacky, multi-line `.stack` strings, so we prove the friendly
// Resolution_Failure message never leaks any of it.
function makeOtherPrimitive(behavior, label) {
  switch (behavior) {
    case "success":
      return async () => OK;
    case "throw":
      // Synchronous throw with a populated stack.
      return () => {
        throw stackyError(label);
      };
    case "reject":
      return () => Promise.reject(stackyError(label));
    case "hang":
      return () => new Promise(() => {});
    case "timeout":
      return () => new Promise((resolve) => setTimeout(() => resolve(OK), LATE_MS));
    default:
      throw new Error(`unknown behavior: ${behavior}`);
  }
}

// Build a full `deps` object: dns pinned to `resolves === false`, headers pinned
// to `reachable === false`, and every other primitive driven by `behaviors`.
function buildDeps(behaviors) {
  return {
    // DNS positively reports no usable address (ran, but resolves === false).
    checkDns: async () => ({
      resolves: false,
      nameservers: [],
      spf: false,
      dmarc: false,
      mx: [],
    }),
    // Headers ran but the site is unreachable (reachable === false).
    checkHeaders: async () => ({
      reachable: false,
      hsts: false,
      csp: false,
      xfo: null,
      xcto: null,
      referrerPolicy: null,
      permissionsPolicy: null,
      setCookies: [],
      body: "",
      servedHttps: false,
      server: null,
      poweredBy: null,
    }),

    // Every OTHER primitive is randomized (incl. stacky throwers / rejecters).
    lookupCaa: makeOtherPrimitive(behaviors.caa, "caa"),
    checkSsl: makeOtherPrimitive(behaviors.ssl, "ssl"),
    checkSubdomains: makeOtherPrimitive(behaviors.subdomains, "subdomains"),
    checkRobotsSitemap: makeOtherPrimitive(behaviors.robots, "robots"),
    checkSensitiveFiles: makeOtherPrimitive(behaviors.files, "files"),

    // Deterministic, content-driven transforms (never the source of a failure).
    inferProvider: (nameservers) =>
      Array.isArray(nameservers) && nameservers.length > 0 ? "ExampleDNS" : "",
    analyzeCookies: (setCookies) =>
      Array.isArray(setCookies) && setCookies.length > 0
        ? { missingSecure: ["sid"], missingHttpOnly: [], missingSameSite: [] }
        : { missingSecure: [], missingHttpOnly: [], missingSameSite: [] },
    analyzeMixedContent: (body, servedHttps) =>
      servedHttps && typeof body === "string" && body.includes("http://")
        ? { applicable: true, count: 1, samples: ["http://x"] }
        : { applicable: false, count: 0, samples: [] },
    fingerprintTech: (server) => (server ? { detected: [server] } : { detected: [] }),

    // Real bounded-timeout helper so fake timers drive the per-check budgets.
    withTimeout,
    env: {},
  };
}

describe("Feature: passive-scan-engine, Property 8: Resolution-failure error state", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns a distinct Resolution_Failure with a sanitized message when DNS yields no address and the site is unreachable", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.domain(),
        otherPrimitiveBehaviorsArb,
        async (domain, behaviors) => {
          const deps = buildDeps(behaviors);

          const pending = runScan(domain, deps);
          // Trip every per-check withTimeout (and the global watchdog), then flush
          // the microtasks chained after them so the scan can settle.
          await vi.runAllTimersAsync();
          const result = await pending;

          // Req 5.1: a distinct Resolution_Failure error state, NOT a Scan_Result.
          expect(result.type).toBe(RESULT_TYPE.RESOLUTION_FAILURE);
          expect(result).not.toHaveProperty("outcomes");
          expect(result.domain).toBe(domain);

          // Req 5.2: a non-empty, human-readable message that is the fixed,
          // friendly, domain-parameterized string.
          expect(typeof result.message).toBe("string");
          expect(result.message.length).toBeGreaterThan(0);
          expect(result.message).toBe(resolutionFailureMessage(domain));
          expect(result.message).toContain(domain);

          // Req 5.3: the message contains NO stack traces or internal details,
          // even though other dependencies threw Errors with populated stacks.
          for (const marker of STACK_MARKERS) {
            expect(result.message).not.toContain(marker);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});
