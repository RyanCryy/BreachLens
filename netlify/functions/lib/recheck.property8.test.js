import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { recheckFinding, STATUS } from "./recheck.js";

// ---------------------------------------------------------------------------
// Property 8: Status is a deterministic, path-independent function of the inputs
//
//   For any Finding_Id and any fixed observation/injected dependencies, two
//   evaluations of the router — one simulating the Re-check-button path and one
//   simulating the chat path — SHALL produce identical Recheck_Status values,
//   regardless of invocation order or which path invoked it.
//
//   Validates: Requirements 9.1, 9.2, 9.3
//
// Both the /api/recheck endpoint and the chat path call the SAME shared
// `recheckFinding` orchestrator (design.md §9, Requirement 9.2). So we simulate the
// "two paths" structurally: invoke `recheckFinding` twice with the SAME findingId,
// the SAME domain, and the SAME deterministic injected dependencies. The injected
// deps return FIXED, generated values (no randomness, no real network, no timers),
// so the only thing that could make the two evaluations differ would be hidden
// state or nondeterminism inside the router — which this property rules out.
//
// We also run the two evaluations in BOTH orders (button-then-chat and
// chat-then-button) to confirm invocation order never alters the result.
// ---------------------------------------------------------------------------

// Generators for each piece of a deterministic, fixed observation. Each value is
// drawn once per run and then frozen into the fake deps, so every invocation of a
// given dependency within a run returns the identical value.
const caaStatusArb = fc.constantFrom("present", "missing", "unknown");
const httpStatusArb = fc.integer({ min: 100, max: 599 });

// A fully deterministic set of injected check dependencies built from generated —
// but then fixed — values. Mirrors the output shapes of the real lib/checks.js
// primitives that the orchestrator reads (see design "Normalized observation").
const fixedDepsArb = fc
  .record({
    spf: fc.boolean(),
    dmarc: fc.boolean(),
    caa: caaStatusArb,
    expiresInDays: fc.oneof(fc.constantFrom(-1, 0, 30, 31), fc.integer({ min: -400, max: 1000 })),
    sslError: fc.oneof(fc.constant(null), fc.string({ minLength: 1 })),
    reachable: fc.boolean(),
    hsts: fc.boolean(),
    csp: fc.boolean(),
    xfo: fc.boolean(),
    xcto: fc.boolean(),
    missingSecure: fc.array(fc.string({ minLength: 1 }), { maxLength: 4 }),
    missingHttpOnly: fc.array(fc.string({ minLength: 1 }), { maxLength: 4 }),
    missingSameSite: fc.array(fc.string({ minLength: 1 }), { maxLength: 4 }),
    mixedCount: fc.nat({ max: 25 }),
    sensitiveDisallows: fc.array(fc.string({ minLength: 1 }), { maxLength: 4 }),
    fileStatus: httpStatusArb,
    robotsProbeReachable: fc.boolean(),
  })
  .map((v) => {
    // Freeze the generated values into deterministic, side-effect-free deps. Every
    // call returns the SAME object, so the dependency layer is a pure constant
    // function of its identity — any difference between two runs must come from the
    // router itself, which is exactly what Property 8 forbids.
    const headers = {
      reachable: v.reachable,
      hsts: v.hsts,
      csp: v.csp,
      xfo: v.xfo,
      xcto: v.xcto,
      setCookies: ["sid=abc"],
      body: "<html></html>",
      servedHttps: true,
    };
    const cookies = {
      missingSecure: v.missingSecure,
      missingHttpOnly: v.missingHttpOnly,
      missingSameSite: v.missingSameSite,
    };
    return {
      checkDns: async () => ({ spf: v.spf, dmarc: v.dmarc, caa: { status: v.caa } }),
      checkSsl: async () => ({ expiresInDays: v.expiresInDays, error: v.sslError }),
      checkHeaders: async () => headers,
      checkRobotsSitemap: async () => ({ sensitiveDisallows: v.sensitiveDisallows }),
      analyzeCookies: () => cookies,
      analyzeMixedContent: () => ({ count: v.mixedCount }),
      // checkFileStatus serves two roles: the robots reachability probe (/robots.txt)
      // and the exposed-file status-only probe. Both return fixed values per run.
      checkFileStatus: async (_domain, path) =>
        path === "/robots.txt"
          ? { reachable: v.robotsProbeReachable, status: v.robotsProbeReachable ? 200 : null, exposed: false }
          : { reachable: true, status: v.fileStatus, exposed: v.fileStatus === 200 },
    };
  });

// Finding_Id generator: a mix of valid recheckable family ids (exact + dynamic
// ssl-/exposed-file- prefixes), non-recheckable subdomain-* ids, and arbitrary
// strings, so the property holds across the entire input space.
const findingIdArb = fc.oneof(
  fc.constantFrom(
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
    "ssl-error",
    "ssl-expired",
    "ssl-expiring-soon",
    "exposed-file-/.env",
    "exposed-file-/.git/config"
  ),
  fc.string({ minLength: 1 }).map((s) => `ssl-${s}`),
  fc.string({ minLength: 1 }).map((s) => `exposed-file-${s}`),
  fc.string().map((s) => `subdomain-${s}`),
  fc.string()
);

describe("Recheck_Router — path-independent determinism", () => {
  it("Feature: finding-recheck, Property 8: Status is a deterministic, path-independent function of the inputs", async () => {
    await fc.assert(
      fc.asyncProperty(findingIdArb, fc.domain(), fixedDepsArb, async (findingId, domain, deps) => {
        // Simulate the Re-check-button path and the chat path: both call the single
        // shared orchestrator with identical inputs and identical fixed deps.
        const buttonPath = await recheckFinding({ domain, findingId }, deps);
        const chatPath = await recheckFinding({ domain, findingId }, deps);

        // Same id, same domain, same observable target state ⇒ identical status...
        expect(chatPath.status).toBe(buttonPath.status);
        // ...and identical message (the full result is path-independent).
        expect(chatPath.message).toBe(buttonPath.message);
        expect(chatPath.findingId).toBe(buttonPath.findingId);

        // Status is one of the three allowed values regardless of path.
        expect([STATUS.RESOLVED, STATUS.UNRESOLVED, STATUS.INDETERMINATE]).toContain(buttonPath.status);

        // Invocation ORDER must not matter: run the two paths in the reverse order
        // and confirm the result is still identical to the first evaluation.
        const chatFirst = await recheckFinding({ domain, findingId }, deps);
        const buttonSecond = await recheckFinding({ domain, findingId }, deps);
        expect(chatFirst.status).toBe(buttonPath.status);
        expect(buttonSecond.status).toBe(buttonPath.status);
        expect(chatFirst.message).toBe(buttonPath.message);
        expect(buttonSecond.message).toBe(buttonPath.message);
      }),
      { numRuns: 200 }
    );
  });
});
