import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  runScan,
  keyGateSentinel,
  CHECK_REGISTRY,
  CHECK_TIMEOUTS,
  CHECK_STATUS,
  RESULT_TYPE,
  MISSING_KEY_SENTINEL,
} from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 9: Paid-source key gating
//
// For any key-gated check, when no valid API key is configured in `deps.env`,
// the engine SHALL report that Check_Outcome as `Unavailable` WITHOUT invoking
// the underlying paid primitive; and when a valid key IS configured, the engine
// SHALL invoke the real primitive and derive the outcome from its returned
// observation, never substituting engine-fabricated findings.
//
// **Validates: Requirements 6.1, 6.2, 6.3**
//
// The engine exposes a general, registry-driven gate: a registry entry opts into
// gating by declaring `requiresKey: "<ENV_KEY>"`, and `launchChecks` consults
// `keyGateSentinel(entry, deps)` BEFORE calling the entry's `run`. We exercise it
// by injecting a `deps.registry` that overrides ONE existing check id ("tls")
// with a key-gated entry whose `run` is a spy primitive recording its invocation
// count. The `env` arbitrary toggles the key between invalid (absent / undefined /
// empty / whitespace -> gated) and valid (a non-empty trimmed string -> runs).
//
// All other checks are wired with trivial in-memory primitives so `runScan`
// resolves to a Scan_Result; `dns` returns `resolves: true` so the DNS-resolution
// gate never fires and we always reach aggregation. No real network is touched.
// ---------------------------------------------------------------------------

const KEY = "HIBP_API_KEY";
// The existing check id whose registry entry we override to be key-gated.
const GATED_ID = "tls";

// --- env arbitraries --------------------------------------------------------
// Invalid configurations — every one must gate the check (no valid key):
//   absent, explicit undefined, empty string, and whitespace-only strings.
const invalidEnvArb = fc.oneof(
  fc.constant({}), // key absent entirely
  fc.constant({ [KEY]: undefined }), // present but undefined
  fc.constant({ [KEY]: "" }), // empty string
  fc.constant({ [KEY]: "   " }), // spaces only
  fc.constant({ [KEY]: "\t\n " }) // mixed whitespace
);

// A valid key is any string that is non-empty AFTER trimming.
const validKeyArb = fc.string().filter((s) => s.trim().length > 0);
const validEnvArb = validKeyArb.map((k) => ({ [KEY]: k }));

// A scenario quantifies over: the env (valid vs invalid), whether the (real)
// primitive's observation carries findings, and the target domain.
const scenarioArb = fc.record({
  env: fc.oneof(invalidEnvArb, validEnvArb),
  runReturnsFindings: fc.boolean(),
  domain: fc.domain(),
});

// Pure predicate mirroring the engine's "valid/configured key" rule.
function hasValidKey(env) {
  const v = env && env[KEY];
  return typeof v === "string" && v.trim().length > 0;
}

// Build a full deps object. The gated entry overrides `tls` in the registry; its
// `run` is a spy recording invocation count and returning a findings-bearing or
// empty observation. Every other check uses a trivial in-memory primitive.
function buildDeps(env, runReturnsFindings, spy) {
  // The key-gated registry entry for the overridden check id.
  const gatedEntry = {
    requiresKey: KEY,
    timeout: CHECK_TIMEOUTS[GATED_ID],
    // Spy primitive: must NEVER be called when the key is invalid (Req 6.1).
    run: (...args) => {
      spy.count += 1;
      spy.args.push(args);
      // Observation drives the outcome: findings -> Success, none -> Empty.
      return runReturnsFindings
        ? { breaches: ["acme-corp-2019"] }
        : { breaches: [] };
    },
    // Pure: derive findings from the real observation only (no fabrication).
    toFindings: (raw) => {
      const breaches = raw && Array.isArray(raw.breaches) ? raw.breaches : [];
      return breaches.map((name) => ({ type: "breach", name }));
    },
  };

  return {
    // Override ONLY the gated id; all other entries come from the real registry.
    registry: { ...CHECK_REGISTRY, [GATED_ID]: gatedEntry },

    // --- primitives used by the non-overridden registry entries -------------
    // dns resolves so the DNS-resolution gate never fires.
    checkDns: async () => ({ resolves: true, nameservers: ["ns1.example.com"] }),
    // headers reachable so dependents behave and the gate stays closed.
    checkHeaders: async () => ({
      reachable: true,
      setCookies: [],
      body: "",
      servedHttps: true,
      server: null,
      poweredBy: null,
    }),
    checkSsl: async () => ({}), // unused: tls is overridden by the gated entry
    lookupCaa: async () => ({ status: "missing" }),
    checkSubdomains: async () => ({ subdomains: [] }),
    checkRobotsSitemap: async () => ({}),
    checkSensitiveFiles: async () => [],
    inferProvider: () => "",
    analyzeCookies: () => ({ missingSecure: [], missingHttpOnly: [], missingSameSite: [] }),
    analyzeMixedContent: () => ({ applicable: false, count: 0, samples: [] }),
    fingerprintTech: () => ({ detected: [] }),

    // Bounded-timeout helper that clears its timer when the inner promise wins,
    // so no real timers linger between iterations.
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

    env,
  };
}

describe("Feature: passive-scan-engine, Property 9: Paid-source key gating", () => {
  it("gates the paid primitive without a valid key (Unavailable, never invoked) and runs it with one (real observation drives the outcome)", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ env, runReturnsFindings, domain }) => {
        const spy = { count: 0, args: [] };
        const deps = buildDeps(env, runReturnsFindings, spy);

        const result = await runScan(domain, deps);

        // Precondition for Property 9: the scan resolves to a Scan_Result.
        expect(result.type).toBe(RESULT_TYPE.SCAN);

        const gated = result.outcomes.find((o) => o.id === GATED_ID);
        expect(gated).toBeDefined();

        if (!hasValidKey(env)) {
          // Req 6.1: no valid key -> Unavailable AND the paid primitive is NEVER
          // invoked, and no findings are fabricated.
          expect(spy.count).toBe(0);
          expect(gated.status).toBe(CHECK_STATUS.UNAVAILABLE);
          expect(gated.findings).toEqual([]);
        } else {
          // Req 6.2 / 6.3: valid key -> the REAL primitive IS invoked and the
          // outcome derives strictly from its returned observation.
          expect(spy.count).toBeGreaterThanOrEqual(1);
          if (runReturnsFindings) {
            expect(gated.status).toBe(CHECK_STATUS.SUCCESS);
            expect(gated.findings.length).toBeGreaterThan(0);
          } else {
            expect(gated.status).toBe(CHECK_STATUS.EMPTY);
            expect(gated.findings).toEqual([]);
          }
        }
      }),
      { numRuns: 100 }
    );
  });

  it("keyGateSentinel: gates a key-gated entry iff no valid key is configured, and never gates a non-key-gated entry", async () => {
    const gatedEntry = { requiresKey: KEY, run: () => ({}), toFindings: () => [] };
    const plainEntry = { run: () => ({}), toFindings: () => [] };

    await fc.assert(
      fc.property(fc.oneof(invalidEnvArb, validEnvArb), (env) => {
        const sentinel = keyGateSentinel(gatedEntry, { env });
        if (hasValidKey(env)) {
          // A valid key clears the gate.
          expect(sentinel).toBeNull();
        } else {
          // Any invalid/missing key gates to the missing-key sentinel.
          expect(sentinel).toBe(MISSING_KEY_SENTINEL);
        }
        // A non-key-gated entry is NEVER gated, regardless of env.
        expect(keyGateSentinel(plainEntry, { env })).toBeNull();
      }),
      { numRuns: 100 }
    );
  });
});
