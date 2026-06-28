// Property-based test for the Recheck_Router (lib/recheck.js).
//
// Property 2: Non-recheckable and unrecognized ids yield indeterminate without
// running any check.
//
// For any Finding_Id that is NOT a recognized recheckable family — every
// `subdomain-*` id and every otherwise-unrecognized string — `recheckFinding`
// returns status === "indeterminate" and invokes NONE of the passive check
// dependencies.
//
// Validates: Requirements 1.7, 2.6, 3.10, 3.12

import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";

import { recheckFinding, STATUS, isRecheckable } from "./recheck.js";

// Build a fresh `deps` object whose every check function is a vi.fn() spy. If the
// router runs any passive check for a non-recheckable id, the matching spy records a
// call and the property fails. The spies return harmless values so that, in the event
// of an (incorrect) invocation, the orchestrator still completes rather than throwing.
function makeSpyDeps() {
  return {
    checkDns: vi.fn(async () => ({ spf: false, dmarc: false, caa: { status: "missing" } })),
    checkSsl: vi.fn(async () => ({ expiresInDays: 90, error: null })),
    checkHeaders: vi.fn(async () => ({ reachable: true, setCookies: [], body: "", servedHttps: true })),
    checkRobotsSitemap: vi.fn(async () => ({ sensitiveDisallows: [] })),
    analyzeCookies: vi.fn(() => ({ missingSecure: [], missingHttpOnly: [], missingSameSite: [] })),
    analyzeMixedContent: vi.fn(() => ({ count: 0 })),
    checkFileStatus: vi.fn(async () => ({ reachable: true, status: 404, exposed: false })),
  };
}

describe("Feature: finding-recheck, Property 2: Non-recheckable and unrecognized ids yield indeterminate without running any check", () => {
  it("returns indeterminate and invokes no passive check for non-recheckable / unrecognized ids", async () => {
    await fc.assert(
      fc.asyncProperty(
        // A mix of subdomain-* ids and arbitrary strings, filtered to only those the
        // router classifies as non-recheckable (guards against accidentally generating
        // a real recheckable id such as "spf-missing" or "ssl-...").
        fc
          .oneof(
            fc.string().map((s) => `subdomain-${s}`),
            fc.string(),
          )
          .filter((id) => isRecheckable(id) === false),
        fc.domain(),
        async (findingId, domain) => {
          const deps = makeSpyDeps();

          const result = await recheckFinding({ domain, findingId }, deps);

          // Status must be indeterminate (Requirements 1.7, 2.6, 3.10, 3.12).
          expect(result.status).toBe(STATUS.INDETERMINATE);
          // The requested id is echoed back unchanged.
          expect(result.findingId).toBe(findingId);

          // NONE of the passive check dependencies may have been invoked.
          for (const spy of Object.values(deps)) {
            expect(spy).not.toHaveBeenCalled();
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
