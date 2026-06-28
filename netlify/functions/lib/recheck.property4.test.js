import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { recheckFinding, STATUS } from "./recheck.js";

// ---------------------------------------------------------------------------
// Property 4: Any check failure, unreachability, or error yields indeterminate
//
//   For any recheckable Finding_Id, when the mapped check dependency fails, is
//   unreachable, times out, or throws an arbitrary error, recheckFinding returns
//   status === "indeterminate" and never returns resolved or unresolved.
//
//   Validates: Requirements 3.13, 4.1, 4.5, 9.4
//
// The orchestrator accepts injected check dependencies (`deps`), so every failure
// mode below is simulated fully in-memory — no real network, no real timers — which
// keeps 100+ iterations cheap. We exercise three concrete failure modes for the
// mapped dependency:
//   (a) the check throws an arbitrary error,
//   (b) the check returns the unreachable / failure shape ({ reachable: false, ... }
//       or null/undefined), and
//   (c) the check resolves to a malformed value that is not a valid observation
//       (a primitive, an empty/garbage object, or one with wrong-typed signal fields).
//
// Crucially, none of the generated malformed values ever carries a valid "fixed"
// observation (e.g. reachable:true + a present header), so the only honest outcome
// for every family is `indeterminate`.
// ---------------------------------------------------------------------------

// Every recheckable Finding_Id family the router recognizes (design truth table).
// Includes exact ids plus representative `ssl-*` and `exposed-file-{path}` ids.
const recheckableIdArb = fc.constantFrom(
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
  "ssl-error",
  "ssl-expiring-soon",
  "exposed-file-/.env",
  "exposed-file-/.git/config",
  "exposed-file-/wp-config.php.bak"
);

// (a) An arbitrary thrown value — Errors of various kinds, an AbortError/TimeoutError
//     look-alike, a raw string, and null — to model "throws an arbitrary error" and a
//     timed-out request surfacing as a rejection (Requirements 3.13, 4.5).
const thrownArb = fc.oneof(
  fc.string().map((m) => new Error(m)),
  fc.string().map((m) => new TypeError(m)),
  fc.string().map((m) => Object.assign(new Error(m), { name: "TimeoutError" })),
  fc.string().map((m) => Object.assign(new Error(m), { name: "AbortError" })),
  fc.string(),
  fc.constant(null)
);

// (b) The unreachable / failure shape a real check emits when it can't reach the host,
//     plus null/undefined (Requirements 3.13, 4.1).
const failureShapeArb = fc.oneof(
  fc.constant(null),
  fc.constant(undefined),
  fc.constant({ reachable: false }),
  fc.constant({ reachable: false, status: null, exposed: false }),
  fc.constant({ reachable: false, error: "unreachable" })
);

// (c) A malformed value that is not a valid observation. Each candidate is deliberately
//     chosen so it can NEVER be read as resolved/unresolved by any family predicate:
//     primitives, empty/garbage objects, and objects whose signal fields are wrong-typed.
const malformedArb = fc.oneof(
  fc.constant({}),
  fc.constant([]),
  fc.string(),
  fc.integer(),
  fc.boolean(),
  fc.constant({ unexpected: "field" }),
  fc.constant({ spf: "maybe", dmarc: "maybe", caa: { status: "weird" } }),
  fc.constant({ expiresInDays: "soon", error: null }),
  fc.constant({ reachable: "yes" })
);

// A single failure (mode + value) applied uniformly to every injected dependency, so
// whichever check the routed family invokes, that mapped dependency fails.
const failureArb = fc.oneof(
  fc.record({ mode: fc.constant("throw"), value: thrownArb }),
  fc.record({ mode: fc.constant("shape"), value: failureShapeArb }),
  fc.record({ mode: fc.constant("malformed"), value: malformedArb })
);

// Build a `deps` object in which every check primitive exhibits the chosen failure mode.
function buildFailingDeps({ mode, value }) {
  if (mode === "throw") {
    const asyncThrower = async () => {
      throw value;
    };
    const syncThrower = () => {
      throw value;
    };
    return {
      checkDns: asyncThrower,
      checkSsl: asyncThrower,
      checkHeaders: asyncThrower,
      checkRobotsSitemap: asyncThrower,
      checkFileStatus: asyncThrower,
      analyzeCookies: syncThrower,
      analyzeMixedContent: syncThrower,
    };
  }
  // "shape" and "malformed": the dependency resolves to the failure/garbage value.
  const asyncReturn = async () => value;
  const syncReturn = () => value;
  return {
    checkDns: asyncReturn,
    checkSsl: asyncReturn,
    checkHeaders: asyncReturn,
    checkRobotsSitemap: asyncReturn,
    checkFileStatus: asyncReturn,
    analyzeCookies: syncReturn,
    analyzeMixedContent: syncReturn,
  };
}

describe("Recheck_Router — failure/unreachability/error honesty", () => {
  it("Feature: finding-recheck, Property 4: Any check failure, unreachability, or error yields indeterminate", async () => {
    await fc.assert(
      fc.asyncProperty(
        recheckableIdArb,
        fc.domain(),
        failureArb,
        async (findingId, domain, failure) => {
          const deps = buildFailingDeps(failure);

          const result = await recheckFinding({ domain, findingId }, deps);

          // The honest outcome for any failure is exactly `indeterminate`...
          expect(result.status).toBe(STATUS.INDETERMINATE);
          // ...and never an optimistic resolved/unresolved (Requirements 3.13, 4.1, 9.4).
          expect(result.status).not.toBe(STATUS.RESOLVED);
          expect(result.status).not.toBe(STATUS.UNRESOLVED);
          // The result still satisfies the basic contract: echoes the id, has a message.
          expect(result.findingId).toBe(findingId);
          expect(typeof result.message).toBe("string");
          expect(result.message.length).toBeGreaterThan(0);
        }
      ),
      { numRuns: 200 }
    );
  });
});
