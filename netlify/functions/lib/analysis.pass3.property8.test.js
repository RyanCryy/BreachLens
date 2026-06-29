import { describe, it, expect } from "vitest";
import fc from "fast-check";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 8: Integration omits narrative fields
// exactly when result is null
//
// For any Pass 3 result, the report-assembly step SHALL set both
// `attackScenario` and `ifUnaddressed` as own properties when the result is a
// non-null object, and SHALL leave both as absent own properties (never `null`,
// empty, or placeholder) when the result is `null`.
//
// **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 7.7**
//
// This models the assembly step in `netlify/functions/scan.js`:
//
//   if (narrative) {
//     rep.attackScenario = narrative.attackScenario;
//     rep.ifUnaddressed = narrative.ifUnaddressed;
//   }
//
// The block is part of the streaming handler closure (not an exported unit), so
// we replicate the exact conditional here and drive it with an arbitrary that is
// either `null` or a `{ attackScenario, ifUnaddressed }` object. Membership is
// asserted with Object.prototype.hasOwnProperty so we test for the presence of
// the *own* property, distinguishing "absent" from "present but null/empty".
// ---------------------------------------------------------------------------

// Faithful reproduction of the scan.js assembly conditional. `rep` is the report
// object being assembled; `narrative` is the Pass 3 result (object or null).
function assembleNarrative(rep, narrative) {
  if (narrative) {
    rep.attackScenario = narrative.attackScenario;
    rep.ifUnaddressed = narrative.ifUnaddressed;
  }
  return rep;
}

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// A non-null Pass 3 result: the two-field object whose values are arbitrary
// strings (the only shape runPass3 can return when it is non-null).
const narrativeObjectArb = fc.record({
  attackScenario: fc.string(),
  ifUnaddressed: fc.string(),
});

// The Pass 3 result is either the two-field object or null.
const pass3ResultArb = fc.oneof(narrativeObjectArb, fc.constant(null));

// A representative base report skeleton onto which the narrative is assembled.
// Pass 3 narrative fields must not pre-exist on it, mirroring the freshly built
// base/pass2 report in scan.js.
const baseRepArb = fc.record({
  domain: fc.domain(),
  riskLevel: fc.constantFrom("Low", "Medium", "High", "Critical"),
  overallRiskScore: fc.integer({ min: 0, max: 100 }),
});

describe("Feature: exploit-narrative, Property 8: Integration omits narrative fields exactly when result is null", () => {
  it("sets both fields as own properties iff the Pass 3 result is a non-null object", () => {
    fc.assert(
      fc.property(baseRepArb, pass3ResultArb, (rep, narrative) => {
        assembleNarrative(rep, narrative);

        if (narrative === null) {
          // Null result -> neither field becomes an own property, and neither is
          // set to null/empty/placeholder.
          expect(hasOwn(rep, "attackScenario")).toBe(false);
          expect(hasOwn(rep, "ifUnaddressed")).toBe(false);
        } else {
          // Non-null object -> both fields are own properties copied verbatim
          // from the result.
          expect(hasOwn(rep, "attackScenario")).toBe(true);
          expect(hasOwn(rep, "ifUnaddressed")).toBe(true);
          expect(rep.attackScenario).toBe(narrative.attackScenario);
          expect(rep.ifUnaddressed).toBe(narrative.ifUnaddressed);
        }
      }),
      { numRuns: 200 }
    );
  });

  it("never assigns null narrative fields when the result is null", () => {
    fc.assert(
      fc.property(baseRepArb, (rep) => {
        assembleNarrative(rep, null);

        // The fields are absent, not present-with-null. hasOwnProperty is the
        // discriminator: `rep.attackScenario === undefined` would also hold for
        // an explicit `undefined` assignment, which the contract forbids.
        expect(hasOwn(rep, "attackScenario")).toBe(false);
        expect(hasOwn(rep, "ifUnaddressed")).toBe(false);
      }),
      { numRuns: 100 }
    );
  });
});
