import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { fallbackClassify } from "./findings.js";
import { unknownFindingArbitrary } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 10: the deterministic rule is total
//
// For any finding whose `id` and `type` are absent from the severity tables,
// `fallbackClassify` returns `severity: "low"` together with non-empty generic
// explanation and recommendation text.
//
// **Validates: Requirements 2.6**
//
// `unknownFindingArbitrary` is restricted to genuine unknown ids/types: it
// excludes both the known `SEVERITY_MAP` ids and the `exposure`/`subdomain`
// dynamic-id branches, and (per the shared arbitraries) also excludes JS
// prototype property names (e.g. "constructor", "toString", "__proto__") that
// would resolve to inherited members of the plain-object `SEVERITY_MAP` rather
// than the total-coverage `low` branch. Real finding ids are kebab-case slugs
// and never such names, so this stays within the genuine input space.
// `fallbackClassify` is pure, so every iteration runs fully in-memory.
// ---------------------------------------------------------------------------

describe("Property 10: the deterministic rule is total", () => {
  it("classifies any unknown finding as low severity with non-empty generic prose", () => {
    fc.assert(
      fc.property(unknownFindingArbitrary, (finding) => {
        const result = fallbackClassify(finding);

        // The total-coverage branch always assigns "low".
        expect(result.severity).toBe("low");

        // Generic prose is always present and non-empty.
        expect(typeof result.explanation).toBe("string");
        expect(result.explanation.trim().length).toBeGreaterThan(0);

        expect(typeof result.recommendation).toBe("string");
        expect(result.recommendation.trim().length).toBeGreaterThan(0);
      }),
      { numRuns: 100 }
    );
  });
});
