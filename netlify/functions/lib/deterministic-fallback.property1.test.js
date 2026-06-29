import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { fallbackClassify } from "./findings.js";
import { findingArbitrary } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 1: severity is always a valid deterministic value
//
// For any finding (including findings with unknown ids or types),
// `fallbackClassify` returns a `severity` drawn from the fixed set
// {critical, high, medium, low} — with `info` reserved for the informational
// tech-stack item, which is never routed through `fallbackClassify` — never a
// value supplied by the LLM.
//
// **Validates: Requirements 1.1**
//
// `fallbackClassify` is a pure, LLM-free function, so every iteration runs
// in-memory with no network access. `findingArbitrary` drives both the
// known-id branches (SEVERITY_MAP / EXPOSED_FILE_INFO / subdomain) and the
// unknown-id / unknown-type total-coverage `low` branch, so the assertion
// covers the entire input space the deterministic rule can see.
// ---------------------------------------------------------------------------

// The fixed deterministic severity domain for a (non-tech) finding. `info` is
// reserved for the informational tech-stack item, which is added separately and
// never passes through `fallbackClassify`, so it must not appear here.
const DETERMINISTIC_SEVERITIES = ["critical", "high", "medium", "low"];

describe("Feature: deterministic-fallback, Property 1: severity is always a valid deterministic value", () => {
  it("classifies every finding with a severity from {critical, high, medium, low}", () => {
    fc.assert(
      fc.property(findingArbitrary, (finding) => {
        const classification = fallbackClassify(finding);

        // The severity is always one of the four deterministic values...
        expect(DETERMINISTIC_SEVERITIES).toContain(classification.severity);

        // ...and it is unambiguous: exactly one of the domain values matches.
        const matches = DETERMINISTIC_SEVERITIES.filter(
          (s) => s === classification.severity
        );
        expect(matches).toHaveLength(1);
      }),
      { numRuns: 200 }
    );
  });
});
