import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { scoreToLevel } from "./analysis.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 4: risk level partitions the score range
//
// For any integer score in 0..100, `scoreToLevel` returns exactly one level
// matching the thresholds Critical (>= 70), High (45-69), Medium (20-44),
// Low (0-19); the thresholds are mutually exclusive and exhaustive across the
// full range.
//
// **Validates: Requirements 1.4**
//
// `scoreToLevel` is a pure function, so every iteration runs in-memory with no
// network access. We drive the full input space with `fc.integer({min:0,max:100})`
// and assert the returned level is (a) one of the four allowed strings,
// (b) the unique level whose threshold the score satisfies, and (c) consistent
// with an independent partition derived directly from the documented thresholds.
// ---------------------------------------------------------------------------

const LEVELS = ["Critical", "High", "Medium", "Low"];

// Independent reference partition of 0..100 derived from the documented
// thresholds. This is intentionally written differently from the production
// chained-if so that agreement is meaningful, not tautological.
function expectedLevel(score) {
  const matches = [];
  if (score >= 70 && score <= 100) matches.push("Critical");
  if (score >= 45 && score <= 69) matches.push("High");
  if (score >= 20 && score <= 44) matches.push("Medium");
  if (score >= 0 && score <= 19) matches.push("Low");
  return matches;
}

describe("Feature: deterministic-fallback, Property 4: risk level partitions the score range", () => {
  it("maps every score in 0..100 to exactly one of the four levels", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 100 }), (score) => {
        const level = scoreToLevel(score);

        // (a) The result is always one of the four allowed level strings.
        expect(LEVELS).toContain(level);

        // (b) Exhaustiveness + mutual exclusivity: exactly one threshold band
        // claims this score, and it is the band the function returned.
        const matches = expectedLevel(score);
        expect(matches).toHaveLength(1);
        expect(level).toBe(matches[0]);
      }),
      { numRuns: 100 }
    );
  });
});
