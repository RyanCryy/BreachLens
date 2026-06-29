import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { computeFallbackScore } from "./analysis.js";
import { severityArbitrary } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 3: risk score is the clamped,
// case-normalized weighted sum
//
// For any multiset of finding severities (including mixed-case values such as
// "Critical"/"HIGH" and unrecognized/junk/info values), `computeFallbackScore`
// equals `min(100, Σ weight(lower(severity)))` where
// `weight = {critical:40, high:22, medium:10, low:3}` after lowercasing, and
// `info`/unrecognized contribute 0.
//
// **Validates: Requirements 1.3, 1.6**
//
// `computeFallbackScore(findings)` is a pure function that reads only each
// finding's `severity` field, so every iteration runs fully in-memory with no
// network access. We drive it with a multiset of `severityArbitrary` values
// (mixed-case recognized values, the `info` sentinel, and junk/unrecognized
// strings), wrap each in a finding object, and independently re-derive the
// expected clamped weighted sum to compare against.
// ---------------------------------------------------------------------------

// The fixed per-severity weights, keyed by the lowercased severity. Any value
// not present here (info, junk, whitespace, arbitrary strings) contributes 0.
const WEIGHTS = { critical: 40, high: 22, medium: 10, low: 3 };

// Independent reference implementation of the expected score: lowercase each
// severity, sum its weight (0 for unrecognized / non-string), then clamp at 100.
function expectedScore(severities) {
  let score = 0;
  for (const sev of severities) {
    const key = typeof sev === "string" ? sev.toLowerCase() : sev;
    score += WEIGHTS[key] || 0;
  }
  return Math.min(100, score);
}

// A multiset of severities, including the empty multiset.
const severityMultisetArb = fc.array(severityArbitrary, { maxLength: 30 });

describe("Feature: deterministic-fallback, Property 3: risk score is the clamped, case-normalized weighted sum", () => {
  it("computeFallbackScore equals min(100, Σ weight(lower(severity))) with info/unrecognized contributing 0", () => {
    fc.assert(
      fc.property(severityMultisetArb, (severities) => {
        // Build findings carrying those (mixed-case + junk + info) severities.
        const findings = severities.map((severity, i) => ({
          id: `f-${i}`,
          severity,
        }));

        const score = computeFallbackScore(findings);

        // Matches the independently-derived clamped, case-normalized weighted sum.
        expect(score).toBe(expectedScore(severities));

        // Always an integer within the inclusive 0..100 range.
        expect(Number.isInteger(score)).toBe(true);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }),
      { numRuns: 200 }
    );
  });

  it("is case-insensitive: a severity's weight is identical regardless of letter case", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("critical", "high", "medium", "low"),
        (canonical) => {
          const variants = [
            canonical,
            canonical.toUpperCase(),
            canonical[0].toUpperCase() + canonical.slice(1),
          ];
          const scores = variants.map((sev) =>
            computeFallbackScore([{ id: "x", severity: sev }])
          );
          // All casings of the same severity yield the same single-finding weight.
          expect(scores[1]).toBe(scores[0]);
          expect(scores[2]).toBe(scores[0]);
          expect(scores[0]).toBe(WEIGHTS[canonical]);
        }
      ),
      { numRuns: 200 }
    );
  });

  it("info and unrecognized severities contribute weight 0", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom("info", "Info", "INFO", "severe", "trivial", "unknown", "", "  "), {
          maxLength: 20,
        }),
        (zeroWeightSeverities) => {
          const findings = zeroWeightSeverities.map((severity, i) => ({ id: `z-${i}`, severity }));
          expect(computeFallbackScore(findings)).toBe(0);
        }
      ),
      { numRuns: 200 }
    );
  });
});
