import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  computeFallbackScore,
  scoreToLevel,
  buildFallbackReport,
} from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import { findingArbitrary } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 5: score and level are
// order-independent and deterministic
//
// For any list of findings and any permutation of it (matched on
// (id, type, severity)), `computeFallbackScore` produces a byte-identical
// integer and `scoreToLevel` produces an identical level string. The same
// invariant is verifiable end-to-end through `buildFallbackReport`, whose
// `overallRiskScore` / `riskLevel` are derived from those two functions.
//
// **Validates: Requirements 1.5**
//
// These functions are pure and LLM-free, so every iteration runs entirely
// in-memory with no network access. We drive them with severity-bearing
// classifications produced by running the shared `findingArbitrary` through the
// deterministic rule (`fallbackClassify`) — exactly the shape Pass 2 /
// `buildFallbackReport` consume — then compare each list against a permuted
// copy of itself.
// ---------------------------------------------------------------------------

// A severity-bearing classification, derived deterministically from a generated
// finding (carries id, type, severity, and prose) — the same shape the scoring
// engine receives downstream.
const classificationArb = findingArbitrary.map((finding) => ({
  ...fallbackClassify(finding),
  type: finding.type,
}));

// A list of classifications, including the empty list (score 0 / Low).
const classificationListArb = fc.array(classificationArb, { maxLength: 25 });

// Given a concrete list, produce an arbitrary that yields a PERMUTED copy of it.
// We attach an independent random sort key to each element and stable-sort by
// it: any ordering of the original elements is reachable, and the multiset of
// elements is preserved exactly (a genuine permutation).
function permutationOf(list) {
  if (list.length === 0) return fc.constant([]);
  return fc
    .array(fc.double({ noNaN: true, noDefaultInfinity: true }), {
      minLength: list.length,
      maxLength: list.length,
    })
    .map((keys) =>
      list
        .map((item, i) => ({ item, key: keys[i], i }))
        .sort((a, b) => a.key - b.key || a.i - b.i)
        .map((x) => x.item)
    );
}

// Pair each generated list with a permutation of itself.
const listAndPermutationArb = classificationListArb.chain((list) =>
  fc.tuple(fc.constant(list), permutationOf(list))
);

// Confirm `permuted` really is a permutation of `original` matched on
// (id, type, severity) — guards the generator itself so a degenerate "shuffle"
// can never make the property pass vacuously.
function assertIsPermutation(original, permuted) {
  expect(permuted).toHaveLength(original.length);
  const key = (f) => `${f.id}\u0000${f.type}\u0000${f.severity}`;
  const tally = (arr) => {
    const m = new Map();
    for (const f of arr) m.set(key(f), (m.get(key(f)) || 0) + 1);
    return m;
  };
  const a = tally(original);
  const b = tally(permuted);
  expect(b.size).toBe(a.size);
  for (const [k, count] of a) expect(b.get(k)).toBe(count);
}

describe("Feature: deterministic-fallback, Property 5: score and level are order-independent and deterministic", () => {
  it("computeFallbackScore and scoreToLevel are identical across any permutation", () => {
    fc.assert(
      fc.property(listAndPermutationArb, ([original, permuted]) => {
        assertIsPermutation(original, permuted);

        const scoreA = computeFallbackScore(original);
        const scoreB = computeFallbackScore(permuted);

        // Byte-identical integer score regardless of ordering.
        expect(Number.isInteger(scoreA)).toBe(true);
        expect(scoreB).toBe(scoreA);

        // Identical level string regardless of ordering.
        expect(scoreToLevel(scoreB)).toBe(scoreToLevel(scoreA));
      }),
      { numRuns: 200 }
    );
  });

  it("buildFallbackReport derives an identical score and level end-to-end across any permutation", () => {
    fc.assert(
      fc.property(
        fc.domain(),
        listAndPermutationArb,
        (domain, [original, permuted]) => {
          assertIsPermutation(original, permuted);

          const reportA = buildFallbackReport(domain, original);
          const reportB = buildFallbackReport(domain, permuted);

          // The security-bearing numbers are order-independent end-to-end.
          expect(reportB.overallRiskScore).toBe(reportA.overallRiskScore);
          expect(reportB.riskLevel).toBe(reportA.riskLevel);

          // And they agree with the direct scoring helpers.
          expect(reportA.overallRiskScore).toBe(computeFallbackScore(original));
          expect(reportA.riskLevel).toBe(scoreToLevel(reportA.overallRiskScore));
        }
      ),
      { numRuns: 200 }
    );
  });
});
