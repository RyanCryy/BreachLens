// tests/pass2.property4.authoritative.test.js
//
// Feature: analyst-synthesis, Property 4: Score and level are authoritative — independent of finding order and of LLM output
//
// Validates: Requirements 2.3, 2.5, 3.5, 3.7, 5.1, 5.2, 5.3, 5.4, 7.5
//
// Property 4 statement (design.md):
//   For any array of Classified_Findings, the report's Overall_Risk_Score and
//   Risk_Level are identical across (a) any permutation of the findings, and
//   (b) every LLM outcome — a successful response that omits score/level, one
//   that returns values equal to the deterministic ones, one that returns
//   conflicting values, and a failed call that triggers fallback — and in every
//   case equal the deterministically computed score and the level derived from it.
//
// HOW THIS IS TESTED
// ------------------
// We drive the FROZEN production `runPass2` through the single test seam — a
// `vi.mock` of `netlify/functions/lib/llm.js`'s `callLLMJson` export (every other
// real export preserved), exactly as the harness smoke test and the Pass 1 suite
// establish. No production file is edited.
//
// For each generated scenario we:
//   1. Generate a NON-EMPTY Classified_Finding list (the deterministic score is
//      a property of this multiset; the zero-findings fixed-5/Low shape is a
//      separate property — Property 11 — and is intentionally excluded here).
//   2. Generate an arbitrary PERMUTATION of those findings (order independence).
//   3. Generate one of four LLM OUTCOMES:
//        - "omit":     success response carrying neither score nor riskLevel
//        - "equal":    success response echoing the deterministic score/level
//        - "conflict": success response with bogus, conflicting score/level
//        - "fail":     a thrown rejection (generic / timeout / parse) → fallback
//   4. Program the double accordingly and invoke `runPass2(permuted, domain, tech)`.
//   5. Assert `report.overallRiskScore === expectedScore(findings)` and
//      `report.riskLevel === expectedLevel(expectedScore(findings))` in EVERY case.
//
// Because `expectedScore` is order-independent (a sum over a multiset), the
// expected values are computed from the original (pre-permutation) list and must
// match the report produced from the permuted list for all four LLM outcomes.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  nonEmptyClassifiedListArb,
  domainArb,
  expectedScore,
  expectedLevel,
} from "./helpers/pass2-fixtures.js";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export
// (extractJson, callLLM, LLMError, ...) intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// A tech-context arbitrary (sometimes absent / empty) — never affects scoring.
const techArb = fc.oneof(
  fc.constant(undefined),
  fc.constant({ detected: [] }),
  fc.record({ detected: fc.array(fc.constantFrom("nginx", "react", "php", "cloudflare"), { maxLength: 3 }) })
);

// The four LLM outcomes Property 4 must sweep.
const llmOutcomeArb = fc.oneof(
  fc.record({ mode: fc.constant("omit") }),
  fc.record({ mode: fc.constant("equal") }),
  fc.record({
    mode: fc.constant("conflict"),
    bogusScore: fc.integer({ min: -999, max: 999 }),
    bogusLevel: fc.constantFrom("Critical", "High", "Medium", "Low", "totally-bogus"),
  }),
  fc.record({ mode: fc.constant("fail"), failKind: fc.constantFrom("generic", "timeout", "parse") })
);

// A scenario: a non-empty finding list, a permutation of it, a domain, a tech
// context, and an LLM outcome to program onto the double.
const scenarioArb = nonEmptyClassifiedListArb({ minLength: 1, maxLength: 8 }).chain((findings) =>
  fc.record({
    findings: fc.constant(findings),
    // A full permutation of the findings (same multiset, arbitrary order).
    permuted: fc.shuffledSubarray(findings, {
      minLength: findings.length,
      maxLength: findings.length,
    }),
    domain: domainArb,
    tech: techArb,
    outcome: llmOutcomeArb,
  })
);

// Translate an outcome descriptor + the deterministic values into a programmed
// behavior for the double.
function behaviorFor(outcome, detScore, detLevel) {
  switch (outcome.mode) {
    case "omit":
      // Success: valid prose only, no score/level fields at all.
      return behaviors.resolveJson({
        summary: "Executive summary prose.",
        topPriority: "Fix the most important thing first.",
      });
    case "equal":
      // Success: model echoes the deterministic values (must still be ignored,
      // i.e. the report's values come from the engine, which happen to match).
      return behaviors.resolveJson({
        summary: "Executive summary prose.",
        topPriority: "Fix the most important thing first.",
        score: detScore,
        overallRiskScore: detScore,
        riskLevel: detLevel,
      });
    case "conflict":
      // Success: model returns conflicting score/level — production must ignore.
      return behaviors.resolveJson({
        summary: "Executive summary prose.",
        topPriority: "Fix the most important thing first.",
        score: outcome.bogusScore,
        overallRiskScore: outcome.bogusScore,
        riskLevel: outcome.bogusLevel,
      });
    case "fail":
      // Failure → deterministic fallback report.
      if (outcome.failKind === "timeout") return behaviors.timeout();
      if (outcome.failKind === "parse") return behaviors.throwParse();
      return behaviors.throwGeneric();
    default:
      return behaviors.resolveJson({ summary: "s", topPriority: "p" });
  }
}

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 — Property 4: score & level authoritative, independent of order and LLM output", () => {
  it("report score/level equal the deterministic values for every permutation and every LLM outcome", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ findings, permuted, domain, tech, outcome }) => {
        // Deterministic expectations — computed from the ORIGINAL list. Because
        // the score is a sum over the severity multiset, it is invariant under
        // the permutation fed to runPass2.
        const detScore = expectedScore(findings);
        const detLevel = expectedLevel(detScore);

        // Program the double for this scenario's LLM outcome, then run synthesis
        // over the PERMUTED findings.
        llm.reset();
        llm.program(behaviorFor(outcome, detScore, detLevel));

        const report = await runPass2(permuted, domain, tech);

        // (a) Order independence + (b) independence from LLM output: the report's
        // authoritative score/level always equal the deterministic values,
        // whether the model omitted them, echoed them, conflicted with them, or
        // the call failed and fell back.
        expect(report.overallRiskScore).toBe(detScore);
        expect(report.riskLevel).toBe(detLevel);

        // Sanity: the deterministic score is always a bounded integer in [0,100].
        expect(Number.isInteger(report.overallRiskScore)).toBe(true);
        expect(report.overallRiskScore).toBeGreaterThanOrEqual(0);
        expect(report.overallRiskScore).toBeLessThanOrEqual(100);
      }),
      { numRuns: 200 }
    );
  });
});
