// tests/pass2.property5.banding.test.js
//
// Feature: analyst-synthesis, Property 5: Risk level banding is correct and total
//
// Property 5 — Risk level banding is correct and total.
//
// For any integer score in 0..100, the risk level the production code derives
// (`scoreToLevel`, exercised here indirectly through `runPass2`'s authoritative
// `report.riskLevel`) is exactly one of `Critical`, `High`, `Medium`, `Low`,
// assigning `Critical` when score >= 70, `High` when 45 <= score < 70,
// `Medium` when 20 <= score < 45, and `Low` when score < 20.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6
//
// HOW THIS IS DRIVEN
// ------------------
// `scoreToLevel` is NOT exported from analysis.js, so banding is verified by
// driving the frozen production `runPass2` over generated Classified_Findings.
// The deterministic `overallRiskScore` is computed before any LLM call and the
// derived band surfaces verbatim as `report.riskLevel`. We therefore assert, for
// every generated finding set:
//
//   report.riskLevel === expectedLevel(report.overallRiskScore)   // banding correct
//   report.riskLevel ∈ { Critical, High, Medium, Low }            // banding total
//
// Because the generated severities span the scored weights (critical=40,
// high=22, medium=10, low=3) the resulting scores densely cover 0..100 across
// all four bands. The boundary scores (70, 45, 20, 69, 44, 19, 0, 100) are then
// pinned explicitly with hand-constructed finding sets.
//
// The LLM client is replaced by the controllable double (it resolves valid
// prose) so no network call occurs; banding is computed before the call and is
// independent of the response.
//
// This file authors NO production change — the only seam is the module-mock of
// ./llm.js's callLLMJson, matching tests/pass2.harness.smoke.test.js.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors, expectedLevel } from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

const VALID_BANDS = ["Critical", "High", "Medium", "Low"];
const domain = "example.com";
const tech = { detected: [] };

// Build a minimal, valid Classified_Finding carrying a given severity. The
// `recommendation` is always present so the topPriority fallback has a value
// (irrelevant to banding, but keeps the report well-formed).
let seq = 0;
function findingWith(severity) {
  const n = seq++;
  return {
    id: `finding-${n}`,
    type: "header",
    title: `Finding ${n}`,
    severity,
    explanation: "An explanation.",
    recommendation: "A recommendation.",
    fixSnippet: null,
    _source: "llm",
  };
}

function findingsFrom(severities) {
  return severities.map((s) => findingWith(s));
}

// A severity arbitrary weighted toward the four scored levels so generated
// scores densely span 0..100 (and therefore every band), while still hitting
// 0-weight severities (info / unknown).
const bandSeverityArb = fc.oneof(
  { weight: 6, arbitrary: fc.constantFrom("critical", "high", "medium", "low") },
  { weight: 1, arbitrary: fc.constantFrom("info", "none", "unknown") }
);

// Non-empty finding lists, long enough to push scores into the Critical band
// (>= 70 needs e.g. two criticals) yet bounded for speed.
const findingListArb = fc.array(bandSeverityArb, { minLength: 1, maxLength: 12 });

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson, {
    default: behaviors.resolveJson({ summary: "ok", topPriority: "ok" }),
  });
});

describe("Pass 2 — Property 5: risk level banding is correct and total", () => {
  it("derives the correct band for every generated score and the band is always one of the four", async () => {
    await fc.assert(
      fc.asyncProperty(findingListArb, async (severities) => {
        const report = await runPass2(findingsFrom(severities), domain, tech);

        // Banding is TOTAL: always exactly one of the four bands.
        expect(VALID_BANDS).toContain(report.riskLevel);

        // Banding is CORRECT: matches the oracle recomputed from the boundaries
        // 70 / 45 / 20 applied to the deterministic overallRiskScore.
        expect(report.riskLevel).toBe(expectedLevel(report.overallRiskScore));

        // Score stays in range, so the banding domain is fully covered.
        expect(report.overallRiskScore).toBeGreaterThanOrEqual(0);
        expect(report.overallRiskScore).toBeLessThanOrEqual(100);
      }),
      { numRuns: 200 }
    );
  });

  // Explicit boundary coverage. Each finding set is constructed from the scored
  // weights (critical=40, high=22, medium=10, low=3) to land EXACTLY on a target
  // score, pinning the behavior at and around every band threshold.
  //
  //  score | construction                              | expected band
  //  ------+-------------------------------------------+--------------
  //    0   | 1 x info (weight 0)                       | Low
  //   19   | 1 medium + 3 low  (10 + 9)                | Low
  //   20   | 2 medium          (10 + 10)               | Medium
  //   44   | 2 high            (22 + 22)               | Medium
  //   45   | 1 high + 2 medium + 1 low (22+10+10+3)    | High
  //   69   | 1 critical + 2 medium + 3 low (40+20+9)   | High
  //   70   | 1 critical + 3 medium (40 + 30)           | Critical
  //  100   | 3 critical (120 -> capped at 100)         | Critical
  const boundaryCases = [
    { name: "score 0 -> Low", severities: ["info"], score: 0, level: "Low" },
    { name: "score 19 -> Low", severities: ["medium", "low", "low", "low"], score: 19, level: "Low" },
    { name: "score 20 -> Medium", severities: ["medium", "medium"], score: 20, level: "Medium" },
    { name: "score 44 -> Medium", severities: ["high", "high"], score: 44, level: "Medium" },
    { name: "score 45 -> High", severities: ["high", "medium", "medium", "low"], score: 45, level: "High" },
    { name: "score 69 -> High", severities: ["critical", "medium", "medium", "low", "low", "low"], score: 69, level: "High" },
    { name: "score 70 -> Critical", severities: ["critical", "medium", "medium", "medium"], score: 70, level: "Critical" },
    { name: "score 100 -> Critical", severities: ["critical", "critical", "critical"], score: 100, level: "Critical" },
  ];

  for (const { name, severities, score, level } of boundaryCases) {
    it(`boundary: ${name}`, async () => {
      const report = await runPass2(findingsFrom(severities), domain, tech);
      expect(report.overallRiskScore).toBe(score);
      expect(report.riskLevel).toBe(level);
      expect(report.riskLevel).toBe(expectedLevel(score));
      expect(VALID_BANDS).toContain(report.riskLevel);
    });
  }
});
