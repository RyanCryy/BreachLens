// tests/pass2.property9.sort-stable.test.js
//
// Task 5.3 — Property 9: Findings are ordered by severity descending and stably.
//
// Feature: analyst-synthesis, Property 9: Findings are ordered by severity descending and stably
// Validates: Requirements 6.6
//
// This test verifies EXISTING production behavior in `runPass2` / `sortFindings`
// (netlify/functions/lib/analysis.js). No production code is modified.
//
// Property statement (design.md, Property 9):
//   For any array of Classified_Findings, the report's findings are ordered by
//   the fixed rank critical > high > medium > low > any-other, and findings
//   sharing the same severity rank preserve their original relative order.
//
// The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export), exactly as the
// harness smoke test (tests/pass2.harness.smoke.test.js) establishes. We drive
// `runPass2` with the double resolving valid prose so the LLM-success path is
// taken, then verify the ordering of `report.findings`.
//
// `classifiedListArb` tags each element with its ORIGINAL `_index`. We verify
// stability two ways: (1) the report findings are non-increasing by SEVERITY_RANK
// and equal-rank adjacent findings have STRICTLY INCREASING `_index` (original
// relative order preserved), and (2) the report findings match the independent
// `expectedSorted(findings)` oracle order exactly.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  classifiedListArb,
  domainArb,
  expectedSorted,
  SEVERITY_RANK,
  attachDouble,
  behaviors,
} from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// Tech-context arbitrary — Pass 2 only reads tech.detected for a prompt line.
const techArb = fc.record({
  detected: fc.array(fc.string({ maxLength: 12 }), { maxLength: 4 }),
});

/** Rank of a severity exactly as production does (normalized via toLowerCase, else 0). */
function rankOf(finding) {
  const sev =
    finding && typeof finding.severity === "string"
      ? finding.severity.toLowerCase()
      : finding && finding.severity;
  return SEVERITY_RANK[sev] || 0;
}

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 — Property 9: findings ordered by severity descending and stably", () => {
  it("report.findings are non-increasing by rank and stable for equal-rank items", async () => {
    await fc.assert(
      fc.asyncProperty(
        // min length 1 so the LLM-resolving path is taken (length 0 short-circuits
        // to the fixed zero-findings shape with an empty findings list).
        classifiedListArb({ minLength: 1, maxLength: 12 }),
        domainArb,
        techArb,
        async (findings, domain, tech) => {
          // Resolve valid prose so the LLM-success path is taken; ordering of
          // findings must be the deterministic severity-desc stable order.
          llm.reset();
          llm.program(behaviors.resolveJson({ summary: "S", topPriority: "P" }));

          const report = await runPass2(findings, domain, tech);

          const out = report.findings;

          // No findings are added or dropped by sorting.
          expect(out.length).toBe(findings.length);

          // (1) Adjacent pairs are non-increasing by rank, and equal-rank
          //     adjacent findings preserve original relative order: their
          //     `_index` tags strictly increase.
          for (let i = 1; i < out.length; i++) {
            const prevRank = rankOf(out[i - 1]);
            const currRank = rankOf(out[i]);

            // Non-increasing by severity rank.
            expect(prevRank).toBeGreaterThanOrEqual(currRank);

            // Stable: equal-rank neighbours keep ascending original index.
            if (prevRank === currRank) {
              expect(out[i - 1]._index).toBeLessThan(out[i]._index);
            }
          }

          // (2) Cross-check against the independent oracle order. Compare by the
          //     original-index tag, which uniquely identifies each input element.
          const expected = expectedSorted(findings);
          expect(out.map((f) => f._index)).toEqual(expected.map((f) => f._index));
        }
      ),
      { numRuns: 200 }
    );
  });
});
