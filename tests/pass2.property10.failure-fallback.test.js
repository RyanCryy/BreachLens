// tests/pass2.property10.failure-fallback.test.js
//
// Task 7.1 — Property 10: Any LLM failure yields the deterministic Base_Report.
//
// Feature: analyst-synthesis, Property 10: Any LLM failure yields the deterministic Base_Report
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.6, 7.7
//
// This test verifies EXISTING production behavior in `runPass2`
// (netlify/functions/lib/analysis.js). No production code is modified.
//
// Property statement (design.md, Property 10):
//   For any non-empty findings, when the LLM client throws, aborts on timeout,
//   or fails to parse after its single internal retry, `runPass2` returns the
//   deterministic Base_Report: deterministic score and level, templated summary,
//   findings sorted by severity descending, Top_Priority equal to the first
//   sorted finding's `recommendation`, and Source_Tag "fallback".
//
// HOW THIS IS TESTED
// ------------------
// We drive the FROZEN production `runPass2` through the single test seam — a
// `vi.mock` of `netlify/functions/lib/llm.js`'s `callLLMJson` export (every other
// real export preserved), exactly as the Pass 2 suite and the harness smoke test
// establish. No production file is edited.
//
// Production (analysis.js) on any thrown rejection does:
//     } catch (e) { return buildFallbackReport(domain, sorted); }
// where `sorted = sortFindings(classified)`. So the ground-truth oracle for the
// whole report is the REAL exported `buildFallbackReport(domain, expectedSorted(findings))`
// — `expectedSorted` mirrors production's stable severity-desc sort exactly, so
// the findings array (including the non-production `_index` tags carried through)
// deep-equals what production hands to `buildFallbackReport`.
//
// We sweep all three failure kinds the design calls out — generic throw, timeout
// (AbortError), and parse-failure rejection — via the `behaviors` helper.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  nonEmptyClassifiedListArb,
  domainArb,
  expectedSorted,
  expectedScore,
  expectedLevel,
  buildFallbackReport,
  attachDouble,
  behaviors,
} from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export
// (extractJson, callLLM, LLMError, ...) intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// A tech-context arbitrary (sometimes absent / empty) — never affects the
// deterministic fallback report's score/level/findings/topPriority.
const techArb = fc.oneof(
  fc.constant(undefined),
  fc.constant({ detected: [] }),
  fc.record({
    detected: fc.array(fc.constantFrom("nginx", "react", "php", "cloudflare"), {
      maxLength: 3,
    }),
  })
);

// The three failure kinds Property 10 must sweep: a generic throw, a timeout
// (AbortError), and a parse-failure rejection (unparseable after the single
// internal retry). All three are surfaced to runPass2 as a thrown rejection.
const failKindArb = fc.constantFrom("generic", "timeout", "parse");

function behaviorFor(failKind) {
  if (failKind === "timeout") return behaviors.timeout();
  if (failKind === "parse") return behaviors.throwParse();
  return behaviors.throwGeneric();
}

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 — Property 10: any LLM failure yields the deterministic Base_Report", () => {
  it("returns buildFallbackReport(domain, sorted) for throw / timeout / parse-failure", async () => {
    await fc.assert(
      fc.asyncProperty(
        nonEmptyClassifiedListArb({ minLength: 1, maxLength: 12 }),
        domainArb,
        techArb,
        failKindArb,
        async (findings, domain, tech, failKind) => {
          // Program the double to fail this iteration's way, then synthesize.
          llm.reset();
          llm.program(behaviorFor(failKind));

          const report = await runPass2(findings, domain, tech);

          // Ground-truth deterministic Base_Report. expectedSorted mirrors
          // production's stable severity-desc sortFindings exactly, so this is
          // byte-for-byte what production passes to buildFallbackReport.
          const sorted = expectedSorted(findings);
          const expected = buildFallbackReport(domain, sorted);

          // The whole report equals the deterministic Base_Report.
          expect(report).toEqual(expected);

          // Spelled-out invariants (Requirements 7.1–7.4, 7.6, 7.7):
          // - deterministic score/level (independent of the failed LLM call)
          const detScore = expectedScore(findings);
          expect(report.overallRiskScore).toBe(detScore);
          expect(report.riskLevel).toBe(expectedLevel(detScore));
          // - templated summary naming the domain
          expect(typeof report.summary).toBe("string");
          expect(report.summary).toContain(domain);
          // - severity-sorted findings (deep-equal to the stable-sorted oracle)
          expect(report.findings).toEqual(sorted);
          // - topPriority = first sorted finding's recommendation
          expect(report.topPriority).toBe(sorted[0].recommendation);
          // - source tag "fallback"
          expect(report._source).toBe("fallback");

          // The call WAS attempted exactly once before falling back.
          expect(llm.callCount).toBe(1);
        }
      ),
      { numRuns: 200 }
    );
  });
});
