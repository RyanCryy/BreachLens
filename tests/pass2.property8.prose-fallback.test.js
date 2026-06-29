// tests/pass2.property8.prose-fallback.test.js
//
// Feature: analyst-synthesis, Property 8: Missing or invalid model prose falls back deterministically
//
// Validates: Requirements 6.2, 6.4
//
// Property 8 statement (design.md):
//   For any non-empty findings and any successful LLM response in which
//   `summary` is absent/empty/non-string and/or `topPriority` is
//   absent/empty/non-string, the report's Summary defaults to the templated
//   summary (naming the domain, the total finding count, and the per-severity
//   counts) and/or the Top_Priority defaults to the `recommendation` of the
//   highest-severity (first sorted) finding, respectively.
//
// HOW THIS IS TESTED
// ------------------
// We drive the FROZEN production `runPass2` (netlify/functions/lib/analysis.js)
// through the single test seam — a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (every other real export preserved), exactly as the rest
// of the Pass 2 suite does. No production file is edited.
//
// For each iteration we generate a non-empty Classified_Finding list and a
// `fallbackTriggeringLlmResponseArb` response — a SUCCESSFUL (resolved) response
// in which at least one of `summary` / `topPriority` is absent / empty / a
// non-string. We program the double to resolve that response, run `runPass2`,
// and assert the partial-fallback behavior.
//
// PRODUCTION SEMANTICS (read from analysis.js — verified, authoritative)
// ----------------------------------------------------------------------
// The success path fills prose only when the model's field is a NON-EMPTY
// STRING (after trimming):
//
//     summary:     (typeof json.summary === "string" && json.summary.trim().length > 0)
//                    ? json.summary : synthFallbackSummary(domain, sorted)
//     topPriority: (typeof json.topPriority === "string" && json.topPriority.trim().length > 0)
//                    ? json.topPriority : sorted[0].recommendation
//
// so the deterministic fallback fires whenever the model's field is absent,
// null, a non-string (number / array / object / boolean), or a string that is
// empty or whitespace-only. ONLY a string with at least one non-whitespace
// character is used verbatim. This matches Requirements 6.2 / 6.4 exactly: a
// value that is "not a string of length one or more characters" triggers the
// deterministic fallback.
//
// On a successful-but-incomplete response the partially-filled report keeps
// `_source === "llm"` (only the missing/invalid field is back-filled).
//
// EXACT EXPECTED FALLBACK STRINGS
// -------------------------------
// `synthFallbackSummary` is NOT exported, but the exported `buildFallbackReport`
// builds its `.summary` via `synthFallbackSummary(domain, sortedFindings)` and
// its `.topPriority` as `sortedFindings[0].recommendation` for a non-empty list.
// We therefore derive the EXACT expected fallback prose from
// `buildFallbackReport(domain, expectedSorted(findings))` — exact equality, no
// reimplementation of the template — and additionally assert the structural
// requirements called out by Property 8 (the summary names the domain and the
// total finding count).

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  nonEmptyClassifiedListArb,
  domainArb,
  fallbackTriggeringLlmResponseArb,
  expectedSorted,
  buildFallbackReport,
} from "./helpers/pass2-fixtures.js";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// Tech context never affects the non-empty fallback summary
// (`synthFallbackSummary` ignores it); keep it minimal but exercise both shapes.
const techArb = fc.oneof(
  fc.constant(undefined),
  fc.constant({ detected: [] }),
  fc.record({ detected: fc.array(fc.constantFrom("nginx", "react", "php"), { maxLength: 3 }) })
);

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 — Property 8: missing/invalid model prose falls back deterministically", () => {
  it("back-fills only the absent/empty field from the deterministic template; keeps _source 'llm'", async () => {
    await fc.assert(
      fc.asyncProperty(
        nonEmptyClassifiedListArb({ minLength: 1, maxLength: 8 }),
        domainArb,
        techArb,
        fallbackTriggeringLlmResponseArb,
        async (findings, domain, tech, response) => {
          // The deterministic ground truth: the same sorted order production
          // uses, and the exact fallback prose production would build from it.
          const sorted = expectedSorted(findings);
          const det = buildFallbackReport(domain, sorted);
          const fallbackSummary = det.summary; // === synthFallbackSummary(domain, sorted)
          const fallbackTopPriority = det.topPriority; // === sorted[0].recommendation

          // Program the double to RESOLVE this (successful) incomplete response.
          llm.reset();
          llm.program(behaviors.resolveJson(response));

          const report = await runPass2(findings, domain, tech);

          // A successful-but-incomplete response is still tagged "llm" — only the
          // missing/invalid prose field is back-filled.
          expect(report._source).toBe("llm");

          // A value is used verbatim ONLY when it is a non-empty (post-trim) string;
          // otherwise the deterministic fallback fires (Requirements 6.2 / 6.4).
          const summaryIsValid =
            typeof response.summary === "string" && response.summary.trim().length > 0;
          const topPriorityIsValid =
            typeof response.topPriority === "string" && response.topPriority.trim().length > 0;

          // --- summary ---
          if (!summaryIsValid) {
            // Absent / null / non-string / empty / whitespace → templated summary.
            expect(report.summary).toBe(fallbackSummary);
            // Property 8 structural guarantees: names the domain and the total count.
            expect(report.summary).toContain(domain);
            expect(report.summary).toContain(String(findings.length));
          } else {
            // Non-empty string → model value used verbatim.
            expect(report.summary).toBe(response.summary);
          }

          // --- topPriority ---
          if (!topPriorityIsValid) {
            // Absent / null / non-string / empty / whitespace → highest-severity
            // finding's recommendation.
            expect(report.topPriority).toBe(fallbackTopPriority);
            expect(report.topPriority).toBe(sorted[0].recommendation);
          } else {
            expect(report.topPriority).toBe(response.topPriority);
          }

          // The double is invoked exactly once (single synthesis call).
          expect(llm.callCount).toBe(1);
        }
      ),
      { numRuns: 200 }
    );
  });
});
