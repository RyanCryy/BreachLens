// tests/pass2.property11.zero-findings.test.js
//
// Task 7.2 — Property test: zero-findings report has the fixed clean shape.
//
// Feature: analyst-synthesis, Property 11: Zero-findings report has the fixed clean shape
// Validates: Requirements 8.2, 8.3, 8.4, 8.5, 8.6, 8.7
//
// For ANY domain (and any tech context), invoking `runPass2` with an EMPTY
// finding set must return the fixed, deterministic "clean" report shape from
// production (netlify/functions/lib/analysis.js):
//
//   overallRiskScore === 5            (8.2)
//   riskLevel         === "Low"       (8.3)
//   findings          === []          (8.4 — empty array)
//   summary           names the domain verbatim and conveys no notable exposures (8.5)
//   topPriority       === the fixed maintenance string (8.6)
//   _source           === "none"      (8.7)
//
// The model is NEVER consulted on the clean path, so the LLM double must be
// invoked zero times. The single test seam is a `vi.mock` of
// `netlify/functions/lib/llm.js`'s `callLLMJson` export (keeping every other
// real export). No production file is edited.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors, domainArb } from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// The exact, fixed maintenance topPriority production emits for a clean scan.
const FIXED_TOP_PRIORITY =
  "Maintain current good practices and re-scan periodically as infrastructure changes.";

// A tech-context arbitrary: present-with-list, empty list, and absent. The clean
// shape (score/level/findings/topPriority/_source) is invariant across all of
// these — tech only ever appends a context clause to the summary prose.
const techArb = fc.oneof(
  fc.constant(undefined),
  fc.record({
    detected: fc.array(fc.constantFrom("nginx", "react", "wordpress", "cloudflare"), {
      maxLength: 4,
    }),
  })
);

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  // Program a healthy resolve as the default so that, IF production were to
  // (incorrectly) call the LLM on the clean path, the call would succeed —
  // making any non-zero callCount a genuine signal rather than a masked failure.
  llm = attachDouble(mockCallLLMJson, {
    default: behaviors.resolveJson({ summary: "should-not-be-used", topPriority: "x" }),
  });
});

describe("Pass 2 — Property 11: zero-findings report has the fixed clean shape", () => {
  // Feature: analyst-synthesis, Property 11: Zero-findings report has the fixed clean shape
  it("returns the fixed clean report for runPass2([], domain, tech) and never calls the LLM", async () => {
    await fc.assert(
      fc.asyncProperty(domainArb, techArb, async (domain, tech) => {
        // Reset the spy per iteration so callCount reflects only this run.
        llm.reset();

        const report = await runPass2([], domain, tech);

        // 8.2 — fixed clean baseline score.
        expect(report.overallRiskScore).toBe(5);

        // 8.3 — fixed clean risk level.
        expect(report.riskLevel).toBe("Low");

        // 8.4 — findings is an empty array.
        expect(Array.isArray(report.findings)).toBe(true);
        expect(report.findings).toEqual([]);
        expect(report.findings.length).toBe(0);

        // 8.5 — summary names the domain verbatim and conveys no notable exposures.
        expect(typeof report.summary).toBe("string");
        expect(report.summary).toContain(domain);
        expect(report.summary).toContain("No notable public security exposures");

        // 8.6 — fixed maintenance topPriority.
        expect(report.topPriority).toBe(FIXED_TOP_PRIORITY);

        // 8.7 — source tag marks this as the no-findings (clean) path.
        expect(report._source).toBe("none");

        // The model is never consulted on the clean path.
        expect(llm.callCount).toBe(0);
      }),
      { numRuns: 200 }
    );
  });
});
