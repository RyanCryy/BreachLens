import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so that the
// `callLLMJson` dependency inside `runPass2` is the auto-mocked vi.fn — no
// network, fully in-memory across 100+ iterations, and forced to reject so the
// Pass 2 catch (Layer 2) path is taken.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import {
  runPass2,
  buildFallbackReport,
  computeFallbackScore,
  scoreToLevel,
} from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  errorShapeArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 11: Pass 2 failure yields a
// deterministic fallback report
//
// For any non-empty list of classified findings, when the Pass 2 LLM call
// throws or times out, `runPass2` returns `buildFallbackReport(domain, sorted)`
// tagged `_source: "fallback"`, carrying the deterministic score and level,
// severity-ordered findings (preserving any Pass 1 LLM-authored prose), a
// synthesized summary, and a topPriority.
//
// **Validates: Requirements 3.1, 3.7**
//
// `runPass2` takes the list of ALREADY-classified Pass 1 findings. To exercise
// prose preservation (3.7) we simulate successful Pass 1 LLM output: each
// classified finding is built by running `fallbackClassify` for its
// (deterministic) severity, then OVERWRITING the prose fields with distinctly
// tagged "LLM-authored" strings and `_source: "llm"`. Because the security-
// bearing severity always comes from the deterministic rule (never the LLM),
// this matches exactly what `classifyOne` produces on its success path.
//
// The Pass 2 LLM call is forced to reject across every documented failure shape
// (401-like, 429-like, abort/timeout-like, generic parse failure) via
// `errorShapeArbitrary`. Because layer selection is latency-driven and never
// error-typed, the fallback report must be identical regardless of which error
// shape is thrown.
// ---------------------------------------------------------------------------

// Local mirror of the module-private `sortFindings` / `SEVERITY_RANK` from
// analysis.js. Reproduced (not imported) so the expected report can be built
// from the same severity-ordered list `runPass2` feeds to `buildFallbackReport`.
// Array.prototype.sort is stable in V8, so this reproduces the production order
// byte-for-byte.
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function normalizeSeverity(severity) {
  return typeof severity === "string" ? severity.toLowerCase() : severity;
}
function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_RANK[normalizeSeverity(b.severity)] || 0) -
      (SEVERITY_RANK[normalizeSeverity(a.severity)] || 0)
  );
}

// A classified finding as produced by a SUCCESSFUL Pass 1 (`classifyOne`):
// deterministic severity, LLM-authored prose, `_source: "llm"`. The prose is
// prefixed so a re-derivation to deterministic text would be detectable.
const classifiedFindingArb = fc
  .record({
    finding: findingArbitrary,
    llmTitle: fc.string({ minLength: 1, maxLength: 40 }),
    llmExplanation: fc.string({ minLength: 1, maxLength: 80 }),
    llmRecommendation: fc.string({ minLength: 1, maxLength: 80 }),
  })
  .map(({ finding, llmTitle, llmExplanation, llmRecommendation }) => {
    const rule = fallbackClassify(finding);
    return {
      id: finding.id,
      type: finding.type,
      title: `LLM-TITLE::${llmTitle}`,
      severity: rule.severity, // ALWAYS deterministic — never LLM-supplied
      explanation: `LLM-EXPLANATION::${llmExplanation}`,
      recommendation: `LLM-RECOMMENDATION::${llmRecommendation}`,
      fixSnippet: rule.fixSnippet,
      _source: "llm",
    };
  });

const classifiedListArb = fc.array(classifiedFindingArb, {
  minLength: 1,
  maxLength: 12,
});

const domainArb = fc
  .domain()
  .map((d) => d)
  .filter((d) => typeof d === "string" && d.length > 0);

const techArb = fc.option(
  fc.record({
    server: fc.option(fc.string(), { nil: null }),
    poweredBy: fc.option(fc.string(), { nil: null }),
    detected: fc.array(fc.constantFrom("WordPress", "React", "nginx", "PHP"), {
      maxLength: 3,
    }),
  }),
  { nil: undefined }
);

describe("Feature: deterministic-fallback, Property 11: Pass 2 failure yields a deterministic fallback report", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("returns buildFallbackReport(domain, sorted) tagged _source: \"fallback\" with deterministic numbers, severity-ordered findings, preserved Pass 1 prose, a synthesized summary, and a topPriority", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        techArb,
        errorShapeArbitrary,
        async (classified, domain, tech, error) => {
          // Force the Pass 2 synthesis call to reject (post-retry exhaustion),
          // independent of the error type/shape.
          llm.reset();
          if (error.name === "AbortError") {
            llm.rejectAbort(error.message);
          } else {
            llm.rejectWith(error);
          }

          const report = await runPass2(classified, domain, tech);

          // The expected report is buildFallbackReport over the SAME severity-
          // ordered list runPass2 feeds its catch path.
          const sorted = sortFindings(classified);
          const expected = buildFallbackReport(domain, sorted);

          // Full-shape equality: tag, score, level, ordered findings, summary,
          // and topPriority all match the deterministic fallback report.
          expect(report).toEqual(expected);

          // --- Explicit subclaims (Requirement 3.1) ---

          // Tagged _source: "fallback".
          expect(report._source).toBe("fallback");

          // Deterministic score and level, derived only from severities.
          const score = computeFallbackScore(classified);
          expect(report.overallRiskScore).toBe(score);
          expect(report.riskLevel).toBe(scoreToLevel(score));

          // Findings are severity-ordered, highest rank first.
          const ranks = report.findings.map(
            (f) => SEVERITY_RANK[normalizeSeverity(f.severity)] || 0
          );
          for (let i = 1; i < ranks.length; i++) {
            expect(ranks[i]).toBeLessThanOrEqual(ranks[i - 1]);
          }
          expect(report.findings.length).toBe(classified.length);

          // A synthesized summary (non-empty, mentioning the domain) and a
          // topPriority are present.
          expect(typeof report.summary).toBe("string");
          expect(report.summary.length).toBeGreaterThan(0);
          expect(report.summary).toContain(domain);
          expect(report.topPriority).toBe(sorted[0].recommendation);

          // --- Pass 1 LLM prose is PRESERVED, not re-derived (Requirement 3.7) ---
          for (const f of report.findings) {
            expect(f._source).toBe("llm");
            expect(f.title.startsWith("LLM-TITLE::")).toBe(true);
            expect(f.explanation.startsWith("LLM-EXPLANATION::")).toBe(true);
            expect(f.recommendation.startsWith("LLM-RECOMMENDATION::")).toBe(true);
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
