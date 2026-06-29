import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so the `callLLMJson`
// dependency inside `runPass2` is the auto-mocked vi.fn — no network, fully
// in-memory across 100+ iterations, and forced to reject so the Pass 2 catch
// (Layer 2) path is taken.
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
// Feature: deterministic-fallback, Property 21: the two fallback reports agree
// on numbers and differ on prose
//
// For any list of findings carrying Pass 1 LLM-authored prose, the Pass 2
// Fallback_Report (layer 2 — which RETAINS that prose) and the top-level
// Deterministic_Report (layer 4 — which RE-DERIVES prose from the rule) share an
// identical per-finding severity, Overall_Risk_Score, and Risk_Level, are both
// tagged `_source: "fallback"`, and differ only in their prose fields where LLM
// prose existed.
//
// **Validates: Requirements 6.4, 6.5**
//
// This is the headline subtlety of the four-layer design: layers 2 and 4 BOTH
// tag their output `_source: "fallback"` yet produce genuinely different reports
// for the same findings. Layer 2 reuses Pass 1's already-classified findings
// (still carrying LLM-authored prose); layer 4 discards all LLM work and
// re-derives every classification from the deterministic rule. They agree on
// every number and disagree on prose.
//
// How each layer is reproduced here:
//   - ORIGINAL findings (pre-classification) are generated and KEPT so layer 4
//     can re-derive from scratch.
//   - Layer 2 (Pass 2 Fallback_Report): each original finding is turned into a
//     SUCCESSFUL Pass 1 classification — deterministic severity (never LLM),
//     `_source: "llm"`, and prose fields OVERWRITTEN with distinctly tagged
//     "LLM-authored" markers (`LLM-TITLE::`, `LLM-EXPLANATION::`,
//     `LLM-RECOMMENDATION::`). `runPass2` is then driven with the LLM REJECTING
//     (across every documented error shape), so its catch returns
//     `buildFallbackReport(domain, sorted)` with the Pass 1 prose preserved.
//   - Layer 4 (Deterministic_Report): re-derived exactly like `deterministicReport`
//     in `scan.js` — `originalFindings.map(f => ({...fallbackClassify(f), type,
//     _source: "fallback"}))`, sorted by `fallbackSeverityRank`, then
//     `buildFallbackReport(domain, sorted)`.
// ---------------------------------------------------------------------------

// Local mirror of the module-private `SEVERITY_RANK`/`sortFindings` from
// analysis.js (used by `runPass2`) — reproduced (not imported) so we can reason
// about ordering. Array.prototype.sort is stable in V8.
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function normalizeSeverity(severity) {
  return typeof severity === "string" ? severity.toLowerCase() : severity;
}

// Local mirror of `FALLBACK_SEVERITY_RANK`/`fallbackSeverityRank` from `scan.js`
// (used by `deterministicReport`). For the severities produced by
// `fallbackClassify` (critical/high/medium/low only — `info` is reserved for the
// non-present tech-stack item) this ranks identically to SEVERITY_RANK, so both
// layers sort the same underlying severity sequence into the same order.
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const fallbackSeverityRank = (severity) =>
  FALLBACK_SEVERITY_RANK[typeof severity === "string" ? severity.toLowerCase() : severity] || 0;

// Reproduce layer 4 (`deterministicReport` in scan.js), minus the
// provider/domain/techStack attach which is orthogonal to the numbers-vs-prose
// claim and would otherwise append an extra informational finding.
function deterministicReport(originalFindings, domain) {
  const sorted = originalFindings
    .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
    .sort((a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity));
  return buildFallbackReport(domain, sorted);
}

// A spec pairing an ORIGINAL finding with the LLM prose Pass 1 would have
// authored for it. The original is kept for layer-4 re-derivation; the prose
// markers feed layer 2.
const findingWithProseArb = fc.record({
  finding: findingArbitrary,
  llmTitle: fc.string({ minLength: 1, maxLength: 40 }),
  llmExplanation: fc.string({ minLength: 1, maxLength: 80 }),
  llmRecommendation: fc.string({ minLength: 1, maxLength: 80 }),
});

// Non-empty so `runPass2` does NOT short-circuit to the `_source: "none"` report.
const specListArb = fc.array(findingWithProseArb, { minLength: 1, maxLength: 12 });

const domainArb = fc.domain().filter((d) => typeof d === "string" && d.length > 0);

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

describe("Feature: deterministic-fallback, Property 21: the two fallback reports agree on numbers and differ on prose", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("layer 2 (Pass 2 fallback, prose retained) and layer 4 (deterministic re-derivation) agree on severity/score/level, are both _source: \"fallback\", and differ only in prose", async () => {
    await fc.assert(
      fc.asyncProperty(
        specListArb,
        domainArb,
        techArb,
        errorShapeArbitrary,
        async (specs, domain, tech, error) => {
          // Original, pre-classification findings — kept so layer 4 re-derives
          // from scratch (no in-flight Pass 1 output).
          const originalFindings = specs.map((s) => s.finding);

          // Layer 2 input: SUCCESSFUL Pass 1 classifications. Severity is ALWAYS
          // the deterministic rule value (never LLM); prose carries distinct
          // LLM-authored markers; _source is "llm".
          const classified = specs.map((s) => {
            const rule = fallbackClassify(s.finding);
            return {
              id: s.finding.id,
              type: s.finding.type,
              title: `LLM-TITLE::${s.llmTitle}`,
              severity: rule.severity, // deterministic — never LLM-supplied
              explanation: `LLM-EXPLANATION::${s.llmExplanation}`,
              recommendation: `LLM-RECOMMENDATION::${s.llmRecommendation}`,
              fixSnippet: rule.fixSnippet,
              _source: "llm",
            };
          });

          // Force the Pass 2 synthesis call to reject (post-retry exhaustion),
          // independent of error shape — layer selection is latency-driven, not
          // error-typed.
          llm.reset();
          if (error.name === "AbortError") {
            llm.rejectAbort(error.message);
          } else {
            llm.rejectWith(error);
          }

          // Layer 2: Pass 2 Fallback_Report (retains Pass 1 LLM prose).
          const fallbackReport = await runPass2(classified, domain, tech);
          // Layer 4: top-level Deterministic_Report (re-derives prose from rule).
          const detReport = deterministicReport(originalFindings, domain);

          // --- Both reports are tagged _source: "fallback" ---
          expect(fallbackReport._source).toBe("fallback");
          expect(detReport._source).toBe("fallback");

          // --- They agree on the security-bearing numbers ---
          const expectedScore = computeFallbackScore(classified);
          expect(fallbackReport.overallRiskScore).toBe(expectedScore);
          expect(detReport.overallRiskScore).toBe(expectedScore);
          expect(fallbackReport.overallRiskScore).toBe(detReport.overallRiskScore);

          const expectedLevel = scoreToLevel(expectedScore);
          expect(fallbackReport.riskLevel).toBe(expectedLevel);
          expect(detReport.riskLevel).toBe(expectedLevel);
          expect(fallbackReport.riskLevel).toBe(detReport.riskLevel);

          // Same number of findings (layer 4 here omits the informational
          // tech-stack item, so the two finding lists align one-to-one).
          expect(fallbackReport.findings.length).toBe(detReport.findings.length);
          expect(fallbackReport.findings.length).toBe(specs.length);

          // Both layers sort the SAME underlying severity sequence with a stable
          // sort, so the i-th finding in each report is the SAME original finding.
          // Reproduce that ordering on the specs so each report index maps back
          // to its originating spec (and thus its original finding + LLM prose).
          const sortedSpecs = [...specs].sort(
            (a, b) =>
              fallbackSeverityRank(fallbackClassify(b.finding).severity) -
              fallbackSeverityRank(fallbackClassify(a.finding).severity)
          );

          for (let i = 0; i < fallbackReport.findings.length; i++) {
            const l2 = fallbackReport.findings[i]; // layer 2: prose retained
            const l4 = detReport.findings[i]; // layer 4: prose re-derived
            const original = sortedSpecs[i].finding;

            // Alignment + non-prose agreement.
            expect(l2.id).toBe(l4.id);
            expect(l2.type).toBe(l4.type);

            // --- Agree on per-finding severity (deterministic, identical) ---
            expect(l2.severity).toBe(l4.severity);

            // --- Differ on prose where LLM prose existed ---
            // Layer 2 retains the LLM-authored markers...
            expect(l2.title.startsWith("LLM-TITLE::")).toBe(true);
            expect(l2.explanation.startsWith("LLM-EXPLANATION::")).toBe(true);
            expect(l2.recommendation.startsWith("LLM-RECOMMENDATION::")).toBe(true);
            expect(l2._source).toBe("llm");

            // ...layer 4 re-derives the deterministic rule prose (which is fixed
            // English text / the original label, never an LLM marker).
            expect(l4.explanation.startsWith("LLM-EXPLANATION::")).toBe(false);
            expect(l4.recommendation.startsWith("LLM-RECOMMENDATION::")).toBe(false);
            expect(l4._source).toBe("fallback");

            // The deterministic prose equals fallbackClassify applied to the
            // ORIGINAL finding (no in-flight Pass 1 output).
            const rule = fallbackClassify(original);
            expect(l4.title).toBe(rule.title);
            expect(l4.explanation).toBe(rule.explanation);
            expect(l4.recommendation).toBe(rule.recommendation);

            // The prose genuinely differs between the two layers (explanation and
            // recommendation are guaranteed distinct: layer 2 is marker-prefixed,
            // layer 4 is fixed rule text).
            expect(l2.explanation).not.toBe(l4.explanation);
            expect(l2.recommendation).not.toBe(l4.recommendation);

            // Non-prose fixSnippet is the same deterministic literal in both.
            expect(l2.fixSnippet).toBe(l4.fixSnippet);
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
