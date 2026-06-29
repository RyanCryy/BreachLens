import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` must be hoisted above the `./analysis.js` import so that runPass2's
// `callLLMJson` dependency is the auto-mocked vi.fn (no network, fully
// in-memory across 100+ iterations).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass2, computeFallbackScore, scoreToLevel } from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 12: Pass 2 success keeps LLM prose
// with deterministic numbers, substituting empties
//
// For any non-empty list of classified findings, when the Pass 2 LLM call
// succeeds, `runPass2` returns a `_source: "llm"` report whose score, level, and
// finding order are the deterministic values, whose `summary`/`topPriority` are
// the LLM's when non-empty, and whose `summary` falls back to the synthesized
// summary and `topPriority` falls back to the highest-severity finding's
// recommendation when the LLM value is empty or whitespace.
//
// **Validates: Requirements 3.2, 3.3, 3.4**
//
// This test mirrors the EXACT substitution semantics of the runPass2 success
// path in analysis.js:
//
//   summary     : (typeof json.summary === "string" && json.summary.trim().length > 0)
//                   ? json.summary : synthFallbackSummary(domain, sorted)
//   topPriority : (typeof json.topPriority === "string" && json.topPriority.trim().length > 0)
//                   ? json.topPriority : sorted[0].recommendation
//
// Note this is STRICTER than Pass 1's plain truthiness: Pass 2 requires a string
// AND a non-whitespace trimmed value. A whitespace-only string therefore falls
// back (unlike Pass 1's title/explanation/recommendation, which retain truthy
// whitespace verbatim). score/riskLevel/order are always deterministic.
// ---------------------------------------------------------------------------

// Local mirror of the private SEVERITY_RANK / normalizeSeverity / sortFindings
// in analysis.js. Reproduced (not imported) because they are module-private;
// they must match the production sort byte-for-byte so the expected finding
// order is computed identically.
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

// Local mirror of the private synthFallbackSummary in analysis.js — the single
// source of truth for the deterministic summary substitution.
function synthFallbackSummary(domain, findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const sev = normalizeSeverity(f.severity);
    counts[sev] = (counts[sev] || 0) + 1;
  }
  const parts = [];
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }
  return `We reviewed the public security footprint of ${domain} and found ${findings.length} item${
    findings.length === 1 ? "" : "s"
  } worth attention (${parts.join(", ")}). These are based entirely on publicly visible signals — addressing the highest-severity items first will meaningfully reduce your exposure.`;
}

// Mirror of the runPass2 success-path predicate for LLM prose substitution.
function usableLLMString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

// Build a Pass-1-style classified finding from a raw finding by applying the
// deterministic rule and carrying the finding type forward — exactly the shape
// `runPass2` consumes (severity is always a rule value in {critical,high,
// medium,low}).
function toClassified(finding) {
  return { ...fallbackClassify(finding), type: finding.type, _source: "fallback" };
}

describe("Feature: deterministic-fallback, Property 12: Pass 2 success keeps LLM prose with deterministic numbers, substituting empties", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("returns _source 'llm' with deterministic score/level/order, substituting empty summary/topPriority", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(findingArbitrary, { minLength: 1, maxLength: 12 }),
        llmResponseArbitrary,
        fc.domain(),
        async (rawFindings, json, domain) => {
          // Each iteration resolves callLLMJson with this iteration's raw
          // response, keeping runPass2 on its success path.
          llm.reset();
          llm.resolveWith(json);

          const classified = rawFindings.map(toClassified);
          const sorted = sortFindings(classified);
          const expectedScore = computeFallbackScore(sorted);
          const expectedLevel = scoreToLevel(expectedScore);

          const report = await runPass2(classified, domain, /* tech */ null);

          // --- Success tag (Requirement 3.2) ---
          expect(report._source).toBe("llm");

          // --- Deterministic numbers (Requirement 3.2) ---
          expect(report.overallRiskScore).toBe(expectedScore);
          expect(report.riskLevel).toBe(expectedLevel);

          // --- Deterministic, severity-ordered findings (highest first) ---
          expect(report.findings).toEqual(sorted);
          // Order is non-increasing by severity rank.
          for (let i = 1; i < report.findings.length; i++) {
            const prev = SEVERITY_RANK[normalizeSeverity(report.findings[i - 1].severity)] || 0;
            const cur = SEVERITY_RANK[normalizeSeverity(report.findings[i].severity)] || 0;
            expect(prev).toBeGreaterThanOrEqual(cur);
          }

          // --- summary substitution (Requirement 3.3) ---
          if (usableLLMString(json.summary)) {
            expect(report.summary).toBe(json.summary);
          } else {
            expect(report.summary).toBe(synthFallbackSummary(domain, sorted));
          }

          // --- topPriority substitution (Requirement 3.4) ---
          if (usableLLMString(json.topPriority)) {
            expect(report.topPriority).toBe(json.topPriority);
          } else {
            // Highest-severity finding's recommendation.
            expect(report.topPriority).toBe(sorted[0].recommendation);
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
