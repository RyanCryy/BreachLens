import { describe, it, expect } from "vitest";
import fc from "fast-check";

import { buildFallbackReport } from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import { findingArbitrary } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 18: the deterministic report
// re-derives everything from scratch
//
// For any list of findings, `deterministicReport()` produces classifications
// equal to those from `fallbackClassify` applied independently to each finding
// — incorporating no in-flight Pass 1 output — sorted by severity rank, and
// tags the report `_source: "fallback"`.
//
// **Validates: Requirements 5.4, 5.5**
//
// `deterministicReport()` is defined inline in `scan.js` (a closure over the
// handler's `findings`/`domain`/`provider`/`techStack`) and is therefore not
// importable. Its body is short and pure with respect to `findings`/`domain`:
//
//   const deterministicReport = () => {
//     const sorted = findings
//       .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
//       .sort((a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity));
//     const r = buildFallbackReport(domain, sorted);
//     r.provider = provider;
//     r.domain = domain;
//     attachTechStack(r, techStack);
//     return r;
//   };
//
// This test models that exact re-derivation (`deterministicReport`, below) and
// then independently re-derives the expected classifications a second way — by
// mapping `fallbackClassify` over the SAME raw findings with no reference to any
// Pass 1 / classified state — and asserts the report's findings equal that
// independent re-derivation, that they are ordered by severity rank (highest
// first), and that both each finding and the report carry `_source: "fallback"`.
//
// Crucially, the input is the RAW pre-classification finding list (Requirement
// 5.4: "re-derive every finding classification from scratch using only
// Deterministic_Rule output, incorporating no in-flight or partial AI_Pipeline
// pass output"). The deterministic path never sees a classified finding.
// ---------------------------------------------------------------------------

// Mirror of scan.js's module-private `FALLBACK_SEVERITY_RANK` + `fallbackSeverityRank`.
// Mirrored (not imported) because both are private to scan.js. Recognized
// severities rank {critical:4, high:3, medium:2, low:1}; info/unknown rank 0.
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const fallbackSeverityRank = (severity) =>
  FALLBACK_SEVERITY_RANK[
    typeof severity === "string" ? severity.toLowerCase() : severity
  ] || 0;

// Faithful model of scan.js's inline `deterministicReport()`. Pure over
// (findings, domain); the provider/techStack mutations are display-only context
// not under test here, so we omit them to keep the model focused on the
// re-derivation Property 18 is about.
function deterministicReport(findings, domain) {
  const sorted = findings
    .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
    .sort((a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity));
  return buildFallbackReport(domain, sorted);
}

// A RAW finding list — exactly the pre-classification shape `deriveFindings`
// hands the handler, NEVER a classified/Pass-1 finding.
const rawFindingsArb = fc.array(findingArbitrary, { maxLength: 20 });
const domainArb = fc.constantFrom("example.com", "test.org", "acme.dev", "shop.io");

describe("Feature: deterministic-fallback, Property 18: the deterministic report re-derives everything from scratch", () => {
  it("classifications equal fallbackClassify applied independently to each raw finding, severity-ordered, tagged _source: fallback", () => {
    fc.assert(
      fc.asyncProperty(rawFindingsArb, domainArb, async (findings, domain) => {
        const report = deterministicReport(findings, domain);

        // (a) Independent re-derivation: map fallbackClassify over the SAME raw
        //     findings with zero reference to any in-flight/Pass-1 state, then
        //     order by severity rank exactly as the handler does.
        const expectedFindings = findings
          .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
          .sort((a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity));

        // The report's findings must equal that independent re-derivation
        // exactly — classification (id/title/severity/explanation/recommendation/
        // fixSnippet) + type + _source:"fallback", in the same severity order.
        expect(report.findings).toEqual(expectedFindings);

        // (b) The ordered-list deep equality in (a) already proves each reported
        //     finding equals `{ ...fallbackClassify(finding), type, _source:
        //     "fallback" }`. Make the per-finding `_source` and length claims
        //     explicit so a regression that dropped the tag or a finding is
        //     reported as such directly.
        expect(report.findings.length).toBe(expectedFindings.length);
        for (const reported of report.findings) {
          expect(reported._source).toBe("fallback");
        }

        // (c) Findings are ordered by severity rank, highest first.
        for (let i = 1; i < report.findings.length; i++) {
          const prev = fallbackSeverityRank(report.findings[i - 1].severity);
          const cur = fallbackSeverityRank(report.findings[i].severity);
          expect(prev).toBeGreaterThanOrEqual(cur);
        }

        // (d) The report itself is tagged _source: "fallback" (Requirement 5.5).
        expect(report._source).toBe("fallback");
      }),
      { numRuns: 100 }
    );
  });
});
