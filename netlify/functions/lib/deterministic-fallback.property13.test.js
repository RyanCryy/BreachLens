import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so that runPass2's
// `callLLMJson` dependency is the auto-mocked vi.fn — no network, fully
// in-memory across 100+ iterations.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass2 } from "./analysis.js";
import {
  severityArbitrary,
  llmResponseArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 13: Pass 2 findings are severity-ordered
//
// For any list of classified findings, the findings in the Pass 2 output are
// ordered by severity rank from highest to lowest (Critical > High > Medium >
// Low, with info/unrecognized lowest).
//
// **Validates: Requirements 3.6**
//
// `runPass2` sorts its input via the private `sortFindings`, which orders by
// `SEVERITY_RANK[normalizeSeverity(severity)] || 0` descending. The output
// `findings` array is the sorted list on BOTH paths:
//   - LLM success  -> `findings: sorted`        (prose from the LLM, order from sort)
//   - LLM failure  -> `buildFallbackReport(domain, sorted)` (findings: sortedFindings)
// Ordering must hold regardless of which path runs. The only other path is the
// empty-input short-circuit (`findings: []`), which is trivially ordered.
//
// The assertion is the pairwise invariant: for every consecutive pair,
// rank(findings[i]) >= rank(findings[i + 1]).
// ---------------------------------------------------------------------------

// Local mirror of the private rank table + normalization in analysis.js,
// reproduced (not imported) because both are module-private. This is the single
// source of truth for ordering and must match byte-for-byte: recognized
// severities map to {critical:4, high:3, medium:2, low:1}; everything else
// (info, junk, mixed-case-after-lowercasing-but-unrecognized) ranks 0.
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function normalizeSeverity(severity) {
  return typeof severity === "string" ? severity.toLowerCase() : severity;
}
function rank(severity) {
  return SEVERITY_RANK[normalizeSeverity(severity)] || 0;
}

// A classified finding as it would arrive from Pass 1: only `severity` matters
// to the ordering under test, but the rest of the shape is populated so the
// success-path report (which echoes `sorted`) and the fallback report (which
// reads `sorted[0].recommendation`) both compose realistically.
const classifiedFindingArb = fc.record({
  id: fc.string({ minLength: 1, maxLength: 20 }),
  type: fc.constantFrom("email-auth", "tls", "header", "dns", "cookie", "exposure", "subdomain"),
  title: fc.string({ minLength: 1, maxLength: 40 }),
  severity: severityArbitrary,
  explanation: fc.string({ minLength: 1, maxLength: 80 }),
  recommendation: fc.string({ minLength: 1, maxLength: 80 }),
  fixSnippet: fc.oneof(fc.constant(null), fc.string({ minLength: 1, maxLength: 40 })),
  _source: fc.constantFrom("llm", "fallback"),
});

const classifiedListArb = fc.array(classifiedFindingArb, { maxLength: 12 });
const domainArb = fc.constantFrom("example.com", "test.org", "acme.dev", "shop.io");

// Assert the pairwise descending-rank invariant over a findings array.
function expectSeverityOrdered(findings) {
  for (let i = 0; i < findings.length - 1; i++) {
    expect(rank(findings[i].severity)).toBeGreaterThanOrEqual(
      rank(findings[i + 1].severity)
    );
  }
}

describe("Feature: deterministic-fallback, Property 13: Pass 2 findings are severity-ordered", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("orders Pass 2 findings highest-to-lowest severity on the LLM-success path", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        llmResponseArbitrary,
        async (classified, domain, llmResponse) => {
          // Resolve keeps runPass2 on its success path: `findings: sorted`.
          llm.reset();
          llm.resolveWith(llmResponse);

          const report = await runPass2(classified, domain, { detected: [] });

          expectSeverityOrdered(report.findings);
        }
      ),
      { numRuns: 200 }
    );
  });

  it("orders Pass 2 findings highest-to-lowest severity on the LLM-failure (fallback) path", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        async (classified, domain) => {
          // Reject drives runPass2 into its catch -> buildFallbackReport(domain,
          // sorted), whose `findings` is the same sorted list.
          llm.reset();
          llm.rejectWith(new Error("LLM unavailable"));

          const report = await runPass2(classified, domain, { detected: [] });

          expectSeverityOrdered(report.findings);
        }
      ),
      { numRuns: 200 }
    );
  });
});
