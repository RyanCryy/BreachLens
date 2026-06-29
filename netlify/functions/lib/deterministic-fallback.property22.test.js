import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so the
// `callLLMJson` dependency inside `runPass2` is the auto-mocked vi.fn — no
// network, fully in-memory across 100+ iterations, and controllable so we can
// drive the success ("llm"), failure ("fallback"), and empty ("none") report
// branches.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass2, buildFallbackReport } from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  errorShapeArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 22: report source tag is always
// within the allowed domain
//
// For any report produced by any backend path, `_source` is one of
// `"llm" | "fallback" | "none" | "deterministic"`, and is NEVER `"error"`.
//
// **Validates: Requirements 7.1**
//
// The report-level `_source` is set by the importable report producers:
//   - `runPass2` success            -> "llm"
//   - `runPass2` LLM throw/timeout  -> "fallback"
//   - `runPass2` empty short-circuit -> "none"
//   - `buildFallbackReport`         -> "fallback"
//
// The top-level `deterministicReport()` in scan.js (which tags "fallback") and
// `attachTechStack` (which adds an informational finding tagged "deterministic")
// are inline / report-decorating and are not separately importable, so this
// property exercises the importable producers across many findings and mocked
// pipeline outcomes and asserts the report-level `_source` is always in the
// allowed set and never "error".
// ---------------------------------------------------------------------------

// The complete allowed Source_Tag domain (design: Source_Tag domain table).
const ALLOWED_SOURCES = ["llm", "fallback", "none", "deterministic"];

// A classified finding as produced by Pass 1 (`classifyOne`): deterministic
// severity from the rule, LLM-authored prose, `_source: "llm"`.
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
      title: llmTitle,
      severity: rule.severity, // ALWAYS deterministic — never LLM-supplied
      explanation: llmExplanation,
      recommendation: llmRecommendation,
      fixSnippet: rule.fixSnippet,
      _source: "llm",
    };
  });

// May be empty (to drive the "none" short-circuit) or non-empty.
const classifiedListArb = fc.array(classifiedFindingArb, {
  minLength: 0,
  maxLength: 12,
});

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

// The mocked pipeline outcome for a given iteration: the LLM call either
// resolves with an arbitrary response (Pass 2 success) or rejects with any
// error shape (Pass 2 fallback). Combined with empty/non-empty findings this
// reaches every report-producing branch.
const outcomeArb = fc.oneof(
  fc.record({ kind: fc.constant("success"), response: llmResponseArbitrary }),
  fc.record({ kind: fc.constant("failure"), error: errorShapeArbitrary })
);

describe("Feature: deterministic-fallback, Property 22: report source tag is always within the allowed domain", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("every report produced by runPass2 (success/fallback/empty) has _source in the allowed set and never \"error\"", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        techArb,
        outcomeArb,
        async (classified, domain, tech, outcome) => {
          llm.reset();
          if (outcome.kind === "success") {
            llm.resolveWith(outcome.response);
          } else if (outcome.error.name === "AbortError") {
            llm.rejectAbort(outcome.error.message);
          } else {
            llm.rejectWith(outcome.error);
          }

          const report = await runPass2(classified, domain, tech);

          expect(ALLOWED_SOURCES).toContain(report._source);
          expect(report._source).not.toBe("error");
        }
      ),
      { numRuns: 200 }
    );
  });

  it("buildFallbackReport always tags the report \"fallback\" (in the allowed set, never \"error\")", () => {
    fc.assert(
      fc.property(classifiedListArb, domainArb, (classified, domain) => {
        const report = buildFallbackReport(domain, classified);

        expect(report._source).toBe("fallback");
        expect(ALLOWED_SOURCES).toContain(report._source);
        expect(report._source).not.toBe("error");
      }),
      { numRuns: 200 }
    );
  });
});
