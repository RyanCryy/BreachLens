import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so the
// `callLLMJson` dependency used inside `runPass1`/`runPass2`/`runPass3` is the
// auto-mocked vi.fn — no network, fully in-memory across 100+ iterations, and
// forced to REJECT (with every documented error shape) so the latency-driven
// fallback path is taken.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import {
  runPass1,
  runPass2,
  runPass3,
  attachTechStack,
  buildFallbackReport,
} from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  errorShapeArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 20: layer selection is
// latency-driven, not error-typed
//
// For any LLM error shape (e.g. 401, 429, timeout-like) that causes every LLM
// call to reject BEFORE the 14000 ms budget elapses, the AI_Pipeline resolves
// with the Pass 2 Fallback_Report and the top-level `deterministicReport()` is
// NOT invoked — the outcome is independent of the error type.
//
// **Validates: Requirements 6.1, 6.2**
//
// This is a documentation / formalization spec: no production logic changes.
// The cleanest importable surface is the analysis pipeline. This test reproduces
// the exact composition that `scan.js` runs inside `aiPipeline` (runPass1 →
// Promise.all([runPass2, runPass3])) and the budget race
// (`pipelineResult || deterministicReport()`), then asserts:
//
//   1. With `callLLMJson` rejecting for EVERY shape (401/429/abort-timeout/
//      generic), the pipeline RESOLVES (it never rejects — every pass `.catch`
//      returns a value) and settles instantly, well before the 14000 ms budget.
//   2. The resolved report is the Pass 2 Fallback_Report, tagged
//      `_source: "fallback"`.
//   3. Because the pipeline resolves to a truthy report, the race's
//      `|| deterministicReport()` short-circuits — `deterministicReport()` is
//      NEVER invoked.
//   4. The produced report is IDENTICAL across two independently-generated error
//      shapes — the outcome does not depend on the error type. The branch is
//      selected purely by latency (failure settling within budget), never by a
//      `status === 401 / 429`-style check.
// ---------------------------------------------------------------------------

// Mirror of scan.js's ANALYSIS_BUDGET_MS — the wall-clock budget the pipeline
// races against. Mocked LLM rejections settle synchronously, far under this.
const ANALYSIS_BUDGET_MS = 14000;

// Mirror of scan.js's severity ranking (highest first, info lowest), used by
// both `deterministicReport()` and the pipeline's base-report sort.
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const fallbackSeverityRank = (severity) =>
  FALLBACK_SEVERITY_RANK[typeof severity === "string" ? severity.toLowerCase() : severity] || 0;

// Faithful reproduction of scan.js's top-level `deterministicReport()` (Layer 4):
// it re-derives EVERY classification from scratch via `fallbackClassify`,
// ignoring any in-flight Pass 1 work. Used only as the sentinel the race would
// fall back to — this property asserts it is never reached.
function deterministicReport(findings, domain, provider, techStack) {
  const sorted = findings
    .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
    .sort((a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity));
  const r = buildFallbackReport(domain, sorted);
  r.provider = provider;
  r.domain = domain;
  attachTechStack(r, techStack);
  return r;
}

// Faithful reproduction of scan.js's `aiPipeline` IIFE composition. Every pass
// degrades gracefully (each `.catch` returns a value), so the pipeline RESOLVES
// even when every underlying `callLLMJson` rejects.
async function aiPipeline(findings, domain, provider, techStack) {
  let classified;
  try {
    classified = await runPass1(findings, provider, techStack);
  } catch (_) {
    classified = findings.map((f) => ({
      ...fallbackClassify(f),
      type: f.type,
      _source: "fallback",
    }));
  }

  const sortedClassified = [...classified].sort(
    (a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity)
  );
  const baseReport = buildFallbackReport(domain, sortedClassified);

  const [pass2Rep, narrative] = await Promise.all([
    runPass2(classified, domain, techStack).catch(() => null),
    runPass3(baseReport, domain).catch(() => null),
  ]);

  const rep = pass2Rep || baseReport;
  rep.provider = provider;
  rep.domain = domain;
  attachTechStack(rep, techStack);
  if (narrative) {
    rep.attackScenario = narrative.attackScenario;
    rep.ifUnaddressed = narrative.ifUnaddressed;
  }
  return rep;
}

// Non-empty list of pre-classification findings (Property 20 is about a real
// report; an empty list would short-circuit Pass 2 to `_source: "none"` with no
// LLM call, which is outside this property's scope).
const findingsArb = fc.array(findingArbitrary, { minLength: 1, maxLength: 12 });

const domainArb = fc.domain().filter((d) => typeof d === "string" && d.length > 0);

const providerArb = fc.option(fc.constantFrom("Cloudflare", "AWS Route 53", "GoDaddy"), {
  nil: null,
});

const techArb = fc.option(
  fc.record({
    server: fc.option(fc.string(), { nil: null }),
    poweredBy: fc.option(fc.string(), { nil: null }),
    detected: fc.array(fc.constantFrom("WordPress", "React", "nginx", "PHP"), { maxLength: 3 }),
  }),
  { nil: undefined }
);

// Apply an error shape to the callLLMJson mock (abort-style errors use the
// dedicated controller path so the rejection mirrors a real timeout/abort).
function rejectWithShape(llm, error) {
  llm.reset();
  if (error && error.name === "AbortError") {
    llm.rejectAbort(error.message);
  } else {
    llm.rejectWith(error);
  }
}

describe("Feature: deterministic-fallback, Property 20: layer selection is latency-driven, not error-typed", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("resolves the AI pipeline with the Pass 2 Fallback_Report (deterministicReport never invoked) for any error shape, with an identical outcome across error types", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingsArb,
        domainArb,
        providerArb,
        techArb,
        errorShapeArbitrary,
        errorShapeArbitrary,
        async (findings, domain, provider, tech, errorA, errorB) => {
          // ---- Run A: every LLM call rejects with errorA, within budget. ----
          rejectWithShape(llm, errorA);

          const startA = Date.now();
          const pipelineResultA = await aiPipeline(findings, domain, provider, tech);
          const elapsedA = Date.now() - startA;

          // (1) The pipeline RESOLVES (no throw) and settles far under budget —
          // the failure is caught inside the budget, so Layer 4 is not reached.
          expect(elapsedA).toBeLessThan(ANALYSIS_BUDGET_MS);

          // (2) The resolved value is the Pass 2 Fallback_Report.
          expect(pipelineResultA).toBeTruthy();
          expect(pipelineResultA._source).toBe("fallback");

          // (3) The budget race: because the pipeline resolved to a truthy
          // report, `|| deterministicReport()` short-circuits — the top-level
          // deterministic report is NEVER invoked.
          let deterministicInvoked = false;
          const det = () => {
            deterministicInvoked = true;
            return deterministicReport(findings, domain, provider, tech);
          };
          const racedReport = pipelineResultA || det();
          expect(deterministicInvoked).toBe(false);
          expect(racedReport).toBe(pipelineResultA);

          // No narrative is attached (Pass 3 also rejected → null).
          expect(racedReport.attackScenario).toBeUndefined();
          expect(racedReport.ifUnaddressed).toBeUndefined();

          // ---- Run B: identical inputs, a DIFFERENT error shape. ----
          rejectWithShape(llm, errorB);
          const pipelineResultB = await aiPipeline(findings, domain, provider, tech);

          // (4) Outcome is independent of the error type: the two reports are
          // byte-for-byte identical regardless of 401 vs 429 vs abort vs generic.
          expect(pipelineResultB._source).toBe("fallback");
          expect(pipelineResultB).toEqual(pipelineResultA);

          // And both equal the content the top-level Deterministic_Report would
          // have produced for the same findings — confirming the two fallback
          // sources agree on every field when Pass 1 also fell back.
          expect(pipelineResultA).toEqual(
            deterministicReport(findings, domain, provider, tech)
          );
        }
      ),
      { numRuns: 150 }
    );
  });
});
