import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so the
// `callLLMJson` dependency inside `runPass2` / `runPass3` is the auto-mocked
// vi.fn — no network, fully in-memory across 100+ iterations.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import {
  runPass2,
  runPass3,
  buildFallbackReport,
  attachTechStack,
} from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 14: a failed narrative is truly
// absent with the core report intact
//
// For any report, when Pass 3 fails (or its narrative is treated as absent),
// the returned report has no `attackScenario` or `ifUnaddressed` keys, no
// substitute/default/placeholder content is inserted, and every other field of
// the report is unchanged — whether Pass 2 succeeded or fell back.
//
// **Validates: Requirements 4.1, 4.4, 4.6**
//
// The handler's narrative attach rule lives INLINE in `scan.js` (not exported):
//
//   const [pass2Rep, narrative] = await Promise.all([
//     runPass2(...).catch(() => null),
//     runPass3(baseReport, domain).catch(() => null),
//   ]);
//   const rep = pass2Rep || baseReport;
//   rep.provider = provider;
//   rep.domain = domain;
//   attachTechStack(rep, techStack);
//   if (narrative) {
//     rep.attackScenario = narrative.attackScenario;
//     rep.ifUnaddressed = narrative.ifUnaddressed;
//   }
//
// Since the guard cannot be imported, it is modeled faithfully below
// (`applyNarrativeAttachRule`). The test builds a realistic base report `rep`
// in BOTH the Pass-2-success (`_source: "llm"`) and Pass-2-fallback
// (`_source: "fallback"`) shapes using the real production functions, snapshots
// it, drives Pass 3 to its "absent narrative" outcome (`runPass3` returns
// `null` — via reject, all-empty response, or a direct `.catch(() => null)`),
// applies the guard, and asserts the report is byte-identical to the snapshot
// with no narrative keys present.
// ---------------------------------------------------------------------------

// Faithful, verbatim model of the inline narrative attach rule in scan.js.
function applyNarrativeAttachRule(rep, narrative) {
  if (narrative) {
    rep.attackScenario = narrative.attackScenario;
    rep.ifUnaddressed = narrative.ifUnaddressed;
  }
  return rep;
}

// A classified finding as produced by a SUCCESSFUL Pass 1 (`classifyOne`):
// deterministic severity, LLM-authored prose, `_source: "llm"`.
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

// Allow the empty list so the Pass-2 `_source: "none"` shape is also exercised.
const classifiedListArb = fc.array(classifiedFindingArb, {
  minLength: 0,
  maxLength: 10,
});

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

const domainArb = fc.domain();

const providerArb = fc.constantFrom(
  "Google Workspace",
  "Microsoft 365",
  "self-hosted",
  null,
  undefined
);

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

// Which Pass-2 shape the base report takes.
const pass2ShapeArb = fc.constantFrom("success", "fallback");

// How the (absent) narrative is produced. All three must yield a falsy
// `narrative` so the attach guard is skipped.
const narrativeModeArb = fc.constantFrom(
  "direct-null", // models `.catch(() => null)` on a Pass 3 reject
  "runpass3-reject", // runPass3 catches the LLM throw and returns null
  "runpass3-both-empty" // runPass3 returns null when both fields are empty/whitespace
);

const emptyNarrativeFieldArb = fc.constantFrom("", "   ", "\t", "\n  \n", null, undefined, 42);

describe("Feature: deterministic-fallback, Property 14: a failed narrative is truly absent with the core report intact", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("leaves attackScenario/ifUnaddressed absent (no placeholder) and every other report field unchanged when Pass 3 yields no narrative — for both Pass-2 success and fallback reports", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        providerArb,
        techArb,
        pass2ShapeArb,
        narrativeModeArb,
        fc.string({ minLength: 1, maxLength: 60 }), // LLM summary (success shape)
        fc.string({ minLength: 1, maxLength: 60 }), // LLM topPriority (success shape)
        emptyNarrativeFieldArb,
        emptyNarrativeFieldArb,
        async (
          classified,
          domain,
          provider,
          tech,
          pass2Shape,
          narrativeMode,
          llmSummary,
          llmTopPriority,
          emptyAttack,
          emptyIfUnaddressed
        ) => {
          const sorted = sortFindings(classified);

          // --- Build the base report `rep` exactly as scan.js would ---
          let rep;
          if (pass2Shape === "fallback") {
            // Layer 2 / base report: built directly from the rule, no LLM.
            rep = buildFallbackReport(domain, sorted);
          } else {
            // Pass-2 success: drive runPass2 with the LLM resolving so it
            // returns the `_source: "llm"` (or `_source: "none"` when empty)
            // report. Findings still carry their deterministic severity.
            llm.reset();
            llm.resolveWith({ summary: llmSummary, topPriority: llmTopPriority });
            rep = await runPass2(classified, domain, tech);
          }

          // Attach provider/domain/techStack just like the handler does before
          // the narrative guard runs.
          rep.provider = provider;
          rep.domain = domain;
          attachTechStack(rep, tech);

          // Snapshot the report immediately before the narrative attach rule.
          const snapshot = structuredClone(rep);

          // --- Drive Pass 3 to its "absent narrative" outcome ---
          let narrative;
          if (narrativeMode === "direct-null") {
            narrative = null;
          } else if (narrativeMode === "runpass3-reject") {
            llm.reset();
            llm.rejectWith(new Error("pass3 failure"));
            narrative = await runPass3(rep, domain).catch(() => null);
          } else {
            // runpass3-both-empty: LLM resolves but both narrative fields are
            // empty/whitespace/non-string -> runPass3 returns null.
            llm.reset();
            llm.resolveWith({
              attackScenario: emptyAttack,
              ifUnaddressed: emptyIfUnaddressed,
            });
            narrative = await runPass3(rep, domain).catch(() => null);
          }

          // runPass3 must have produced no narrative for every absent mode.
          expect(narrative).toBeFalsy();

          // --- Apply the handler's inline attach rule ---
          applyNarrativeAttachRule(rep, narrative);

          // --- Assertions ---

          // 4.4: the narrative keys must NOT appear on the report at all.
          expect(Object.prototype.hasOwnProperty.call(rep, "attackScenario")).toBe(false);
          expect(Object.prototype.hasOwnProperty.call(rep, "ifUnaddressed")).toBe(false);
          expect("attackScenario" in rep).toBe(false);
          expect("ifUnaddressed" in rep).toBe(false);
          expect(rep.attackScenario).toBeUndefined();
          expect(rep.ifUnaddressed).toBeUndefined();

          // No placeholder / substitute / default content was inserted: the key
          // set is exactly what it was before the guard ran.
          expect(Object.keys(rep).sort()).toEqual(Object.keys(snapshot).sort());

          // 4.1 / 4.6: every other field is unchanged — whether Pass 2 succeeded
          // or fell back — so a Pass 3 failure neither blocks nor degrades the
          // core report.
          expect(rep).toEqual(snapshot);
        }
      ),
      { numRuns: 200 }
    );
  });
});
