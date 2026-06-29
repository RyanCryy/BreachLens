import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so that runPass2 /
// runPass3's `callLLMJson` dependency is the auto-mocked vi.fn — no network,
// fully in-memory across 100+ iterations.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import {
  runPass2,
  runPass3,
  buildFallbackReport,
  computeFallbackScore,
  scoreToLevel,
} from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 17: the base report is
// deterministic regardless of pass outcomes
//
// For any list of Pass 1 findings, the base report that Pass 2 and Pass 3 run
// against (`buildFallbackReport` over the sorted Pass 1 findings) has an
// identical score, level, and finding ordering regardless of the outcomes of
// Pass 2 and Pass 3.
//
// **Validates: Requirements 4.5**
//
// In `scan.js` the handler builds the base report from the Pass 1 findings
// BEFORE dispatching Pass 2 and Pass 3:
//
//   const sortedClassified = [...classified].sort(
//     (a, b) => fallbackSeverityRank(b.severity) - fallbackSeverityRank(a.severity)
//   );
//   const baseReport = buildFallbackReport(domain, sortedClassified);
//   const [pass2Rep, narrative] = await Promise.all([
//     runPass2(classified, domain, techStack).catch(() => null),
//     runPass3(baseReport, domain).catch(() => null),
//   ]);
//   const rep = pass2Rep || baseReport;
//   if (narrative) { rep.attackScenario = ...; rep.ifUnaddressed = ...; }
//
// `buildFallbackReport` is a pure function of `(domain, sortedClassified)`:
// its `overallRiskScore` / `riskLevel` come from `computeFallbackScore` /
// `scoreToLevel`, and its `findings` is exactly the sorted input. Nothing in
// Pass 2 or Pass 3 feeds back into that computation. This test GENUINELY runs
// Pass 2 and Pass 3 across the full matrix of outcomes (Pass 2 success /
// fallback; Pass 3 both-fields / one-field / null / reject) and asserts the
// base report's score, level, and finding ordering are byte-identical across
// every scenario — proving the base is invariant to what the later passes do.
// ---------------------------------------------------------------------------

// Local mirror of the private severity-rank table + normalization used by both
// scan.js (`fallbackSeverityRank`) and analysis.js (`SEVERITY_RANK`). Mirrored
// (not imported) because both are module-private. Recognized severities rank
// {critical:4, high:3, medium:2, low:1}; info/unknown rank 0.
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function rank(severity) {
  return FALLBACK_SEVERITY_RANK[
    typeof severity === "string" ? severity.toLowerCase() : severity
  ] || 0;
}

// A Pass 1 classification, derived deterministically from a generated finding —
// the exact shape `classified` holds when the base report is built. Carries a
// realistic deterministic severity so ordering and scoring exercise real values.
const classificationArb = findingArbitrary.map((finding) => ({
  ...fallbackClassify(finding),
  type: finding.type,
  _source: "fallback",
}));

const classifiedListArb = fc.array(classificationArb, { maxLength: 20 });
const domainArb = fc.constantFrom("example.com", "test.org", "acme.dev", "shop.io");
const techArb = fc.constantFrom(
  { detected: [] },
  { detected: ["WordPress"] },
  { server: "nginx", poweredBy: null, detected: ["nginx"] }
);

// The full matrix of Pass 2 / Pass 3 outcomes the base report must survive.
//   pass2: "success" -> runPass2 resolves (LLM prose, _source "llm")
//          "fallback" -> runPass2's LLM call rejects -> buildFallbackReport
//   pass3: "both" -> both narrative fields present (object returned)
//          "one"  -> exactly one field present (object returned)
//          "null" -> both fields empty (runPass3 returns null)
//          "reject" -> runPass3's LLM call rejects (caught -> null)
const SCENARIOS = [];
for (const pass2 of ["success", "fallback"]) {
  for (const pass3 of ["both", "one", "null", "reject"]) {
    SCENARIOS.push({ pass2, pass3 });
  }
}

// Capture only the invariant the property is about: score, level, and the
// finding ordering (sequence of (id, type, severity)).
function snapshot(report) {
  return {
    overallRiskScore: report.overallRiskScore,
    riskLevel: report.riskLevel,
    ordering: report.findings.map((f) => `${f.id}\u0000${f.type}\u0000${f.severity}`),
  };
}

describe("Feature: deterministic-fallback, Property 17: the base report is deterministic regardless of pass outcomes", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  // Run one full scan-handler-equivalent pipeline for a given outcome scenario,
  // mirroring scan.js, and return a snapshot of the base report AFTER Pass 2 and
  // Pass 3 have actually run (including the handler's narrative-attach mutation).
  async function baseReportSnapshotForScenario(classified, domain, tech, scenario) {
    // 1. Build the base report from the Pass 1 findings (exactly as scan.js does).
    const sortedClassified = [...classified].sort(
      (a, b) => rank(b.severity) - rank(a.severity)
    );
    const baseReport = buildFallbackReport(domain, sortedClassified);

    // 2. Drive Pass 2 to the requested outcome and run it for real.
    llm.reset();
    if (scenario.pass2 === "success") {
      llm.resolveWith({ summary: "Synthesized summary.", topPriority: "Fix the top item." });
    } else {
      llm.rejectWith(new Error("pass2 LLM unavailable"));
    }
    const pass2Rep = await runPass2(classified, domain, tech).catch(() => null);

    // 3. Drive Pass 3 to the requested outcome and run it for real against the
    //    base report (runPass3 reads from, but does not mutate, baseReport).
    llm.reset();
    if (scenario.pass3 === "both") {
      llm.resolveWith({ attackScenario: "An attacker could...", ifUnaddressed: "Risk would grow." });
    } else if (scenario.pass3 === "one") {
      llm.resolveWith({ attackScenario: "An attacker could...", ifUnaddressed: "   " });
    } else if (scenario.pass3 === "null") {
      llm.resolveWith({ attackScenario: "  ", ifUnaddressed: "" });
    } else {
      llm.rejectWith(new Error("pass3 LLM unavailable"));
    }
    const narrative = await runPass3(baseReport, domain).catch(() => null);

    // 4. Mirror scan.js's final composition. When Pass 2 fell back, `rep` IS the
    //    base report and the narrative attaches onto it — yet that only adds
    //    attackScenario/ifUnaddressed, never touching score/level/ordering.
    const rep = pass2Rep || baseReport;
    if (narrative) {
      rep.attackScenario = narrative.attackScenario;
      rep.ifUnaddressed = narrative.ifUnaddressed;
    }

    return snapshot(baseReport);
  }

  it("the base report's score, level, and finding ordering are identical across every Pass 2 / Pass 3 outcome", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb,
        domainArb,
        techArb,
        async (classified, domain, tech) => {
          // The reference: what the base report's numbers MUST be — derived
          // purely from the Pass 1 findings, with no knowledge of any pass.
          const sortedRef = [...classified].sort(
            (a, b) => rank(b.severity) - rank(a.severity)
          );
          const refScore = computeFallbackScore(sortedRef);
          const refLevel = scoreToLevel(refScore);
          const refOrdering = sortedRef.map(
            (f) => `${f.id}\u0000${f.type}\u0000${f.severity}`
          );

          // Run the pipeline once per outcome scenario and collect each base
          // report snapshot.
          const snapshots = [];
          for (const scenario of SCENARIOS) {
            snapshots.push(
              await baseReportSnapshotForScenario(classified, domain, tech, scenario)
            );
          }

          // Every snapshot must equal the reference — invariant to pass outcomes.
          for (const snap of snapshots) {
            expect(snap.overallRiskScore).toBe(refScore);
            expect(snap.riskLevel).toBe(refLevel);
            expect(snap.ordering).toEqual(refOrdering);
          }

          // And, transitively, every scenario agrees with every other.
          for (const snap of snapshots) {
            expect(snap).toEqual(snapshots[0]);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});
