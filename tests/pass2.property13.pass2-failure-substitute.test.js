// tests/pass2.property13.pass2-failure-substitute.test.js
//
// Task 8.2 — Property 13: Pass 2 failure substitutes the identical deterministic
// base report.
//
// Feature: analyst-synthesis, Property 13: Pass 2 failure substitutes the identical deterministic base report
// Validates: Requirements 9.5
//
// This test verifies EXISTING production behavior in the `aiPipeline`
// orchestration inside `netlify/functions/scan.js`. No production code is
// modified — the handler is driven HERMETICALLY through module-mock seams only,
// mirroring `tests/scan.budget-race.test.js`.
//
// Property statement (design.md, Property 13):
//   When `runPass2` produces no usable result inside the concurrent
//   `Promise.all` (it rejects, or resolves to a null/absent report), the
//   orchestrator's substitution `const rep = pass2Rep || baseReport` ships the
//   IDENTICAL deterministic Base_Report it derived for (and handed to) Pass 3 —
//   `buildFallbackReport(domain, sortedClassified)` — preserving the
//   deterministic `overallRiskScore`, `riskLevel`, and `findings`.
//
// HOW THIS IS TESTED
// ------------------
// The handler's seams are mocked exactly as the budget-race suite establishes:
//   - `runScan` (passive engine) resolves immediately with a successful, empty
//     Scan_Result so `buildScanResult` / `deriveFindings` (kept REAL) produce a
//     neutral context with an EMPTY detected tech stack (so the real
//     `attachTechStack` appends no extra finding and the shipped `findings`
//     array stays byte-for-byte the Base_Report's findings).
//   - `runPass1` is mocked to return a CONTROLLED classified-finding list, so we
//     know exactly what `sortedClassified` / `baseReport` the handler derives.
//   - `runPass2` is mocked to produce NO usable result: either it rejects (the
//     handler's `.catch(() => null)` maps that to null) or it resolves to null.
//     Both drive `pass2Rep || baseReport` to substitute `baseReport`.
//   - `runPass3` is mocked to either return null or a narrative; neither path
//     touches `overallRiskScore` / `riskLevel` / `findings`.
//   - `buildFallbackReport` / `attachTechStack` are kept REAL, so the shipped
//     report is the genuine production artifact and the oracle is the real
//     `buildFallbackReport(domain, expectedSorted(classified))`.
//
// The final NDJSON `{ type: "result", scan, report }` event carries the shipped
// report; we assert its deterministic fields equal the Base_Report's.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  classifiedListArb,
  domainArb,
  expectedSorted,
  buildFallbackReport,
} from "./helpers/pass2-fixtures.js";
import { normalizeDomain } from "../netlify/functions/lib/checks.js";

// Hoisted spies referenced by the (hoisted) vi.mock factories below.
const { mockRunScan, mockRunPass1, mockRunPass2, mockRunPass3 } = vi.hoisted(() => ({
  mockRunScan: vi.fn(),
  mockRunPass1: vi.fn(),
  mockRunPass2: vi.fn(),
  mockRunPass3: vi.fn(),
}));

// Mock ONLY the passive engine's `runScan`; keep RESULT_TYPE + defaultDeps real so
// the handler's success gate and dependency wiring behave exactly as production.
vi.mock("../netlify/functions/lib/scan-engine.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, runScan: (...args) => mockRunScan(...args) };
});

// Mock ONLY the three AI passes; keep buildFallbackReport + attachTechStack REAL so
// the deterministic Base_Report the handler ships is the genuine production output.
vi.mock("../netlify/functions/lib/analysis.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    runPass1: (...args) => mockRunPass1(...args),
    runPass2: (...args) => mockRunPass2(...args),
    runPass3: (...args) => mockRunPass3(...args),
  };
});

import scan from "../netlify/functions/scan.js";

function makeReq(domain) {
  return new Request("https://example.com/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain }),
  });
}

// Read the handler's NDJSON Response body into an array of parsed events.
async function readEvents(res) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const events = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line) events.push(JSON.parse(line));
    }
  }
  const tail = buf.trim();
  if (tail) events.push(JSON.parse(tail));
  return events;
}

const resultEvent = (events) => events.find((e) => e.type === "result");

// The two ways Pass 2 produces "no usable result" inside the concurrent
// Promise.all: it rejects (handler's `.catch(() => null)` → null) or resolves
// to null. Both must drive `pass2Rep || baseReport` to substitute baseReport.
const pass2FailureArb = fc.constantFrom("reject", "null");

// Pass 3 is independent of the deterministic score/level/findings: it either
// fails (null narrative) or returns a narrative the handler attaches separately.
const pass3OutcomeArb = fc.constantFrom("null", "narrative");

beforeEach(() => {
  mockRunScan.mockReset();
  mockRunPass1.mockReset();
  mockRunPass2.mockReset();
  mockRunPass3.mockReset();

  // Passive engine: immediate successful, empty Scan_Result. buildScanResult
  // fills neutral defaults (tech.detected === []), so the REAL attachTechStack
  // appends no finding and the shipped findings array is exactly the Base_Report's.
  mockRunScan.mockImplementation(async (domain) => ({
    type: "scan",
    domain,
    scannedAt: "2024-01-01T00:00:00.000Z",
    outcomes: [],
  }));
});

describe("scan.js aiPipeline — Property 13: Pass 2 failure substitutes the identical deterministic Base_Report", () => {
  it("ships buildFallbackReport(domain, sortedClassified) — preserving overallRiskScore/riskLevel/findings — whenever Pass 2 yields no usable result", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb({ minLength: 0, maxLength: 10 }),
        domainArb,
        pass2FailureArb,
        pass3OutcomeArb,
        async (classified, domain, pass2Failure, pass3Outcome) => {
          // runPass1 returns our controlled classified list (the handler ignores
          // its real inputs since we mock it), so we know the exact baseReport.
          mockRunPass1.mockResolvedValue(classified);

          // runPass2 produces NO usable result this iteration.
          if (pass2Failure === "reject") {
            mockRunPass2.mockRejectedValue(new Error("pass2 unavailable"));
          } else {
            mockRunPass2.mockResolvedValue(null);
          }

          // runPass3 either fails (null) or returns a narrative.
          if (pass3Outcome === "narrative") {
            mockRunPass3.mockResolvedValue({
              attackScenario: "Illustrative scenario.",
              ifUnaddressed: "Risk may grow.",
            });
          } else {
            mockRunPass3.mockResolvedValue(null);
          }

          const res = await scan(makeReq(domain));
          expect(res.status).toBe(200);
          const events = await readEvents(res);

          const result = resultEvent(events);
          expect(result).toBeTruthy();
          const report = result.report;

          // Ground truth: the IDENTICAL deterministic Base_Report the handler
          // derives from Pass 1's classified output (and hands to Pass 3).
          // expectedSorted mirrors the handler's stable severity-desc sort
          // (FALLBACK_SEVERITY_RANK), so this is byte-for-byte the baseReport.
          const norm = normalizeDomain(domain);
          const sorted = expectedSorted(classified);
          const expected = buildFallbackReport(norm, sorted);

          // The substituted report preserves the deterministic fields.
          expect(report.overallRiskScore).toBe(expected.overallRiskScore);
          expect(report.riskLevel).toBe(expected.riskLevel);
          expect(report.findings).toEqual(expected.findings);

          // It is the deterministic Base_Report, NOT a Pass 2 ("llm"/"none") report.
          expect(report._source).toBe("fallback");
        }
      ),
      { numRuns: 120 }
    );
  });
});
