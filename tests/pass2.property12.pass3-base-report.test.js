// tests/pass2.property12.pass3-base-report.test.js
//
// Task 8.1 — Property 12: Pass 3 receives a deterministic base report derived
// only from Pass 1.
//
// Feature: analyst-synthesis, Property 12: Pass 3 receives a deterministic base report derived only from Pass 1
// Validates: Requirements 9.2
//
// This test verifies EXISTING production behavior in the `aiPipeline`
// orchestration of `netlify/functions/scan.js`. No production code is modified.
//
// Property statement (design.md, Property 12):
//   For any Pass 1 classified output, the report the orchestrator passes to
//   Pass 3 equals `buildFallbackReport(domain, sortedClassified)` — carrying the
//   deterministic score, level, and severity-sorted findings — and contains no
//   field originating from Pass 2 output.
//
// MOCKING STRATEGY (mirrors tests/scan.budget-race.test.js):
//   - Mock the passive engine's `runScan` so the handler reaches its AI phase
//     immediately and hermetically (no network), keeping RESULT_TYPE/defaultDeps
//     real so the success gate and dependency wiring behave as in production.
//   - Mock the three AI passes (`runPass1`/`runPass2`/`runPass3`) while keeping
//     `buildFallbackReport` and `attachTechStack` REAL — so the base report the
//     orchestrator builds is the genuine production artifact:
//       * runPass1  -> returns the CONTROLLED classified list (the Pass 1 output).
//       * runPass2  -> returns a recognizable Pass-2 report (its fields must NOT
//                      leak into the base report handed to Pass 3).
//       * runPass3  -> CAPTURES its first argument (the base report) and the
//                      domain it received, then resolves null.
//
// The handler builds `baseReport = buildFallbackReport(domain, sortedClassified)`
// where `sortedClassified = [...classified].sort(byFallbackSeverityRankDesc)`,
// and calls `runPass3(baseReport, domain)` inside the concurrent `Promise.all`.
// We assert the captured argument DEEP-EQUALS `buildFallbackReport(domain,
// sortedClassified)` and carries no Pass-2-only / post-pipeline field.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import {
  classifiedListArb,
  domainArb,
  buildFallbackReport,
} from "./helpers/pass2-fixtures.js";

// Severity ordering used by the handler's base-report sort (see scan.js).
// Mirrored EXACTLY here, including the `info: 0` entry and case-normalized lookup.
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const fallbackRank = (severity) =>
  FALLBACK_SEVERITY_RANK[typeof severity === "string" ? severity.toLowerCase() : severity] || 0;

// Replicate the handler's `[...classified].sort(...)` precisely (same V8 stable
// sort, same comparator, same original order) so the oracle base report matches.
function sortedClassifiedLike(classified) {
  return [...classified].sort((a, b) => fallbackRank(b.severity) - fallbackRank(a.severity));
}

// Hoisted spies referenced by the (hoisted) vi.mock factories below.
const { mockRunScan, mockRunPass1, mockRunPass2, mockRunPass3 } = vi.hoisted(() => ({
  mockRunScan: vi.fn(),
  mockRunPass1: vi.fn(),
  mockRunPass2: vi.fn(),
  mockRunPass3: vi.fn(),
}));

// Mock ONLY the passive engine's `runScan`; keep RESULT_TYPE + defaultDeps real.
vi.mock("../netlify/functions/lib/scan-engine.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, runScan: (...args) => mockRunScan(...args) };
});

// Mock ONLY the three AI passes; keep buildFallbackReport + attachTechStack REAL.
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

// A recognizable Pass-2 report. None of its distinctive fields may appear in the
// base report the orchestrator hands to Pass 3.
const PASS2_SUMMARY_SENTINEL = "PASS2-SUMMARY-SENTINEL-9c4e";
function makePass2Report() {
  return {
    overallRiskScore: 999,
    riskLevel: "TotallyBogus",
    summary: PASS2_SUMMARY_SENTINEL,
    findings: [{ title: "pass2-only-finding", severity: "critical" }],
    topPriority: "PASS2-ONLY-TOP-PRIORITY",
    _source: "llm",
  };
}

function makeReq(domain) {
  return new Request("https://example.com/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain }),
  });
}

// Drain the handler's NDJSON Response body so the pipeline runs to completion.
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

// Fields that originate from Pass 2 output or are attached to the final report
// AFTER the concurrent passes resolve — none may appear on the base report.
const FORBIDDEN_PASS2_AND_POST_PIPELINE_FIELDS = [
  "provider",
  "domain",
  "techStack",
  "attackScenario",
  "ifUnaddressed",
];

beforeEach(() => {
  mockRunScan.mockReset();
  mockRunPass1.mockReset();
  mockRunPass2.mockReset();
  mockRunPass3.mockReset();

  // Passive engine resolves immediately with a successful, empty Scan_Result so
  // the handler reaches its AI phase without any network. (The findings derived
  // here are irrelevant: runPass1 is mocked to return the controlled list.)
  mockRunScan.mockImplementation(async (domain) => ({
    type: "scan",
    domain,
    scannedAt: "2024-01-01T00:00:00.000Z",
    outcomes: [],
  }));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("scan.js aiPipeline — Property 12: Pass 3 receives a deterministic base report derived only from Pass 1", () => {
  it("hands runPass3 a report deep-equal to buildFallbackReport(domain, sortedClassified) with no Pass 2 field", async () => {
    await fc.assert(
      fc.asyncProperty(
        classifiedListArb({ minLength: 0, maxLength: 8 }),
        domainArb,
        async (classified, domain) => {
          // Capture state for this run.
          let capturedBaseReport;
          let capturedDomain;

          // Reset per-iteration call history (fast-check reuses these spies
          // across runs, so call counts would otherwise accumulate).
          mockRunPass1.mockReset();
          mockRunPass2.mockReset();
          mockRunPass3.mockReset();

          // Pass 1 produces the controlled classified output.
          mockRunPass1.mockResolvedValue(classified);
          // Pass 2 returns a recognizable report whose fields must NOT leak.
          mockRunPass2.mockResolvedValue(makePass2Report());
          // Pass 3 captures the base report argument it receives, then resolves.
          mockRunPass3.mockImplementation(async (report, dom) => {
            capturedBaseReport = report;
            capturedDomain = dom;
            return null;
          });

          const res = await scan(makeReq(domain));
          expect(res.status).toBe(200);
          // Draining the stream runs the concurrent passes to completion.
          await readEvents(res);

          // runPass3 must have been handed an argument.
          expect(mockRunPass3).toHaveBeenCalledTimes(1);
          expect(capturedBaseReport).toBeTruthy();

          // The base report is built with the (normalized) domain the handler
          // also passed to Pass 3; use that for the oracle to stay faithful.
          const expectedBase = buildFallbackReport(
            capturedDomain,
            sortedClassifiedLike(classified)
          );

          // (1) The captured base report equals the genuine deterministic
          //     buildFallbackReport output: deterministic score/level, templated
          //     summary, severity-sorted findings, top recommendation, fallback tag.
          expect(capturedBaseReport).toEqual(expectedBase);

          // (2) It carries EXACTLY the buildFallbackReport key set — proving no
          //     extra field (Pass 2 prose or post-pipeline attachment) crept in.
          expect(Object.keys(capturedBaseReport).sort()).toEqual(
            Object.keys(expectedBase).sort()
          );

          // (3) Provenance is the deterministic fallback, never a Pass 2 source.
          expect(capturedBaseReport._source).toBe("fallback");
          expect(capturedBaseReport._source).not.toBe("llm");
          expect(capturedBaseReport._source).not.toBe("none");

          // (4) No recognizable Pass 2 prose leaked into the base report.
          expect(capturedBaseReport.summary).not.toBe(PASS2_SUMMARY_SENTINEL);
          expect(capturedBaseReport.topPriority).not.toBe("PASS2-ONLY-TOP-PRIORITY");

          // (5) No Pass-2-only / post-pipeline field is present on the base report.
          for (const field of FORBIDDEN_PASS2_AND_POST_PIPELINE_FIELDS) {
            expect(Object.prototype.hasOwnProperty.call(capturedBaseReport, field)).toBe(
              false
            );
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});
