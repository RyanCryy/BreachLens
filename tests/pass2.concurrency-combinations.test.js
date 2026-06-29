// scan.js Pass 2 / Pass 3 concurrency & independence example tests (Task 10.3)
//
// Verifies the orchestration in netlify/functions/scan.js where Pass 2 and Pass 3
// are launched CONCURRENTLY via:
//
//   const [pass2Rep, narrative] = await Promise.all([
//     runPass2(classified, domain, techStack).catch(() => null),
//     runPass3(baseReport, domain).catch(() => null),
//   ]);
//   ...
//   const rep = pass2Rep || baseReport;                 // base report substituted on Pass 2 failure
//   if (narrative) { rep.attackScenario = ...; rep.ifUnaddressed = ...; }  // narrative omitted on Pass 3 failure
//
// Each pass carries its OWN independent `.catch(() => null)`, so one stage's
// failure can never prevent the other from completing and being incorporated.
//
// The handler is driven HERMETICALLY, mirroring tests/scan.budget-race.test.js:
//   - The passive scan engine (`runScan`) is mocked to return an immediate,
//     successful Scan_Result (no network).
//   - `runPass1` is mocked to return controlled classified findings, so the
//     deterministic base report built by the REAL `buildFallbackReport` has a
//     known score/level/topPriority.
//   - `runPass2` / `runPass3` are mocked to drive the four success/failure combos.
//   - `buildFallbackReport` and `attachTechStack` are kept REAL, so the
//     deterministic base report the handler ships is the genuine production artifact.
//
// These are EXAMPLE-based unit tests (NOT property tests). Production is FROZEN:
// this file only module-mocks seams; it never edits netlify/functions/*.
//
// _Requirements: 9.1, 9.3, 9.4, 9.6_

import { describe, it, expect, beforeEach, vi } from "vitest";

// Hoisted spies referenced by the vi.mock factories below.
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

// Mock ONLY the three AI passes; keep buildFallbackReport + attachTechStack REAL so
// the deterministic base report the handler ships is the genuine production output.
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

// --- Controlled Pass 1 output -------------------------------------------------
// One critical (weight 40) + one high (weight 22) => deterministic score 62 => "High".
// First (highest-severity) finding's recommendation is the deterministic topPriority.
const CRIT_RECOMMENDATION = "Fix the critical exposure first.";
const CLASSIFIED = [
  {
    id: "f-crit",
    type: "dns",
    title: "Critical exposure",
    severity: "critical",
    explanation: "A critical issue was found.",
    recommendation: CRIT_RECOMMENDATION,
    fixSnippet: null,
    _source: "llm",
  },
  {
    id: "f-high",
    type: "headers",
    title: "High exposure",
    severity: "high",
    explanation: "A high-severity issue was found.",
    recommendation: "Then fix the high-severity item.",
    fixSnippet: null,
    _source: "llm",
  },
];
const EXPECTED_BASE_SCORE = 62; // 40 (critical) + 22 (high)
const EXPECTED_BASE_LEVEL = "High"; // 62 >= 45

// --- Recognizable Pass 2 / Pass 3 outputs ------------------------------------
const LLM_SUMMARY_SENTINEL = "LLM-SUMMARY-SENTINEL-9c2e";
function makeLlmReport() {
  return {
    overallRiskScore: EXPECTED_BASE_SCORE,
    riskLevel: EXPECTED_BASE_LEVEL,
    summary: LLM_SUMMARY_SENTINEL,
    findings: [...CLASSIFIED],
    topPriority: "LLM top priority sentence.",
    _source: "llm",
  };
}

const ATTACK_SENTINEL = "ATTACK-SCENARIO-SENTINEL";
const UNADDRESSED_SENTINEL = "IF-UNADDRESSED-SENTINEL";
function makeNarrative() {
  return { attackScenario: ATTACK_SENTINEL, ifUnaddressed: UNADDRESSED_SENTINEL };
}

function makeReq(domain = "example.com") {
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

async function runScanReport(domain = "example.com") {
  const res = await scan(makeReq(domain));
  expect(res.status).toBe(200);
  const events = await readEvents(res);
  const result = events.find((e) => e.type === "result");
  expect(result).toBeTruthy();
  return result.report;
}

beforeEach(() => {
  mockRunScan.mockReset();
  mockRunPass1.mockReset();
  mockRunPass2.mockReset();
  mockRunPass3.mockReset();

  // Passive engine resolves immediately with a successful, empty Scan_Result.
  mockRunScan.mockImplementation(async (domain) => ({
    type: "scan",
    domain,
    scannedAt: "2024-01-01T00:00:00.000Z",
    outcomes: [],
  }));

  // Pass 1 yields the controlled classified findings used to build the base report.
  mockRunPass1.mockResolvedValue([...CLASSIFIED]);
});

describe("scan.js Pass 2 / Pass 3 concurrency and independence", () => {
  it("launches BOTH Pass 2 and Pass 3 concurrently with independent catches (Req 9.1)", async () => {
    // Both fail — yet both must still have been launched exactly once, proving the
    // launch is concurrent (Promise.all) and each failure is caught independently.
    mockRunPass2.mockRejectedValue(new Error("pass2 boom"));
    mockRunPass3.mockRejectedValue(new Error("pass3 boom"));

    await runScanReport();

    expect(mockRunPass2).toHaveBeenCalledTimes(1);
    expect(mockRunPass3).toHaveBeenCalledTimes(1);
  });

  it("both succeed → both incorporated (LLM summary + Pass 3 narrative)", async () => {
    mockRunPass2.mockResolvedValue(makeLlmReport());
    mockRunPass3.mockResolvedValue(makeNarrative());

    const report = await runScanReport();

    // Pass 2's LLM report is used verbatim.
    expect(report._source).toBe("llm");
    expect(report.summary).toBe(LLM_SUMMARY_SENTINEL);
    // Pass 3's narrative is appended.
    expect(report.attackScenario).toBe(ATTACK_SENTINEL);
    expect(report.ifUnaddressed).toBe(UNADDRESSED_SENTINEL);
  });

  it("Pass 2 fails → deterministic base report substituted, Pass 3 narrative still included (Req 9.3)", async () => {
    mockRunPass2.mockRejectedValue(new Error("pass2 boom"));
    mockRunPass3.mockResolvedValue(makeNarrative());

    const report = await runScanReport();

    // Base report (buildFallbackReport over the sorted classified findings) is substituted.
    expect(report._source).toBe("fallback");
    expect(report.overallRiskScore).toBe(EXPECTED_BASE_SCORE);
    expect(report.riskLevel).toBe(EXPECTED_BASE_LEVEL);
    expect(report.topPriority).toBe(CRIT_RECOMMENDATION);
    expect(report.summary).not.toBe(LLM_SUMMARY_SENTINEL);
    // Pass 3 completed independently → its narrative is still included.
    expect(report.attackScenario).toBe(ATTACK_SENTINEL);
    expect(report.ifUnaddressed).toBe(UNADDRESSED_SENTINEL);
  });

  it("Pass 3 fails → Pass 2 summary kept, narrative fields omitted (Req 9.4)", async () => {
    mockRunPass2.mockResolvedValue(makeLlmReport());
    mockRunPass3.mockRejectedValue(new Error("pass3 boom"));

    const report = await runScanReport();

    // Pass 2's LLM report is kept intact.
    expect(report._source).toBe("llm");
    expect(report.summary).toBe(LLM_SUMMARY_SENTINEL);
    // Pass 3 failed → narrative fields are omitted entirely.
    expect(report.attackScenario).toBeUndefined();
    expect(report.ifUnaddressed).toBeUndefined();
  });

  it("both fail → final report is the deterministic base report with no narrative fields (Req 9.6)", async () => {
    mockRunPass2.mockRejectedValue(new Error("pass2 boom"));
    mockRunPass3.mockRejectedValue(new Error("pass3 boom"));

    const report = await runScanReport();

    // Base report substituted for Pass 2.
    expect(report._source).toBe("fallback");
    expect(report.overallRiskScore).toBe(EXPECTED_BASE_SCORE);
    expect(report.riskLevel).toBe(EXPECTED_BASE_LEVEL);
    expect(report.topPriority).toBe(CRIT_RECOMMENDATION);
    expect(report.summary).not.toBe(LLM_SUMMARY_SENTINEL);
    // No Pass 3 narrative fields.
    expect(report.attackScenario).toBeUndefined();
    expect(report.ifUnaddressed).toBeUndefined();
  });
});
