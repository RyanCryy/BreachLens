// scan.js AI-phase budget race integration tests (Task 10.1)
//
// Exercises the 14_000 ms AI-phase budget enforced by the scan handler's
// `Promise.race([ aiPipeline, budget ])` (see netlify/functions/scan.js). The
// handler is driven HERMETICALLY:
//
//   - The passive scan engine (`runScan`) is mocked to return an immediate,
//     successful (non-resolution-failure) Scan_Result so `buildScanResult` /
//     `deriveFindings` (kept REAL) produce findings without any network.
//   - The AI passes (`runPass1` / `runPass2` / `runPass3`) are mocked so we can
//     drive the race: a within-budget resolution, a never-resolving/over-budget
//     pipeline, and a pipeline that fails before budget.
//   - `buildFallbackReport` and `attachTechStack` are kept REAL, so the
//     deterministic report the handler ships is the genuine production artifact.
//
// The handler emits a newline-delimited JSON (NDJSON) stream; the final event is
// `{ type: "result", scan, report }`. We parse that stream from the Response and
// assert `report._source` distinguishes the LLM report ("llm", produced by
// runPass2) from the deterministic report ("fallback", produced by
// buildFallbackReport via the handler's deterministicReport()).
//
// Vitest fake timers drive the 14_000 ms budget timer; promise microtasks are
// flushed by advanceTimersByTimeAsync / runAllTimersAsync.
//
// PRODUCTION IS FROZEN: this file only module-mocks seams, it never edits
// netlify/functions/*.
//
// _Requirements: 8.1, 8.2, 8.3, 8.4_

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Hoisted spies referenced by the vi.mock factories below.
const { mockRunScan, mockRunPass1, mockRunPass2, mockRunPass3 } = vi.hoisted(() => ({
  mockRunScan: vi.fn(),
  mockRunPass1: vi.fn(),
  mockRunPass2: vi.fn(),
  mockRunPass3: vi.fn(),
}));

// Mock ONLY the passive engine's `runScan`; keep RESULT_TYPE + defaultDeps real so
// the handler's success gate and dependency wiring behave exactly as in production.
vi.mock("../netlify/functions/lib/scan-engine.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, runScan: (...args) => mockRunScan(...args) };
});

// Mock ONLY the three AI passes; keep buildFallbackReport + attachTechStack REAL so
// the deterministic report the handler ships is the genuine production output.
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

const ANALYSIS_BUDGET_MS = 14000;

// A recognizable LLM report so we can prove the handler emitted the pipeline's
// report (not the deterministic one) on the within-budget path.
const LLM_SUMMARY_SENTINEL = "LLM-SUMMARY-SENTINEL-7f3a";
function makeLlmReport() {
  return {
    overallRiskScore: 42,
    riskLevel: "Medium",
    summary: LLM_SUMMARY_SENTINEL,
    findings: [],
    topPriority: "Address the highest-severity item first.",
    _source: "llm",
  };
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

function resultEvent(events) {
  return events.find((e) => e.type === "result");
}

beforeEach(() => {
  vi.useFakeTimers();
  mockRunScan.mockReset();
  mockRunPass1.mockReset();
  mockRunPass2.mockReset();
  mockRunPass3.mockReset();

  // Default: the passive engine resolves immediately with a successful, empty
  // Scan_Result. buildScanResult fills neutral defaults; deriveFindings (real)
  // derives the findings the AI phase would classify.
  mockRunScan.mockImplementation(async (domain) => ({
    type: "scan",
    domain,
    scannedAt: "2024-01-01T00:00:00.000Z",
    outcomes: [],
  }));

  // Pass 3 is non-essential to the budget race; default to no narrative.
  mockRunPass3.mockResolvedValue(null);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("scan.js AI-phase budget race", () => {
  it("emits the LLM report when the pipeline resolves WITHIN the budget (Req 8.2)", async () => {
    // Pipeline settles on microtasks, well before the 14s budget timer fires.
    mockRunPass1.mockResolvedValue([]); // iterable classified result
    mockRunPass2.mockResolvedValue(makeLlmReport());

    const res = await scan(makeReq());
    expect(res.status).toBe(200);

    const eventsPromise = readEvents(res);
    // Flush microtasks (and clear the now-cancelled budget timer).
    await vi.runAllTimersAsync();
    const events = await eventsPromise;

    const result = resultEvent(events);
    expect(result).toBeTruthy();
    // The pipeline won the race → the LLM report is shipped.
    expect(result.report._source).toBe("llm");
    expect(result.report.summary).toBe(LLM_SUMMARY_SENTINEL);
  });

  it("emits the deterministic report when the pipeline is OVER budget, and later sends on the closed stream are ignored (Req 8.1, 8.3)", async () => {
    // runPass1 hangs on a deferred we resolve only AFTER the budget elapses and
    // the stream is closed, so its downstream `send`s hit a closed controller.
    let resolvePass1;
    mockRunPass1.mockImplementation(
      () => new Promise((resolve) => { resolvePass1 = resolve; })
    );
    mockRunPass2.mockResolvedValue(makeLlmReport());

    const res = await scan(makeReq());
    const eventsPromise = readEvents(res);

    // Advance past the 14s budget → budget timer wins the race.
    await vi.advanceTimersByTimeAsync(ANALYSIS_BUDGET_MS);
    const events = await eventsPromise;

    const result = resultEvent(events);
    expect(result).toBeTruthy();
    // Budget elapsed → the deterministic rule-based report is shipped.
    expect(result.report._source).toBe("fallback");
    expect(result.report.summary).not.toBe(LLM_SUMMARY_SENTINEL);

    const resultCountBefore = events.filter((e) => e.type === "result").length;
    expect(resultCountBefore).toBe(1);

    // Now let the over-budget pipeline finally finish. Its subsequent `send`s hit
    // the already-closed stream and must be harmlessly ignored (no throw, and the
    // emitted report is unaffected).
    await expect(
      (async () => {
        resolvePass1([]);
        await vi.runAllTimersAsync();
      })()
    ).resolves.toBeUndefined();
  });

  it("emits the deterministic report when the pipeline REJECTS before the budget (Req 8.4)", async () => {
    // Force the aiPipeline to reject before budget: runPass1 resolves a
    // non-iterable, so the handler's `[...classified]` spread throws inside the
    // pipeline IIFE, rejecting it. The race's rejection handler returns null and
    // the handler falls through to deterministicReport().
    mockRunPass1.mockResolvedValue(null);
    mockRunPass2.mockResolvedValue(makeLlmReport());

    const res = await scan(makeReq());
    const eventsPromise = readEvents(res);
    await vi.runAllTimersAsync();
    const events = await eventsPromise;

    const result = resultEvent(events);
    expect(result).toBeTruthy();
    expect(result.report._source).toBe("fallback");
    expect(result.report.summary).not.toBe(LLM_SUMMARY_SENTINEL);
  });
});
