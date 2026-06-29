import { describe, it, expect, vi, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — Example: budget race timing with fake timers
//
// Concrete example/edge cases (NOT property-generated) for the top-level
// Analysis_Budget race in `netlify/functions/scan.js`. Covers four timing
// scenarios with `vi.useFakeTimers()` and a controllable pipeline:
//   (a) pipeline pending past 14000 ms → ships the Deterministic_Report;
//   (b) pipeline resolving first       → ships the AI report and calls clearTimeout;
//   (c) pipeline rejecting within budget → ships the Deterministic_Report;
//   (d) a timer firing AFTER the result → produces no additional event.
//
// _Requirements: 5.1, 5.2, 5.3, 5.6, 5.7_
//   5.1 race the AI_Pipeline against a single 14000 ms budget timer
//   5.2 budget elapses first → Result_Event carries the Deterministic_Report
//   5.3 pipeline rejects within budget → Result_Event carries the Deterministic_Report
//   5.6 pipeline resolves first → Result_Event carries the AI report AND the timer is cancelled
//   5.7 a budget timer firing after the Result_Event was sent emits no additional event
//
// ── Why a faithful-model harness rather than the real handler ───────────────
// CONTEXT: this is a documentation/formalization spec for EXISTING behavior; no
// production code is modified. The budget race lives inline inside scan.js's
// `ReadableStream` default export, buried behind passive-scan orchestration, and
// the AI pipeline IIFE never rejects through the real handler (every internal
// pass is individually try/catch-guarded). Driving the real streaming handler
// under fake timers is brittle, so — following the same convention used by
// `deterministic-fallback.property19.test.js` and `scan.pass3-integration.test.js`
// — this test reproduces scan.js's race expression EXACTLY in a local harness.
//
// The harness mirrors scan.js line-for-line. The relevant production code is:
//
//     const analysisBudget = ANALYSIS_BUDGET_MS;          // 14000
//     let budgetTimer;
//     const budget = new Promise((resolve) => {
//       budgetTimer = setTimeout(() => resolve(null), analysisBudget);
//     });
//     const report =
//       (await Promise.race([
//         aiPipeline.then(
//           (r) => { clearTimeout(budgetTimer); return r; },
//           () => { clearTimeout(budgetTimer); return null; }
//         ),
//         budget,
//       ])) || deterministicReport();
//
//     send({ type: "result", scan: scanResult, report });
//     controller.close();
//
// We use the REAL setTimeout/clearTimeout under vi.useFakeTimers() so the 14000 ms
// budget is controllable, and we spy on clearTimeout to assert cancellation.
// Only the report payloads are stand-ins.
// ---------------------------------------------------------------------------

// Mirrors the (module-private) ANALYSIS_BUDGET_MS constant in scan.js. Documented
// here because the production constant is not exported; if scan.js changes the
// budget, this mirror should track it.
const ANALYSIS_BUDGET_MS = 14000;

// Distinct stand-in reports so we can assert WHICH report the single Result_Event
// carried (referential identity proves "either ... but never both").
const AI_REPORT = Object.freeze({ _source: "llm", kind: "ai-pipeline-report" });
const DETERMINISTIC_REPORT = Object.freeze({ _source: "fallback", kind: "deterministic-report" });

// Faithful reproduction of scan.js's stream `send` + `controller.close()`:
// `send` enqueues onto the stream, but any enqueue after the stream is closed
// throws inside the controller and is swallowed by scan.js's try/catch. So a late
// event after close is silently dropped — never recorded.
function makeStream() {
  const events = [];
  let closed = false;
  const send = (obj) => {
    try {
      if (closed) throw new Error("stream closed"); // models a closed controller
      events.push(obj);
    } catch (_) {
      /* swallowed, exactly like scan.js's send() */
    }
  };
  const close = () => {
    closed = true;
  };
  return { events, send, close };
}

// Faithful reproduction of scan.js's budget race and the SINGLE result send,
// line-for-line. `aiPipeline` is the awaitable pipeline; `deterministicReport`
// is the safety-net factory. Returns the promise that settles once the
// Result_Event has been sent (so the caller can await completion).
function runResultRace({ aiPipeline, send, close, deterministicReport }) {
  const analysisBudget = ANALYSIS_BUDGET_MS;
  let budgetTimer;
  const budget = new Promise((resolve) => {
    budgetTimer = setTimeout(() => resolve(null), analysisBudget);
  });

  return Promise.race([
    aiPipeline.then(
      (r) => {
        clearTimeout(budgetTimer);
        return r;
      },
      () => {
        clearTimeout(budgetTimer);
        return null;
      }
    ),
    budget,
  ]).then((raced) => {
    const report = raced || deterministicReport();
    send({ type: "result", report }); // the one and only Result_Event
    close();
    return report;
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("Feature: deterministic-fallback — budget race timing (fake timers)", () => {
  // (a) Pipeline pending past 14000 ms → the budget timer wins and the scan
  //     ships the Deterministic_Report (Requirements 5.1, 5.2).
  it("ships the Deterministic_Report when the pipeline is still pending past the 14000 ms budget", async () => {
    vi.useFakeTimers();
    const { events, send, close } = makeStream();

    // A pipeline that resolves only LONG after the budget (never within it).
    const aiPipeline = new Promise((resolve) => {
      setTimeout(() => resolve(AI_REPORT), ANALYSIS_BUDGET_MS + 5000);
    });

    const racePromise = runResultRace({
      aiPipeline,
      send,
      close,
      deterministicReport: () => DETERMINISTIC_REPORT,
    });

    // Advance exactly to the budget boundary: the timer fires, the race resolves
    // to null, and `|| deterministicReport()` supplies the fallback.
    await vi.advanceTimersByTimeAsync(ANALYSIS_BUDGET_MS);
    const report = await racePromise;

    const resultEvents = events.filter((e) => e.type === "result");
    expect(resultEvents).toHaveLength(1);
    expect(resultEvents[0].report).toBe(DETERMINISTIC_REPORT);
    expect(report).toBe(DETERMINISTIC_REPORT);
  });

  // (b) Pipeline resolving first → the scan ships the AI report AND cancels the
  //     budget timer via clearTimeout (Requirements 5.6).
  it("ships the AI report and calls clearTimeout when the pipeline resolves before the budget", async () => {
    vi.useFakeTimers();
    const { events, send, close } = makeStream();
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");

    // A pipeline that resolves well within the budget.
    const aiPipeline = new Promise((resolve) => {
      setTimeout(() => resolve(AI_REPORT), 3000);
    });

    const racePromise = runResultRace({
      aiPipeline,
      send,
      close,
      deterministicReport: () => DETERMINISTIC_REPORT,
    });

    // Advance only to the pipeline's resolution (still inside the budget).
    await vi.advanceTimersByTimeAsync(3000);
    const report = await racePromise;

    const resultEvents = events.filter((e) => e.type === "result");
    expect(resultEvents).toHaveLength(1);
    expect(resultEvents[0].report).toBe(AI_REPORT);
    expect(report).toBe(AI_REPORT);

    // The pipeline's fulfilment handler cancelled the budget timer.
    expect(clearSpy).toHaveBeenCalled();
  });

  // (c) Pipeline rejecting within budget → the rejection handler returns null,
  //     the race yields null, and the scan ships the Deterministic_Report
  //     (Requirements 5.3); the budget timer is cleared in the reject branch too.
  it("ships the Deterministic_Report when the pipeline rejects within the budget", async () => {
    vi.useFakeTimers();
    const { events, send, close } = makeStream();
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");

    // A pipeline that rejects before the budget elapses.
    const aiPipeline = new Promise((_resolve, reject) => {
      setTimeout(() => reject(new Error("ai pipeline rejected")), 2000);
    });

    const racePromise = runResultRace({
      aiPipeline,
      send,
      close,
      deterministicReport: () => DETERMINISTIC_REPORT,
    });

    await vi.advanceTimersByTimeAsync(2000);
    const report = await racePromise;

    const resultEvents = events.filter((e) => e.type === "result");
    expect(resultEvents).toHaveLength(1);
    expect(resultEvents[0].report).toBe(DETERMINISTIC_REPORT);
    expect(report).toBe(DETERMINISTIC_REPORT);

    // The rejection handler cancelled the budget timer (clearTimeout in onRejected).
    expect(clearSpy).toHaveBeenCalled();
  });

  // (d) A timer firing AFTER the Result_Event was already sent produces no
  //     additional event: the late send hits a closed stream and is swallowed
  //     (Requirements 5.7).
  it("produces no additional event when a timer fires after the result was sent", async () => {
    vi.useFakeTimers();
    const { events, send, close } = makeStream();

    // The pipeline resolves first (inside budget). After the result is shipped,
    // the still-pending budget timer would normally fire — but its effect must
    // be inert. We model scan.js's "pipeline keeps running; later sends hit a
    // closed stream and are ignored" by attaching a late send to a timer that
    // fires AFTER the result.
    const aiPipeline = new Promise((resolve) => {
      setTimeout(() => resolve(AI_REPORT), 3000);
    });

    // A late, post-result timer that attempts a second send (e.g. a budget timer
    // that was not cancelled, or trailing pipeline progress). It must be a no-op
    // against the closed stream.
    setTimeout(() => {
      send({ type: "result", report: DETERMINISTIC_REPORT });
    }, ANALYSIS_BUDGET_MS + 1000);

    const racePromise = runResultRace({
      aiPipeline,
      send,
      close,
      deterministicReport: () => DETERMINISTIC_REPORT,
    });

    // Resolve the pipeline and ship the single Result_Event (stream then closes).
    await vi.advanceTimersByTimeAsync(3000);
    const report = await racePromise;
    expect(report).toBe(AI_REPORT);

    // Now advance well past the late timer so it fires against the closed stream.
    await vi.advanceTimersByTimeAsync(2 * ANALYSIS_BUDGET_MS);

    // Still exactly one Result_Event — the late fire added nothing.
    const resultEvents = events.filter((e) => e.type === "result");
    expect(resultEvents).toHaveLength(1);
    expect(resultEvents[0].report).toBe(AI_REPORT);
    expect(events).toHaveLength(1);
  });
});
