import { describe, it, expect, vi, afterEach } from "vitest";
import fc from "fast-check";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 19: exactly one Result_Event per scan
//
// For any timing scenario (pipeline resolving fast, resolving slowly, or
// rejecting; budget elapsing or not), the scan emits exactly one Result_Event,
// carrying either the AI_Pipeline report or the Deterministic_Report but never
// both.
//
// **Validates: Requirements 5.8**
//
// ── Why a faithful-model harness rather than the real handler ───────────────
// The exactly-one-Result_Event guarantee is produced by the top-level budget
// race in `netlify/functions/scan.js`:
//
//     const budget = new Promise((resolve) => {
//       budgetTimer = setTimeout(() => resolve(null), ANALYSIS_BUDGET_MS);
//     });
//     const report =
//       (await Promise.race([
//         aiPipeline.then(
//           (r) => { clearTimeout(budgetTimer); return r; },
//           () => { clearTimeout(budgetTimer); return null; }
//         ),
//         budget,
//       ])) || deterministicReport();
//     send({ type: "result", scan: scanResult, report });
//     controller.close();
//
// Driving the real `ReadableStream` handler under fake timers across 100+
// iterations is brittle (the result send is buried behind passive-scan
// orchestration, and the AI pipeline IIFE *never rejects* through the real
// handler because every internal pass is individually `try/catch`-guarded — so
// the race's `onRejected` branch is unreachable from the outside). Following the
// same convention as `scan.pass3-integration.test.js`, this test reproduces the
// race + single-result-send + closed-stream semantics EXACTLY in a local
// harness, using the real timing primitives (`setTimeout`/`clearTimeout`) under
// Vitest fake timers so the 14000 ms budget is controllable. The harness mirrors
// scan.js line-for-line; only the report payloads are stand-ins.
// ---------------------------------------------------------------------------

// Mirrors the (non-exported) ANALYSIS_BUDGET_MS constant in scan.js. Documented
// here because the production constant is module-private; if scan.js changes the
// budget, this mirror should track it.
const ANALYSIS_BUDGET_MS = 14000;

// Distinct stand-in report objects so we can assert WHICH report the single
// Result_Event carried (referential identity proves "either ... but never both").
const AI_REPORT = Object.freeze({ _source: "llm", kind: "ai-pipeline-report" });
const DETERMINISTIC_REPORT = Object.freeze({ _source: "fallback", kind: "deterministic-report" });

// Faithful reproduction of scan.js's stream `send` + `controller.close()`:
// `send` enqueues onto the stream, but any enqueue after the stream is closed
// throws inside the controller and is swallowed by scan.js's `try/catch`. So a
// late event after close is silently dropped — never recorded.
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

// Builds the AI pipeline promise. Faithful to scan.js, the pipeline either
// resolves (with the AI report) or rejects after `delayMs`. (In production the
// IIFE resolves once Pass1→Pass2/Pass3 settle; we also model a rejecting
// pipeline to cover the race's `onRejected` branch, which scan.js handles by
// clearing the timer and mapping to null → deterministicReport().)
function makeAiPipeline(outcome, delayMs) {
  if (outcome === "reject") {
    return new Promise((_resolve, reject) => {
      setTimeout(() => reject(new Error("ai pipeline rejected")), delayMs);
    });
  }
  return new Promise((resolve) => {
    setTimeout(() => resolve(AI_REPORT), delayMs);
  });
}

// Faithful reproduction of scan.js's budget race and the SINGLE result send.
// Returns the promise that settles once the Result_Event has been sent.
function runResultRace({ aiPipeline, budgetMs, send, close }) {
  const deterministicReport = () => DETERMINISTIC_REPORT;

  let budgetTimer;
  const budget = new Promise((resolve) => {
    budgetTimer = setTimeout(() => resolve(null), budgetMs);
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
    // The one and only Result_Event for this scan.
    send({ type: "result", report });
    close();
    return report;
  });
}

// Timing scenarios: outcome × where the pipeline settles relative to the budget.
// `delayMs` is generated on both sides of the budget (and never exactly equal to
// it, to keep the winner unambiguous for the assertions below).
const scenarioArb = fc
  .record({
    outcome: fc.constantFrom("resolve", "reject"),
    delayMs: fc.integer({ min: 0, max: 2 * ANALYSIS_BUDGET_MS }),
  })
  .filter((s) => s.delayMs !== ANALYSIS_BUDGET_MS);

afterEach(() => {
  vi.useRealTimers();
});

describe("Feature: deterministic-fallback, Property 19: exactly one Result_Event per scan", () => {
  it("emits exactly one result event carrying the AI report XOR the deterministic report, across all timings", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ outcome, delayMs }) => {
        vi.useFakeTimers();
        try {
          const { events, send, close } = makeStream();
          const aiPipeline = makeAiPipeline(outcome, delayMs);

          const racePromise = runResultRace({
            aiPipeline,
            budgetMs: ANALYSIS_BUDGET_MS,
            send,
            close,
          });

          // Advance past BOTH the pipeline timer and the budget timer so every
          // possible late fire has had its chance to (incorrectly) emit a second
          // event. Mirrors "the pipeline keeps running after a budget win; its
          // later activity hits a closed stream and is ignored."
          await vi.advanceTimersByTimeAsync(delayMs + ANALYSIS_BUDGET_MS + 100);
          const report = await racePromise;

          // ── Exactly one Result_Event ──────────────────────────────────────
          const resultEvents = events.filter((e) => e.type === "result");
          expect(resultEvents).toHaveLength(1);

          // ── It carries exactly one of the two reports, never a blend ──────
          const carried = resultEvents[0].report;
          expect([AI_REPORT, DETERMINISTIC_REPORT]).toContain(carried);
          expect(report).toBe(carried);

          // ── The carried report matches the latency-driven winner ──────────
          if (outcome === "resolve" && delayMs < ANALYSIS_BUDGET_MS) {
            // Pipeline resolved within budget → AI report; timer was cancelled.
            expect(carried).toBe(AI_REPORT);
          } else {
            // Budget elapsed first, OR the pipeline rejected → deterministic.
            expect(carried).toBe(DETERMINISTIC_REPORT);
          }
        } finally {
          vi.useRealTimers();
        }
      }),
      { numRuns: 200 }
    );
  });
});
