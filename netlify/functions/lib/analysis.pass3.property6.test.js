import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST run before the `./analysis.js` import so vitest hoists it above
// the module graph and `callLLMJson` is replaced by an auto-mocked vi.fn().
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import {
  baseReportArb,
  domainArb,
  createLLMJsonMock,
  abortError,
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 6: Failure always yields null, never a
// fabricated narrative
//
// For any failure mode of the LLM call (thrown error, timeout/abort, or parse
// failure after the single retry), Pass 3 SHALL return `null` and SHALL NOT
// produce any deterministic fallback narrative text.
//
// **Validates: Requirements 7.1, 7.2, 7.3, 7.5, 6.6, 6.7**
//
// The model boundary (`callLLMJson`) is mocked so each iteration runs fully
// in-memory: the controller makes the stubbed LLM reject across the three
// documented failure shapes, then we drive `runPass3(baseReport, domain)` and
// assert it degrades to omission (returns `null`) rather than fabricating a
// templated narrative.
// ---------------------------------------------------------------------------

// The documented failure modes from the design's Error Handling table:
//   - "throw": LLM throws (network / HTTP error)               (Req 7.1)
//   - "abort": request aborts on the 10 s timeout              (Req 7.2)
//   - "parse": JSON parse failure after the single retry       (Req 7.3)
// Each carries a factory producing the rejection error so each iteration gets a
// fresh error instance with a representative message.
const failureModeArb = fc.oneof(
  fc.record({
    kind: fc.constant("throw"),
    message: fc.string(),
  }),
  fc.record({
    kind: fc.constant("abort"),
    message: fc.string(),
  }),
  fc.record({
    kind: fc.constant("parse"),
    message: fc.string(),
  })
);

function makeError({ kind, message }) {
  if (kind === "abort") {
    return abortError(message || undefined);
  }
  if (kind === "parse") {
    // Mirror a JSON.parse failure propagating out of callLLMJson after its one
    // stricter-instruction retry also fails to parse.
    return new SyntaxError(message || "Unexpected token in JSON");
  }
  // Generic thrown error (network / HTTP).
  return new Error(message || "LLM failure");
}

describe("Feature: exploit-narrative, Property 6: Failure always yields null, never a fabricated narrative", () => {
  const llm = createLLMJsonMock(callLLMJson);

  it("returns null for every LLM failure mode and never fabricates narrative text", async () => {
    await fc.assert(
      fc.asyncProperty(
        failureModeArb,
        baseReportArb,
        domainArb,
        async (failureMode, report, domain) => {
          const error = makeError(failureMode);

          // Drive the chosen rejection shape through the controller helpers.
          if (failureMode.kind === "abort") {
            llm.rejectAbort(failureMode.message || undefined);
          } else {
            llm.rejectWith(error);
          }

          const result = await runPass3(report, domain);

          // Failure always converges on the single `null` outcome — there is no
          // deterministic fallback narrative (unlike Pass 2).
          expect(result).toBeNull();

          // And the LLM was actually invoked (the failure happened on the call,
          // not before it), confirming this is the failure path.
          expect(llm.callCount()).toBeGreaterThanOrEqual(1);
        }
      ),
      { numRuns: 200 }
    );
  });
});
