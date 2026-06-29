import { describe, it, expect, beforeEach, vi } from "vitest";

// `vi.mock` MUST be hoisted above the `../scan.js` import so the handler's
// `runScan`/`RESULT_TYPE` bindings resolve to this controlled module. The mock
// path is stated relative to THIS test file (`./scan-engine.js`); it resolves to
// the same absolute module that `scan.js` imports as `./lib/scan-engine.js`, so
// the handler picks up the override. We keep every other export real via
// `importOriginal` so `RESULT_TYPE` and `defaultDeps` keep their genuine values
// (the handler reads `RESULT_TYPE.RESOLUTION_FAILURE` and spreads `defaultDeps`).
vi.mock("./scan-engine.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, runScan: vi.fn() };
});

import scan from "../scan.js";
import { runScan, RESULT_TYPE } from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — Example/edge test
// Requirement 5.9: "WHEN a fatal error is thrown inside the stream handler THEN
//   THE Scanner SHALL emit a Stream_Error_Event ({ type: \"error\", message })
//   and close the stream (no Result_Event)."
// Requirement 7.2: "Fatal handler errors and DNS-resolution failures emit a
//   Stream_Error_Event instead of a report, so _source: \"error\" is never
//   produced by the backend."
//
// This is an example/edge test (not a numbered Property), so it carries no
// "Property N" tag. It exercises the two backend error paths that emit a
// Stream_Error_Event rather than a Result_Event:
//
//   1. DNS-resolution failure — `runScan` resolves with
//      { type: RESULT_TYPE.RESOLUTION_FAILURE, message }; the handler forwards
//      { type: "error", message } and closes the stream.
//   2. Fatal handler error — `runScan` throws; the outer try/catch sends
//      { type: "error", message: "The scan failed unexpectedly. Please try again." }
//      and closes the stream.
//
// In both cases we assert: exactly one { type: "error", message } event, no
// { type: "result" } event, and that nothing in the stream carries
// _source: "error" (there is no report at all).
// ---------------------------------------------------------------------------

const DOMAIN = "example.com";

// Build a valid POST Request the handler will accept (passes domain validation),
// then drive the real default export and collect the streamed ndjson events.
async function runHandler() {
  const req = new Request("https://scanner.test/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: DOMAIN }),
  });

  const res = await scan(req);
  const text = await res.text(); // drains the ReadableStream to completion

  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

// Shared assertions for an error-path stream: exactly one error event carrying a
// non-empty message, no result event, and no _source: "error" anywhere.
function assertErrorStream(events, expectedMessage) {
  const errorEvents = events.filter((e) => e && e.type === "error");
  const resultEvents = events.filter((e) => e && e.type === "result");

  expect(errorEvents).toHaveLength(1);
  expect(typeof errorEvents[0].message).toBe("string");
  expect(errorEvents[0].message.length).toBeGreaterThan(0);
  expect(errorEvents[0].message).toBe(expectedMessage);

  // No Result_Event (and therefore no report) is ever emitted on an error path.
  expect(resultEvents).toHaveLength(0);

  // Defensive: nothing in the stream — event or nested report — carries the
  // dead "error" source tag the backend never produces (Requirement 7.2).
  const hasErrorSource = events.some(
    (e) => e && (e._source === "error" || (e.report && e.report._source === "error"))
  );
  expect(hasErrorSource).toBe(false);
}

describe("Feature: deterministic-fallback — fatal handler error & DNS-resolution failure emit a Stream_Error_Event (Requirements 5.9, 7.2)", () => {
  beforeEach(() => {
    runScan.mockReset();
  });

  it("DNS-resolution failure: forwards { type: \"error\", message } and closes without a Result_Event", async () => {
    const message =
      `We couldn't find "${DOMAIN}". Double-check the spelling — it may not exist or may not be publicly resolvable.`;
    runScan.mockResolvedValue({ type: RESULT_TYPE.RESOLUTION_FAILURE, message });

    const events = await runHandler();

    assertErrorStream(events, message);
  });

  it("fatal handler error: a thrown runScan triggers the generic Stream_Error_Event and closes without a Result_Event", async () => {
    runScan.mockRejectedValue(new Error("boom — something fatal in the engine"));

    const events = await runHandler();

    assertErrorStream(events, "The scan failed unexpectedly. Please try again.");
  });
});
