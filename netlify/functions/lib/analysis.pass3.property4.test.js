import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be at the top of the module so vitest hoists it above the
// `./analysis.js` import — this auto-mocks `callLLMJson` to a `vi.fn()` so Pass 3
// never touches the network and every iteration runs fully in-memory.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import {
  baseReportArb,
  domainArb,
  createLLMJsonMock,
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 4: Risk fields are copied from the base
// report
//
// For any base report, the payload's `overallRiskLevel` SHALL equal the
// report's `riskLevel` and the payload's `overallRiskScore` SHALL equal the
// report's `overallRiskScore`.
//
// **Validates: Requirements 3.4**
//
// `runPass3(baseReport, domain)` is driven with generated base reports; the
// mocked `callLLMJson` captures the args so we can parse the JSON payload Pass 3
// embedded in the user message and assert its risk fields are copied verbatim
// from the base report.
//
// We constrain `overallRiskScore` to a finite number: Pass 3 serializes the
// payload via `JSON.stringify` (Requirement 3.7) and the captured payload is
// read back through `JSON.parse`, so a non-finite score (±Infinity) would be
// coerced to `null` by JSON itself — an out-of-input-space value (a real risk
// score is always finite) rather than a copy defect.
// ---------------------------------------------------------------------------

// Build on the shared base report arbitrary, keeping only finite risk scores so
// the JSON round-trip used to capture the payload is lossless.
const finiteBaseReportArb = baseReportArb.filter((r) =>
  Number.isFinite(r.overallRiskScore)
);

describe("Feature: exploit-narrative, Property 4: Risk fields are copied from the base report", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("copies overallRiskLevel from report.riskLevel and overallRiskScore from report.overallRiskScore", async () => {
    await fc.assert(
      fc.asyncProperty(finiteBaseReportArb, domainArb, async (report, domain) => {
        // A successful resolve keeps runPass3 on its happy path; the return
        // value is irrelevant to payload construction.
        llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });

        await runPass3(report, domain);

        const payload = llm.lastPayload();

        // Risk fields are copied verbatim from the base report. The score is
        // compared with numeric equality (`===`), which treats -0 and +0 as
        // equal — the spec requires the score to "equal" the report's, and the
        // JSON serialization used to capture the payload normalizes -0 to +0.
        expect(payload.overallRiskLevel).toBe(report.riskLevel);
        expect(payload.overallRiskScore === report.overallRiskScore).toBe(true);
      }),
      { numRuns: 200 }
    );
  });
});
