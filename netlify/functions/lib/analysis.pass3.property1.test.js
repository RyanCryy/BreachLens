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
// Feature: exploit-narrative, Property 1: Payload includes exactly the five
// top-level fields
//
// For any base report and domain, the payload Pass 3 builds SHALL have exactly
// the top-level keys `domain`, `overallRiskLevel`, `overallRiskScore`,
// `cleanScan`, and `findings`, and no others.
//
// **Validates: Requirements 3.1**
//
// `runPass3(baseReport, domain)` is driven with generated base reports; the
// mocked `callLLMJson` captures the args so we can parse the JSON payload Pass 3
// embedded in the user message and assert on its exact top-level key set.
// ---------------------------------------------------------------------------

const EXPECTED_KEYS = [
  "domain",
  "overallRiskLevel",
  "overallRiskScore",
  "cleanScan",
  "findings",
];

describe("Feature: exploit-narrative, Property 1: Payload includes exactly the five top-level fields", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("builds a payload whose top-level keys are exactly the five expected fields", async () => {
    await fc.assert(
      fc.asyncProperty(baseReportArb, domainArb, async (report, domain) => {
        // A successful resolve keeps runPass3 on its happy path; the return
        // value is irrelevant to payload construction.
        llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });

        await runPass3(report, domain);

        const payload = llm.lastPayload();
        const keys = Object.keys(payload).sort();

        // Exactly the five expected top-level fields, no more, no fewer.
        expect(keys).toEqual([...EXPECTED_KEYS].sort());
      }),
      { numRuns: 200 }
    );
  });
});
