import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// vi.mock MUST be at the top so vitest hoists it above the ./analysis.js import,
// making callLLMJson an in-memory auto-mocked vi.fn (no network access).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import {
  baseReportArb,
  domainArb,
  createLLMJsonMock,
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 3: cleanScan reflects the absence of
// scored findings
//
// For any base report, the payload's `cleanScan` SHALL be `true` if and only if
// the filtered scored-findings list is empty (i.e. cleanScan === true  <=>
// payload.findings.length === 0).
//
// **Validates: Requirements 3.5, 6.1, 6.2**
//
// callLLMJson is stubbed so every iteration runs fully in-memory: we resolve it
// with a benign narrative and read back the serialized payload Pass 3 sent.
// ---------------------------------------------------------------------------

describe("Feature: exploit-narrative, Property 3: cleanScan reflects the absence of scored findings", () => {
  const llm = createLLMJsonMock(callLLMJson);

  beforeEach(() => {
    llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });
  });

  it("sets payload.cleanScan true iff payload.findings is empty", async () => {
    await fc.assert(
      fc.asyncProperty(baseReportArb, domainArb, async (report, domain) => {
        llm.reset();
        llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });

        await runPass3(report, domain);

        const payload = llm.lastPayload();

        // cleanScan must be a strict boolean.
        expect(typeof payload.cleanScan).toBe("boolean");

        // The biconditional: cleanScan === true  <=>  findings.length === 0.
        expect(payload.cleanScan).toBe(payload.findings.length === 0);
      }),
      { numRuns: 200 }
    );
  });
});
