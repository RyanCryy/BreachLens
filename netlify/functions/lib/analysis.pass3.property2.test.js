import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` must be hoisted above the `./analysis.js` import so that runPass3's
// `callLLMJson` dependency is the auto-mocked vi.fn (no network, fully in-memory).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import {
  baseReportArb,
  domainArb,
  createLLMJsonMock,
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 2: Payload findings are exactly the
// scored findings, correctly mapped
//
// For any base report whose `findings` is an arbitrary mix of scored and
// excluded findings (varying `severity`, including `"info"`/mixed case, and
// varying `informational` flags), the payload `findings` array SHALL contain
// one entry for each finding with `severity !== "info"` AND falsy
// `informational` and no others, preserving order, where each entry has exactly
// the keys `title`, `severity`, `explanation`.
//
// **Validates: Requirements 3.2, 3.3, 3.6**
//
// `runPass3` builds the payload synchronously before calling `callLLMJson`. We
// stub that call (resolving with a fixed narrative) and read the serialized
// payload it captured. The expected filter mirrors production exactly:
//   f.severity !== "info" && !f.informational   (case-sensitive lowercase "info")
// ---------------------------------------------------------------------------

const EXPECTED_KEYS = ["title", "severity", "explanation"];

describe("Feature: exploit-narrative, Property 2: Payload findings are exactly the scored findings, correctly mapped", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
    // Any non-empty narrative keeps runPass3 on the success path; the return
    // value is irrelevant to payload-shape assertions.
    llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });
  });

  it("payload.findings equals the scored findings in original order, mapped to exactly {title, severity, explanation}", async () => {
    await fc.assert(
      fc.asyncProperty(baseReportArb, domainArb, async (report, domain) => {
        llm.reset();
        llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });

        await runPass3(report, domain);

        const payload = llm.lastPayload();

        // The expected scored list, computed with the exact production filter.
        const expectedScored = report.findings.filter(
          (f) => f.severity !== "info" && !f.informational
        );

        // Same count: exactly the scored findings, no more, no fewer.
        expect(Array.isArray(payload.findings)).toBe(true);
        expect(payload.findings).toHaveLength(expectedScored.length);

        // When every finding is excluded, findings is the empty array (Req 3.6).
        if (expectedScored.length === 0) {
          expect(payload.findings).toEqual([]);
        }

        // Order-preserving, value-correct, exact-key mapping for each entry.
        payload.findings.forEach((entry, i) => {
          const src = expectedScored[i];

          // Exactly the three mapped keys, no others (Req 3.3).
          expect(Object.keys(entry).sort()).toEqual([...EXPECTED_KEYS].sort());

          // Values copied straight from the source scored finding, in order.
          expect(entry.title).toBe(src.title);
          expect(entry.severity).toBe(src.severity);
          expect(entry.explanation).toBe(src.explanation);
        });

        // No excluded finding leaks through: every payload entry corresponds to
        // a finding that passes the filter.
        payload.findings.forEach((entry) => {
          expect(entry.severity).not.toBe("info");
        });
      }),
      { numRuns: 200 }
    );
  });
});
