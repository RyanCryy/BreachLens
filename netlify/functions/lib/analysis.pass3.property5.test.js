import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST run before the `./analysis.js` import so vitest hoists it above
// the module graph and `callLLMJson` is replaced by an auto-mocked vi.fn().
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import {
  llmResponseArb,
  baseReportArb,
  domainArb,
  createLLMJsonMock,
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 5: Output shape and null contract
//
// For any LLM JSON response, after Pass 3 trims `attackScenario` and
// `ifUnaddressed` (coercing absent or non-string values to `""`): if both are
// empty the result SHALL be `null`; otherwise the result SHALL be an object with
// exactly the keys `attackScenario` and `ifUnaddressed`, both strings with no
// leading or trailing whitespace.
//
// **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 7.4, 7.6**
//
// The model boundary (`callLLMJson`) is mocked so each iteration runs fully
// in-memory: the controller resolves the stubbed LLM with a generated
// `llmResponseArb` value, then we drive `runPass3(baseReport, domain)` and assert
// the trim / coercion / null contract on its return value.
// ---------------------------------------------------------------------------

// Mirror of runPass3's coercion: a string is trimmed, anything else becomes "".
function expectedTrimmed(value) {
  return typeof value === "string" ? value.trim() : "";
}

describe("Feature: exploit-narrative, Property 5: Output shape and null contract", () => {
  const llm = createLLMJsonMock(callLLMJson);

  it("returns null when both fields are empty after trim/coercion, else exactly the two trimmed string fields", async () => {
    await fc.assert(
      fc.asyncProperty(
        llmResponseArb,
        baseReportArb,
        domainArb,
        async (response, report, domain) => {
          // Stub the LLM return for this iteration.
          llm.resolveWith(response);

          const result = await runPass3(report, domain);

          const expectedAttack = expectedTrimmed(response.attackScenario);
          const expectedIf = expectedTrimmed(response.ifUnaddressed);

          if (!expectedAttack && !expectedIf) {
            // Both empty after trim/coercion -> null contract.
            expect(result).toBeNull();
            return;
          }

          // Otherwise: an object with EXACTLY the two narrative keys.
          expect(result).not.toBeNull();
          expect(typeof result).toBe("object");
          expect(Object.keys(result).sort()).toEqual([
            "attackScenario",
            "ifUnaddressed",
          ]);

          // Both values are strings...
          expect(typeof result.attackScenario).toBe("string");
          expect(typeof result.ifUnaddressed).toBe("string");

          // ...with no leading/trailing whitespace...
          expect(result.attackScenario).toBe(result.attackScenario.trim());
          expect(result.ifUnaddressed).toBe(result.ifUnaddressed.trim());

          // ...and equal to the expected trimmed/coerced values.
          expect(result.attackScenario).toBe(expectedAttack);
          expect(result.ifUnaddressed).toBe(expectedIf);
        }
      ),
      { numRuns: 200 }
    );
  });
});
