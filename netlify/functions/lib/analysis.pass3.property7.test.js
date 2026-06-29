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
} from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Property 7: Field names are stable
//
// For any successful run, the returned object SHALL use exactly the keys
// `attackScenario` and `ifUnaddressed` and SHALL NOT contain keys `scenario` or
// `trajectory`.
//
// **Validates: Requirements 4.5**
//
// The model boundary (`callLLMJson`) is mocked so each iteration runs fully
// in-memory. To guarantee a successful (non-null) run, the stubbed LLM resolves
// with a response carrying at least one non-empty narrative field. The raw LLM
// response also includes the legacy `scenario`/`trajectory` keys (and other
// noise) to confirm Pass 3 never echoes them onto its output.
// ---------------------------------------------------------------------------

// A string that is guaranteed non-empty after trimming, so the run always
// succeeds (returns a non-null object rather than null).
const nonEmptyTrimmedArb = fc
  .string({ minLength: 1 })
  .map((s) => `x${s}`); // prefix with a non-whitespace char so trim() is non-empty

// A field value that may be a non-empty string, empty/whitespace-only, absent,
// or a non-string — anything goes for the "other" field.
const anyFieldValueArb = fc.oneof(
  fc.string(),
  fc.constantFrom("", "   ", "\t"),
  fc.integer(),
  fc.constant(null)
);

// A raw LLM response guaranteed to yield a successful (non-null) Pass 3 result:
// at least one of attackScenario/ifUnaddressed is a non-empty trimmed string.
// We also inject the legacy `scenario`/`trajectory` keys and an `extra` key to
// prove Pass 3 builds its own two-key object and never carries those through.
const successfulResponseArb = fc.oneof(
  // attackScenario guaranteed non-empty.
  fc.record({
    attackScenario: nonEmptyTrimmedArb,
    ifUnaddressed: anyFieldValueArb,
    scenario: fc.string(),
    trajectory: fc.string(),
    extra: fc.string(),
  }),
  // ifUnaddressed guaranteed non-empty.
  fc.record({
    attackScenario: anyFieldValueArb,
    ifUnaddressed: nonEmptyTrimmedArb,
    scenario: fc.string(),
    trajectory: fc.string(),
    extra: fc.string(),
  })
);

describe("Feature: exploit-narrative, Property 7: Field names are stable", () => {
  const llm = createLLMJsonMock(callLLMJson);

  it("returns exactly { attackScenario, ifUnaddressed } and never scenario/trajectory", async () => {
    await fc.assert(
      fc.asyncProperty(
        successfulResponseArb,
        baseReportArb,
        domainArb,
        async (response, report, domain) => {
          // Stub the LLM return for this iteration with a guaranteed-success shape.
          llm.resolveWith(response);

          const result = await runPass3(report, domain);

          // The run is successful: a non-null object.
          expect(result).not.toBeNull();
          expect(typeof result).toBe("object");

          // Exactly the two stable narrative keys, no others.
          expect(Object.keys(result).sort()).toEqual([
            "attackScenario",
            "ifUnaddressed",
          ]);

          // The stable field names are present as own properties.
          expect(Object.prototype.hasOwnProperty.call(result, "attackScenario")).toBe(true);
          expect(Object.prototype.hasOwnProperty.call(result, "ifUnaddressed")).toBe(true);

          // The legacy field names are never present, even when the raw LLM
          // response carried them.
          expect(Object.prototype.hasOwnProperty.call(result, "scenario")).toBe(false);
          expect(Object.prototype.hasOwnProperty.call(result, "trajectory")).toBe(false);
        }
      ),
      { numRuns: 200 }
    );
  });
});
