import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be at the top of the module so vitest hoists it above the
// `./analysis.js` import — this auto-mocks `callLLMJson` to a `vi.fn()` so
// Pass 3 never touches the network and every iteration runs fully in-memory.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import { createLLMJsonMock } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 16: one non-empty narrative field
// means present
//
// For any Pass 3 response in which exactly one of `attackScenario` /
// `ifUnaddressed` is non-empty (the other empty, whitespace-only, or absent),
// `runPass3` returns an object carrying BOTH trimmed values — the narrative is
// treated as present.
//
// **Validates: Requirements 4.3**
//
// `runPass3(report, domain)` is driven with a generated base report and a
// mocked `callLLMJson` resolving with exactly one non-empty narrative field. We
// assert the result is a non-null object whose `attackScenario` and
// `ifUnaddressed` are each the trimmed form of the corresponding response field
// (the empty/absent side trimming to "").
// ---------------------------------------------------------------------------

// A base report as consumed by runPass3 (it only reads `findings`, `riskLevel`,
// and `overallRiskScore`). Content is irrelevant to the narrative contract.
const findingArb = fc.record(
  {
    title: fc.string(),
    severity: fc.constantFrom("critical", "high", "medium", "low", "info"),
    explanation: fc.string(),
  },
  { requiredKeys: ["title", "severity", "explanation"] }
);

const baseReportArb = fc.record({
  findings: fc.array(findingArb, { maxLength: 8 }),
  riskLevel: fc.constantFrom("Low", "Medium", "High", "Critical"),
  overallRiskScore: fc.integer({ min: 0, max: 100 }),
});

const domainArb = fc.domain ? fc.domain() : fc.string({ minLength: 1 });

// A value whose trimmed form is guaranteed non-empty, optionally surrounded by
// whitespace so we exercise runPass3's `.trim()`.
const whitespacePad = fc.constantFrom("", " ", "  ", "\t", "\n ", " \n\t ");
const nonEmptyNarrativeArb = fc
  .tuple(
    whitespacePad,
    fc.string({ minLength: 1, maxLength: 80 }).filter((s) => s.trim().length > 0),
    whitespacePad
  )
  .map(([pre, core, post]) => `${pre}${core}${post}`);

// The "other" field: empty, whitespace-only, or absent (modeled as `undefined`,
// which we omit from the response object so the key is genuinely absent).
const emptyOrAbsentArb = fc.constantFrom("", "   ", "\t", "\n  \n", undefined);

describe("Feature: deterministic-fallback, Property 16: one non-empty narrative field means present", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("returns both trimmed values when exactly one narrative field is non-empty", async () => {
    await fc.assert(
      fc.asyncProperty(
        baseReportArb,
        domainArb,
        fc.boolean(), // which field is the non-empty one
        nonEmptyNarrativeArb,
        emptyOrAbsentArb,
        async (report, domain, attackIsNonEmpty, nonEmptyValue, emptyValue) => {
          // Build the raw LLM response with exactly one non-empty field. The
          // other field is empty/whitespace, or omitted entirely when absent.
          const response = {};
          if (attackIsNonEmpty) {
            response.attackScenario = nonEmptyValue;
            if (emptyValue !== undefined) response.ifUnaddressed = emptyValue;
          } else {
            response.ifUnaddressed = nonEmptyValue;
            if (emptyValue !== undefined) response.attackScenario = emptyValue;
          }

          llm.resolveWith(response);

          const result = await runPass3(report, domain);

          // Narrative is present: a non-null object carrying both keys.
          expect(result).not.toBeNull();
          expect(result).toMatchObject({
            attackScenario: expect.any(String),
            ifUnaddressed: expect.any(String),
          });

          // Each field is the trimmed form of its source; the empty/absent side
          // trims to "".
          const expectedNonEmpty = nonEmptyValue.trim();
          const expectedEmpty = ""; // empty / whitespace / absent -> ""
          if (attackIsNonEmpty) {
            expect(result.attackScenario).toBe(expectedNonEmpty);
            expect(result.ifUnaddressed).toBe(expectedEmpty);
          } else {
            expect(result.ifUnaddressed).toBe(expectedNonEmpty);
            expect(result.attackScenario).toBe(expectedEmpty);
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
