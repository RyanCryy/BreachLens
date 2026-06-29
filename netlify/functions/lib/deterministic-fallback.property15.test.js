import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` must be hoisted above the `./analysis.js` import so that runPass3's
// `callLLMJson` dependency is the auto-mocked vi.fn (no network, fully
// in-memory across 100+ iterations).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import { createLLMJsonMock } from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 15: Both narrative fields empty
// means absent
//
// For any Pass 3 response whose `attackScenario` and `ifUnaddressed` are both
// empty or whitespace-only, `runPass3` returns `null`.
//
// **Validates: Requirements 4.2**
//
// This test mirrors the EXACT emptiness semantics of the runPass3 success path
// in analysis.js:
//
//   const attackScenario =
//     typeof json.attackScenario === "string" ? json.attackScenario.trim() : "";
//   const ifUnaddressed =
//     typeof json.ifUnaddressed === "string" ? json.ifUnaddressed.trim() : "";
//   if (!attackScenario && !ifUnaddressed) return null;
//
// So a field is "empty" when it is a string that trims to "" OR is not a string
// at all (treated as ""). When BOTH fields are empty by this rule, runPass3 must
// return null. The generators below produce exactly that input space: each field
// is either a whitespace-only / empty string or a non-string (absent, null,
// number, boolean) — both of which reduce to "".
// ---------------------------------------------------------------------------

// Values that runPass3 treats as empty after its trim/typeof rule:
//   - empty / whitespace-only strings  -> trim() === ""
//   - non-string values                -> typeof !== "string" -> ""
const emptyNarrativeValueArb = fc.oneof(
  fc.constantFrom("", " ", "   ", "\t", "\n", "\n  \n", "\t \t ", "  \r\n\t  "),
  fc.constant(null),
  fc.integer(),
  fc.boolean(),
  fc.record({ nested: fc.string() }), // non-string (object)
  fc.array(fc.string()) // non-string (array)
);

// A Pass 3 LLM response in which BOTH narrative fields are empty/whitespace (or
// absent entirely, via requiredKeys: []). Unrelated extra keys may appear and
// must be ignored.
const emptyNarrativeResponseArb = fc.record(
  {
    attackScenario: emptyNarrativeValueArb,
    ifUnaddressed: emptyNarrativeValueArb,
    extra: fc.string(),
  },
  { requiredKeys: [] }
);

// A minimal-but-varied base report. runPass3 only reads `findings`, `riskLevel`,
// and `overallRiskScore`, so we generate just enough to drive the payload build
// without affecting the empty-narrative outcome.
const baseFindingArb = fc.record({
  title: fc.string({ minLength: 1, maxLength: 30 }),
  severity: fc.constantFrom("critical", "high", "medium", "low", "info"),
  explanation: fc.string({ minLength: 1, maxLength: 60 }),
});

const baseReportArb = fc.record({
  riskLevel: fc.constantFrom("Critical", "High", "Medium", "Low"),
  overallRiskScore: fc.integer({ min: 0, max: 100 }),
  findings: fc.array(baseFindingArb, { maxLength: 8 }),
});

describe("Feature: deterministic-fallback, Property 15: both narrative fields empty means absent", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("returns null when both attackScenario and ifUnaddressed are empty/whitespace-only", async () => {
    await fc.assert(
      fc.asyncProperty(
        baseReportArb,
        emptyNarrativeResponseArb,
        fc.domain(),
        async (report, json, domain) => {
          // Each iteration resolves callLLMJson with this iteration's empty
          // narrative response, keeping runPass3 on its success path.
          llm.reset();
          llm.resolveWith(json);

          const result = await runPass3(report, domain);

          expect(result).toBeNull();
        }
      ),
      { numRuns: 200 }
    );
  });
});
