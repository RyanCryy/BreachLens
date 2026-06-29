// tests/pass2.property7.prose-verbatim.test.js
//
// Task 5.1 — Property 7: Valid model prose is used verbatim and tagged "llm".
//
// Feature: analyst-synthesis, Property 7: Valid model prose is used verbatim and tagged "llm"
// Validates: Requirements 6.1, 6.3, 6.5
//
// This test verifies EXISTING production behavior in `runPass2`
// (netlify/functions/lib/analysis.js). No production code is modified.
//
// Property statement (design.md, Property 7):
//   For any non-empty findings and any successful LLM response whose `summary`
//   and `topPriority` are each non-empty strings, the report's Summary and
//   Top_Priority equal those strings verbatim and the Source_Tag is "llm".
//
// The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export), exactly as the
// harness smoke test (tests/pass2.harness.smoke.test.js) establishes. We
// program the double to resolve `validLlmResponseArb` values (summary and
// topPriority both present, non-empty strings) and assert verbatim passthrough.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  nonEmptyClassifiedListArb,
  domainArb,
  validLlmResponseArb,
} from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// Tech-context arbitrary — Pass 2 only reads tech.detected for a prompt line.
const techArb = fc.record({
  detected: fc.array(fc.string({ maxLength: 12 }), { maxLength: 4 }),
});

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe('Pass 2 — Property 7: valid model prose used verbatim and tagged "llm"', () => {
  it("uses the model's summary and topPriority verbatim with _source 'llm'", async () => {
    await fc.assert(
      fc.asyncProperty(
        nonEmptyClassifiedListArb({ minLength: 1, maxLength: 12 }),
        domainArb,
        techArb,
        validLlmResponseArb,
        async (classified, domain, tech, response) => {
          // Reset per iteration and program the healthy, valid-prose resolve.
          llm.reset();
          llm.program(behaviors.resolveJson(response));

          const report = await runPass2(classified, domain, tech);

          // Valid, non-empty prose is used verbatim.
          expect(report.summary).toBe(response.summary);
          expect(report.topPriority).toBe(response.topPriority);
          // Source tag reflects a successful LLM synthesis.
          expect(report._source).toBe("llm");
        }
      ),
      { numRuns: 200 }
    );
  });
});
