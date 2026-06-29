// tests/pass2.property1.single-call.test.js
//
// Task 4.1 — Property 1: At most one LLM call for any non-empty finding set.
//
// Feature: analyst-synthesis, Property 1: At most one LLM call for any non-empty finding set
// Validates: Requirements 1.1, 1.2, 1.3
//
// This test verifies EXISTING production behavior in `runPass2`
// (netlify/functions/lib/analysis.js). No production code is modified.
//
// Property statement (design.md, Property 1):
//   For any non-empty array of Classified_Findings, and any domain and tech
//   context, invoking `runPass2` results in exactly one invocation of the LLM
//   client, independent of the number of findings.
//
// The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export), exactly as the
// harness smoke test (tests/pass2.harness.smoke.test.js) establishes. The
// `callLLMJson` double exposes a `callCount`; we reset the spy per iteration
// and assert `llm.callCount === 1` for every non-empty finding list.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import { nonEmptyClassifiedListArb, domainArb } from "./helpers/pass2-fixtures.js";

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

describe("Pass 2 — Property 1: at most one LLM call for any non-empty finding set", () => {
  it("invokes callLLMJson exactly once regardless of finding count", async () => {
    await fc.assert(
      fc.asyncProperty(
        nonEmptyClassifiedListArb({ minLength: 1, maxLength: 12 }),
        domainArb,
        techArb,
        async (classified, domain, tech) => {
          // Reset the spy per iteration so callCount reflects this run only.
          llm.reset();
          // Program a healthy resolve so the LLM-success path is exercised.
          llm.setDefault(behaviors.resolveJson({ summary: "s", topPriority: "p" }));

          await runPass2(classified, domain, tech);

          // Exactly one LLM invocation for any non-empty finding set,
          // independent of the number of findings.
          expect(llm.callCount).toBe(1);
        }
      ),
      { numRuns: 200 }
    );
  });
});
