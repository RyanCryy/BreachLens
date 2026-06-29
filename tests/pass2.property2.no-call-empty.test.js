// tests/pass2.property2.no-call-empty.test.js
//
// Task 4.2 — Property test: no LLM call for an empty finding set.
//
// Feature: analyst-synthesis, Property 2: No LLM call for an empty finding set
// Validates: Requirements 1.4, 8.1
//
// For ANY domain and tech context, invoking `runPass2` with an empty finding
// set must result in ZERO invocations of the LLM client. This verifies the
// existing production short-circuit in `runPass2` (netlify/functions/lib/
// analysis.js): when there are no findings, the model is skipped entirely.
//
// The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export). The spy is reset per
// iteration and we assert `llm.callCount === 0`. No production file is edited.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors, domainArb } from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// A tech-context arbitrary: present-with-list, empty list, and absent — none of
// which should ever cause an LLM call when the finding set is empty.
const techArb = fc.oneof(
  fc.constant(undefined),
  fc.record({
    detected: fc.array(fc.constantFrom("nginx", "react", "wordpress", "cloudflare"), {
      maxLength: 4,
    }),
  })
);

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  // Program a healthy resolve as the default so that, IF production were to
  // (incorrectly) call the LLM, the call would succeed — making any non-zero
  // callCount a genuine signal rather than a masked failure.
  llm = attachDouble(mockCallLLMJson, {
    default: behaviors.resolveJson({ summary: "should-not-be-used", topPriority: "x" }),
  });
});

describe("Pass 2 — Property 2: no LLM call for an empty finding set", () => {
  // Feature: analyst-synthesis, Property 2: No LLM call for an empty finding set
  it("invokes the LLM double zero times for runPass2([], domain, tech)", async () => {
    await fc.assert(
      fc.asyncProperty(domainArb, techArb, async (domain, tech) => {
        // Reset the spy per iteration so callCount reflects only this run.
        llm.reset();

        await runPass2([], domain, tech);

        expect(llm.callCount).toBe(0);
      }),
      { numRuns: 200 }
    );
  });
});
