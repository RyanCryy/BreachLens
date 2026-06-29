// tests/pass1.property4.degradation.test.js
//
// Property 4: Per-finding failure degrades to a deterministic fallback in isolation.
//
// For any list of findings where an ARBITRARY SUBSET of LLM calls fail (a mix of
// timeout, parse failure, and generic exception), this test asserts:
//   - each FAILING finding's result === fallbackClassify(finding) with `type`
//     preserved and `_source === "fallback"` (the real deterministic oracle);
//   - each NON-FAILING finding's result has `_source === "llm"`;
//   - the returned list still has exactly one result per input finding
//     (count preserved — one failure never affects another → isolation holds).
//
// The LLM boundary is replaced by the controllable double (the single test seam:
// vi.mock of ../netlify/functions/lib/llm.js). NO production file is edited; the
// expected values come from the REAL fallbackClassify, never a reimplementation.
//
// The double consumes its programmed behaviors FIFO by call order, and runPass1
// dispatches classifyOne in finding order (synchronously up to the first
// `await callLLMJson`), so call index i maps deterministically to finding i.
// We therefore program one behavior per finding, aligned by index.
//
// Feature: finding-classification, Property 4: Per-finding failure degrades to a deterministic fallback in isolation
// Validates: Requirements 1.5, 2.5, 7.5, 9.1, 9.4, 12.4

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import { findingListArb, fallbackClassify } from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// A healthy JSON body for the calls we want to SUCCEED.
const SUCCESS_JSON = {
  title: "LLM title",
  explanation: "LLM explanation.",
  recommendation: "LLM recommendation.",
  fixSnippet: null,
};

// Per-index "fate": either a clean success, or one of the three failure modes.
const fateArb = fc.oneof(
  { weight: 2, arbitrary: fc.constant({ fail: false }) },
  {
    weight: 3,
    arbitrary: fc
      .constantFrom("timeout", "parse", "generic")
      .map((kind) => ({ fail: true, kind })),
  }
);

// Map a fate to a double behavior.
function behaviorForFate(fate) {
  if (!fate.fail) return behaviors.resolveJson(SUCCESS_JSON);
  switch (fate.kind) {
    case "timeout":
      return behaviors.timeout();
    case "parse":
      return behaviors.throwParse();
    default:
      return behaviors.throwGeneric();
  }
}

// A non-empty finding list paired with a fate array of equal length, so an
// arbitrary subset of the per-finding calls is programmed to fail.
const findingsWithFatesArb = findingListArb({ minLength: 1, maxLength: 6 }).chain((findings) =>
  fc.record({
    findings: fc.constant(findings),
    fates: fc.array(fateArb, {
      minLength: findings.length,
      maxLength: findings.length,
    }),
  })
);

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 1 — Property 4: per-finding failure degrades to deterministic fallback in isolation", () => {
  it("each failing finding falls back deterministically while others are unaffected", async () => {
    await fc.assert(
      fc.asyncProperty(findingsWithFatesArb, async ({ findings, fates }) => {
        llm.reset();
        // Program one behavior per finding, FIFO-aligned to dispatch order.
        llm.program(...fates.map(behaviorForFate));

        const results = await runPass1(findings, null, undefined);

        // Count preserved: exactly one result per input finding (Req 9.2 spirit,
        // Req 9.4 / 2.5 isolation — failures never drop or duplicate a result).
        expect(results).toHaveLength(findings.length);
        // Exactly one LLM call was attempted per finding.
        expect(llm.callCount).toBe(findings.length);

        for (let i = 0; i < findings.length; i++) {
          const finding = findings[i];
          const result = results[i];

          if (fates[i].fail) {
            // Failing finding → exact deterministic fallback, type preserved,
            // _source === "fallback" (Req 1.5, 7.5, 9.1, 9.4, 12.4).
            const expected = {
              ...fallbackClassify(finding),
              type: finding.type,
              _source: "fallback",
            };
            expect(result).toEqual(expected);
            expect(result._source).toBe("fallback");
            expect(result.type).toBe(finding.type);
          } else {
            // Non-failing finding → LLM-sourced, unaffected by neighbors' failures.
            expect(result._source).toBe("llm");
            // Identity is still preserved on the success path.
            expect(result.id).toBe(finding.id);
            expect(result.type).toBe(finding.type);
          }
        }
      }),
      { numRuns: 200 }
    );
  });
});
