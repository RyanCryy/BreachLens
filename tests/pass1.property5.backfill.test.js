// tests/pass1.property5.backfill.test.js
//
// Property 5: Successful results are marked and prose-backfilled.
//
// For any LLM-sourced result, `_source === "llm"`, and any empty or missing
// `title` / `explanation` / `recommendation` is replaced by the finding's
// `label` / the deterministic explanation / the deterministic recommendation
// respectively; when the LLM supplies a non-empty value, that value is used.
//
// This is a verification test for already-shipped, FROZEN production code
// (netlify/functions/lib/analysis.js `classifyOne`). No production file is
// edited. The only test seam is module-mocking `./llm.js`'s `callLLMJson`,
// matching tests/pass1.harness.smoke.test.js.
//
// Production reference (classifyOne):
//   title:          json.title          || finding.label
//   explanation:    json.explanation    || rule.explanation
//   recommendation: json.recommendation || rule.recommendation
// where `rule = fallbackClassify(finding)`. Because the operator is `||`, BOTH a
// missing key and an empty string ("") fall through to the deterministic value —
// this test asserts exactly that, using the REAL `fallbackClassify` oracle.
//
// **Feature: finding-classification, Property 5: Successful results are marked and backfilled**
// **Validates: Requirements 12.3, 12.5, 12.6, 12.7**

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import { findingListArb, llmJsonArb, fallbackClassify } from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

// Treat a value as "absent or empty" the same way production's `||` does for the
// strings we generate (undefined / missing key / empty string "").
function isEmptyProse(v) {
  return v === undefined || v === "";
}

describe("Property 5: successful results are marked and prose-backfilled", () => {
  it("marks LLM-sourced results and backfills empty/missing title, explanation, recommendation", async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate a finding list, then one LLM JSON payload per finding so the
        // FIFO double queue lines up call i <-> finding i (runPass1 maps in order).
        findingListArb({ minLength: 1, maxLength: 6 }).chain((findings) =>
          fc.tuple(
            fc.constant(findings),
            fc.array(llmJsonArb, {
              minLength: findings.length,
              maxLength: findings.length,
            })
          )
        ),
        async ([findings, jsons]) => {
          llm.reset();
          // Program a successful JSON resolution for each finding, in order.
          llm.program(...jsons.map((j) => behaviors.resolveJson(j)));

          const results = await runPass1(findings, null, undefined);

          expect(results).toHaveLength(findings.length);

          for (let i = 0; i < findings.length; i++) {
            const finding = findings[i];
            const json = jsons[i];
            const result = results[i];
            const rule = fallbackClassify(finding);

            // 12.3 — produced from LLM prose => _source is "llm".
            expect(result._source).toBe("llm");

            // 12.5 — title: empty/missing => finding.label; otherwise the LLM value.
            if (isEmptyProse(json.title)) {
              expect(result.title).toBe(finding.label);
            } else {
              expect(result.title).toBe(json.title);
            }

            // 12.6 — explanation: empty/missing => deterministic explanation.
            if (isEmptyProse(json.explanation)) {
              expect(result.explanation).toBe(rule.explanation);
            } else {
              expect(result.explanation).toBe(json.explanation);
            }

            // 12.7 — recommendation: empty/missing => deterministic recommendation.
            if (isEmptyProse(json.recommendation)) {
              expect(result.recommendation).toBe(rule.recommendation);
            } else {
              expect(result.recommendation).toBe(json.recommendation);
            }
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
