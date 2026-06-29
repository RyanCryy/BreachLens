// tests/pass2.property3.score.test.js
//
// Feature: analyst-synthesis, Property 3: Deterministic score is the capped weighted sum within 0..100
//
// Validates: Requirements 2.1, 2.2, 2.4
//
// Property 3 — Deterministic score is the capped weighted sum within 0..100.
//
// For any array of Classified_Findings, the report's overallRiskScore equals
// `min(100, Σ per-finding weights)` (critical=40, high=22, medium=10, low=3, and
// every other / absent / null severity contributes 0), and always lies in the
// inclusive range [0, 100].
//
// This drives the FROZEN production `runPass2` over the full classified-finding
// space (which deliberately includes critical/high/medium/low plus info, mixed-
// case variants, null, and arbitrary strings — all of which must contribute 0),
// with the LLM client replaced by a controllable double that resolves valid
// prose, so the success path is exercised and 100+ iterations cost no network.
//
// The oracle `expectedScore` reimplements the deterministic capped weighted sum
// EXACTLY as production does (case-insensitive lookup — severity is normalized
// via `.toLowerCase()` before the weight lookup), and is the ground truth here.
// This file authors NO production change — the only seam is the module-mock of
// ./llm.js's callLLMJson.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import {
  classifiedListArb,
  expectedScore,
  attachDouble,
  behaviors,
} from "./helpers/pass2-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

const domain = "example.com";
const tech = { detected: ["nginx"] };

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
  // Default to a valid-prose resolve so every iteration takes the LLM-success
  // path; the score must still be the deterministic capped weighted sum.
  llm.setDefault(
    behaviors.resolveJson({ summary: "Executive summary.", topPriority: "Top priority." })
  );
});

describe("Pass 2 — Property 3: deterministic capped weighted-sum score within 0..100", () => {
  it("overallRiskScore === expectedScore(findings) and lies in [0,100] for any finding set", async () => {
    await fc.assert(
      fc.asyncProperty(
        // min length 1 so the LLM-resolving path is taken (length 0 short-circuits
        // to the fixed zero-findings shape, which is Property 11, not this one).
        classifiedListArb({ minLength: 1, maxLength: 8 }),
        async (findings) => {
          const report = await runPass2(findings, domain, tech);

          const oracle = expectedScore(findings);

          // The report's score equals the deterministic capped weighted sum.
          expect(report.overallRiskScore).toBe(oracle);

          // ...which is always an integer in the inclusive range [0, 100].
          expect(Number.isInteger(report.overallRiskScore)).toBe(true);
          expect(report.overallRiskScore).toBeGreaterThanOrEqual(0);
          expect(report.overallRiskScore).toBeLessThanOrEqual(100);
        }
      ),
      { numRuns: 200 }
    );
  });
});
