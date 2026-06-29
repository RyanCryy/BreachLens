// tests/pass2.property6.request-context.test.js
//
// Task 4.3 — Property 6: The LLM request carries the deterministic score and level.
//
// Feature: analyst-synthesis, Property 6: The LLM request carries the deterministic score and level
// Validates: Requirements 4.1
//
// This test verifies EXISTING production behavior in `runPass2`
// (netlify/functions/lib/analysis.js). No production code is modified.
//
// Property statement (design.md, Property 6):
//   For any non-empty array of Classified_Findings, the request handed to the
//   LLM client contains the deterministically computed Overall_Risk_Score (an
//   integer 0..100) and the derived Risk_Level (one of the four bands).
//
// How the request embeds the score/level (confirmed against analysis.js
// `runPass2`): the deterministic score and level are computed BEFORE the call,
// then the user message is built as
//
//   `Findings for ${domain} (risk level ${riskLevel}, score ${score}/100):\n\n${userContent}`
//
// where `userContent` is a `JSON.stringify(obj, null, 2)` of an object whose
// fields include `overallRiskScore` (the deterministic integer) and `riskLevel`
// (the deterministic band). This test captures the double's `opts`, extracts and
// parses that embedded JSON object from the user-message content, and asserts the
// parsed `overallRiskScore` / `riskLevel` equal the oracle values
// `expectedScore(findings)` / `expectedLevel(expectedScore(findings))`.
//
// The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export), exactly as the harness
// smoke test (tests/pass2.harness.smoke.test.js) establishes.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  nonEmptyClassifiedListArb,
  domainArb,
  expectedScore,
  expectedLevel,
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

const BANDS = ["Critical", "High", "Medium", "Low"];

// Extract the embedded JSON object from the user message content. The content is
// a human-readable prefix followed by a pretty-printed JSON object; the object
// begins at the first "{" and runs to the final "}".
function parseEmbeddedJson(content) {
  const start = content.indexOf("{");
  const end = content.lastIndexOf("}");
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return JSON.parse(content.slice(start, end + 1));
}

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 — Property 6: the LLM request carries the deterministic score and level", () => {
  it("embeds the deterministic overallRiskScore (0..100) and derived riskLevel in the request", async () => {
    await fc.assert(
      fc.asyncProperty(
        nonEmptyClassifiedListArb({ minLength: 1, maxLength: 12 }),
        domainArb,
        techArb,
        async (classified, domain, tech) => {
          // Reset per iteration so captured opts reflect this run only.
          llm.reset();
          // Program a healthy resolve so the request is actually issued.
          llm.setDefault(behaviors.resolveJson({ summary: "s", topPriority: "p" }));

          await runPass2(classified, domain, tech);

          // The request was issued through the seam.
          expect(llm.callCount).toBe(1);

          // Capture opts and pull the single user-message content.
          const [opts] = llm.opts();
          expect(opts).toBeTruthy();
          expect(Array.isArray(opts.messages)).toBe(true);
          const content = opts.messages.map((m) => m && m.content).filter(Boolean).join("\n");

          // Parse the embedded JSON object and assert it carries the
          // deterministic score and level.
          const payload = parseEmbeddedJson(content);

          const wantScore = expectedScore(classified);
          const wantLevel = expectedLevel(wantScore);

          // Deterministic integer score in the inclusive range 0..100.
          expect(Number.isInteger(payload.overallRiskScore)).toBe(true);
          expect(payload.overallRiskScore).toBeGreaterThanOrEqual(0);
          expect(payload.overallRiskScore).toBeLessThanOrEqual(100);
          expect(payload.overallRiskScore).toBe(wantScore);

          // Derived risk level is one of the four bands and equals the oracle.
          expect(BANDS).toContain(payload.riskLevel);
          expect(payload.riskLevel).toBe(wantLevel);
        }
      ),
      { numRuns: 200 }
    );
  });
});
