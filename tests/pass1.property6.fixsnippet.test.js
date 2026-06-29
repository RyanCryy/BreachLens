// tests/pass1.property6.fixsnippet.test.js
//
// Property 6: fixSnippet is always a clean literal or null.
//
// For ANY value the LLM returns in json.fixSnippet, this test asserts the Pass 1
// result's fixSnippet is one of exactly two clean shapes:
//   - null, OR
//   - a trimmed, non-empty string that is NOT the literal "null" (case-insensitive).
//
// It further asserts the resolution rule (Req 6.4 / 6.5 / 6.6):
//   - when the LLM value is UNUSABLE (absent, a non-string, empty, whitespace-only,
//     or "null"/"NULL" after trimming) the field falls back to the REAL
//     defaultFixSnippet(finding) oracle (suggestedSnippet → per-type literal → null);
//   - when the LLM value is a USABLE token surrounded by whitespace, the TRIMMED
//     token is retained (never the default).
//
// Production logic (frozen, netlify/functions/lib/analysis.js):
//     fixSnippet: normalizeSnippet(json.fixSnippet) || defaultFixSnippet(finding)
// `normalizeSnippet` is an internal (non-exported) 4-line helper, so this test
// MIRRORS its exact contract locally purely to CLASSIFY each generated value as
// usable/unusable. The expected backfill value always comes from the REAL,
// imported defaultFixSnippet — never a reimplementation.
//
// The LLM boundary is replaced by the controllable double (the single test seam:
// vi.mock of ../netlify/functions/lib/llm.js). NO production file is edited.
//
// The double consumes programmed behaviors FIFO by call order, and runPass1
// dispatches classifyOne in finding order, so call index i maps to finding i.
//
// Feature: finding-classification, Property 6: fixSnippet is always a clean literal or null
// Validates: Requirements 6.3, 6.4, 6.5, 6.6

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  findingListArb,
  defaultFixSnippet,
  llmFixSnippetValueArb,
  whitespacePaddedSnippetArb,
} from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// Mirrors the frozen, non-exported normalizeSnippet(s) contract EXACTLY. Used
// ONLY to classify a generated value and to compute the trimmed token for the
// "usable" branch; the unusable-branch expectation uses the real defaultFixSnippet.
function normalizeLikeProduction(s) {
  if (!s || typeof s !== "string") return null;
  const trimmed = s.trim();
  if (!trimmed || trimmed.toLowerCase() === "null") return null;
  return trimmed;
}

// Wrap a generated fixSnippet value into a healthy LLM JSON body so the result
// stays on the LLM-success path (_source === "llm").
function jsonWithSnippet(value) {
  return behaviors.resolveJson({
    title: "LLM title",
    explanation: "LLM explanation.",
    recommendation: "LLM recommendation.",
    fixSnippet: value,
  });
}

// Assert the universal "clean literal or null" shape (Req 6.3).
function assertCleanLiteralOrNull(snippet) {
  if (snippet === null) return;
  expect(typeof snippet).toBe("string");
  const trimmed = snippet.trim();
  expect(trimmed.length).toBeGreaterThan(0); // non-empty
  expect(trimmed).toBe(snippet); // already trimmed (no surrounding whitespace)
  expect(trimmed.toLowerCase()).not.toBe("null"); // never the literal "null"
}

// A non-empty finding list paired with one arbitrary LLM fixSnippet value per
// finding (the full value space: usable, whitespace-padded, empty, whitespace-
// only, "null"/"NULL", non-string, and absent/undefined).
const findingsWithSnippetValuesArb = findingListArb({ minLength: 1, maxLength: 6 }).chain(
  (findings) =>
    fc.record({
      findings: fc.constant(findings),
      values: fc.array(llmFixSnippetValueArb, {
        minLength: findings.length,
        maxLength: findings.length,
      }),
    })
);

// A list where EVERY finding's LLM value is a usable token wrapped in whitespace,
// to heavily exercise the "trimmed token retained" branch (Req 6.5).
const findingsWithPaddedValuesArb = findingListArb({ minLength: 1, maxLength: 6 }).chain(
  (findings) =>
    fc.record({
      findings: fc.constant(findings),
      values: fc.array(whitespacePaddedSnippetArb, {
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

describe("Pass 1 — Property 6: fixSnippet is always a clean literal or null", () => {
  it("normalizes arbitrary LLM fixSnippet values to a clean literal or backfills the default", async () => {
    await fc.assert(
      fc.asyncProperty(findingsWithSnippetValuesArb, async ({ findings, values }) => {
        llm.reset();
        llm.program(...values.map(jsonWithSnippet));

        const results = await runPass1(findings, null, undefined);

        expect(results).toHaveLength(findings.length);
        expect(llm.callCount).toBe(findings.length);

        for (let i = 0; i < findings.length; i++) {
          const finding = findings[i];
          const value = values[i];
          const result = results[i];

          // Every result came from the LLM-success path.
          expect(result._source).toBe("llm");

          // (Req 6.3) Universal shape: null or a clean, trimmed, non-"null" literal.
          assertCleanLiteralOrNull(result.fixSnippet);

          const normalized = normalizeLikeProduction(value);
          if (normalized === null) {
            // (Req 6.4 / 6.6) Unusable LLM value → real defaultFixSnippet backfill
            // (suggestedSnippet → per-type literal → null).
            expect(result.fixSnippet).toBe(defaultFixSnippet(finding));
          } else {
            // (Req 6.5) Usable value (incl. whitespace-padded) → trimmed token kept,
            // never the default.
            expect(result.fixSnippet).toBe(value.trim());
          }
        }
      }),
      { numRuns: 200 }
    );
  });

  it("retains the trimmed token when a usable value is surrounded by whitespace", async () => {
    await fc.assert(
      fc.asyncProperty(findingsWithPaddedValuesArb, async ({ findings, values }) => {
        llm.reset();
        llm.program(...values.map(jsonWithSnippet));

        const results = await runPass1(findings, null, undefined);

        expect(results).toHaveLength(findings.length);

        for (let i = 0; i < findings.length; i++) {
          const value = values[i];
          const result = results[i];
          const trimmed = value.trim();

          // The padded value is always usable, so the trimmed token is retained
          // verbatim (Req 6.5) and is a clean literal (Req 6.3).
          expect(result.fixSnippet).toBe(trimmed);
          assertCleanLiteralOrNull(result.fixSnippet);
        }
      }),
      { numRuns: 100 }
    );
  });
});
