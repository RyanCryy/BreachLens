import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` must be hoisted above the `./analysis.js` import so that
// classifyOne's `callLLMJson` dependency is the auto-mocked vi.fn (no network,
// fully in-memory across 100+ iterations).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";
import { fallbackClassify, defaultFixSnippet } from "./findings.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 9: missing or empty LLM fields fall
// back per-field
//
// For any finding and any LLM response in which a subset of
// {title, explanation, recommendation, fixSnippet} is omitted or empty, each
// missing/empty field independently takes the deterministic rule value (or
// `defaultFixSnippet` for `fixSnippet`) while every field the LLM did supply is
// retained.
//
// **Validates: Requirements 2.4**
//
// `classifyOne` runs on its LLM-success path here (the mock always resolves), so
// `_source` is "llm" and severity is always the rule value. The per-field
// substitution semantics in production are NOT uniform, and this test mirrors
// them EXACTLY:
//
//   title          : json.title          || finding.label        // truthiness
//   explanation    : json.explanation    || rule.explanation      // truthiness
//   recommendation : json.recommendation || rule.recommendation   // truthiness
//   fixSnippet     : normalizeSnippet(json.fixSnippet) || defaultFixSnippet(finding)
//
// title/explanation/recommendation use plain JS truthiness (`||`): a falsy
// value — "", 0, false, null, undefined, NaN — falls back, but a whitespace-only
// string or any truthy non-string is RETAINED verbatim (no trimming, no type
// check). fixSnippet is different: `normalizeSnippet` first rejects non-strings
// and trims, so whitespace-only / "null" / non-string values fall back to
// `defaultFixSnippet(finding)`. This asymmetry is the production behavior under
// test.
// ---------------------------------------------------------------------------

// Local mirror of the private `normalizeSnippet` in analysis.js. Reproduced (not
// imported) because it is module-private; it is the single source of truth for
// fixSnippet substitution and must match byte-for-byte.
function normalizeSnippet(s) {
  if (!s || typeof s !== "string") return null;
  const trimmed = s.trim();
  if (!trimmed || trimmed.toLowerCase() === "null") return null;
  return trimmed;
}

describe("Feature: deterministic-fallback, Property 9: missing or empty LLM fields fall back per-field", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("substitutes the deterministic value for each missing/empty field independently while retaining supplied fields", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArbitrary,
        llmResponseArbitrary,
        async (finding, json) => {
          // Each iteration resolves callLLMJson with this iteration's raw
          // response, keeping classifyOne on its success path.
          llm.reset();
          llm.resolveWith(json);

          const rule = fallbackClassify(finding);
          // `classifyOne` is module-private, so it is exercised through
          // `runPass1` with a single finding (identical success path, no
          // production-code change). provider/tech affect only the prompt, not
          // the per-field substitution.
          const [result] = await runPass1([finding], /* provider */ null, /* tech */ null);

          // Success path invariants.
          expect(result._source).toBe("llm");
          expect(result.severity).toBe(rule.severity); // never LLM-supplied
          expect(result.id).toBe(finding.id);
          expect(result.type).toBe(finding.type);

          // --- Per-field substitution, mirroring production exactly ---

          // title: truthiness; deterministic value is finding.label (== rule.title).
          expect(result.title).toBe(json.title || finding.label);

          // explanation: truthiness; deterministic value is rule.explanation.
          expect(result.explanation).toBe(json.explanation || rule.explanation);

          // recommendation: truthiness; deterministic value is rule.recommendation.
          expect(result.recommendation).toBe(
            json.recommendation || rule.recommendation
          );

          // fixSnippet: trim+type-checked via normalizeSnippet, else defaultFixSnippet.
          expect(result.fixSnippet).toBe(
            normalizeSnippet(json.fixSnippet) || defaultFixSnippet(finding)
          );

          // --- Independence: each field's outcome depends ONLY on its own input ---

          // A truthy LLM value for a truthiness-field is retained verbatim.
          if (json.title) expect(result.title).toBe(json.title);
          if (json.explanation) expect(result.explanation).toBe(json.explanation);
          if (json.recommendation)
            expect(result.recommendation).toBe(json.recommendation);

          // A falsy LLM value for a truthiness-field takes the rule value.
          if (!json.title) expect(result.title).toBe(finding.label);
          if (!json.explanation)
            expect(result.explanation).toBe(rule.explanation);
          if (!json.recommendation)
            expect(result.recommendation).toBe(rule.recommendation);

          // A normalizable (non-empty, trimmed, non-"null") string snippet is
          // retained (trimmed); anything else falls back to defaultFixSnippet.
          const normalized = normalizeSnippet(json.fixSnippet);
          if (normalized) {
            expect(result.fixSnippet).toBe(normalized);
          } else {
            expect(result.fixSnippet).toBe(defaultFixSnippet(finding));
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
