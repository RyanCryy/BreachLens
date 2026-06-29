import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` must be hoisted above the `./analysis.js` import so that
// classifyOne's `callLLMJson` dependency is the auto-mocked vi.fn (no network,
// fully in-memory across 100+ iterations).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 2: the LLM never sets severity
//
// For any finding, when the Pass 1 LLM call succeeds and returns arbitrary
// prose (even an arbitrary or bogus `severity`), `classifyOne` returns a
// `severity` exactly equal to `fallbackClassify(finding).severity` while using
// the LLM's text for `title`, `explanation`, and `recommendation`.
//
// **Validates: Requirements 1.2, 2.7**
//
// `classifyOne` is module-private, so we exercise it through the exported
// `runPass1([finding], ...)`, which invokes `classifyOne` once per finding and
// returns its result. `llmResponseArbitrary` carries a bogus `severity` field
// that the production code must always discard in favor of the deterministic
// rule. The prose assertions mirror production's exact `json.field || rule`
// semantics so the test proves LLM prose is used wherever the LLM supplied a
// usable value, while severity is never LLM-derived.
// ---------------------------------------------------------------------------

describe("Feature: deterministic-fallback, Property 2: the LLM never sets severity", () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it("classifyOne uses the deterministic severity while keeping the LLM's title/explanation/recommendation", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArbitrary,
        llmResponseArbitrary,
        async (finding, llmResponse) => {
          // The succeeding Pass 1 call returns arbitrary prose plus a bogus
          // severity the code must ignore.
          llm.reset();
          llm.resolveWith(llmResponse);

          const [result] = await runPass1([finding], null, null);

          const rule = fallbackClassify(finding);

          // Severity is ALWAYS the deterministic rule value — never the LLM's.
          expect(result.severity).toBe(rule.severity);

          // A successful Pass 1 call is tagged "llm".
          expect(result._source).toBe("llm");

          // Prose uses the LLM's value when it supplied a usable (truthy) one,
          // exactly matching production's `json.field || <deterministic>`.
          expect(result.title).toBe(llmResponse.title || finding.label);
          expect(result.explanation).toBe(
            llmResponse.explanation || rule.explanation
          );
          expect(result.recommendation).toBe(
            llmResponse.recommendation || rule.recommendation
          );
        }
      ),
      { numRuns: 200 }
    );
  });
});
