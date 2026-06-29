import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST run before the `./analysis.js` import so vitest hoists it above
// the module graph and `callLLMJson` is replaced by an auto-mocked vi.fn().
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";
import { fallbackClassify } from "./findings.js";
import {
  findingArbitrary,
  errorShapeArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 6: per-finding LLM failure degrades to the deterministic rule
//
// For any finding, when its Pass 1 LLM call throws, returns unparseable output,
// or times out, `classifyOne` returns
// `{ ...fallbackClassify(finding), type, _source: "fallback" }`.
//
// **Validates: Requirements 2.1**
//
// `classifyOne` is module-private, so it is exercised through its sole public
// entry point `runPass1([finding], ...)`, which dispatches exactly one
// `classifyOne` call and returns its result verbatim. The model boundary
// (`callLLMJson`) is auto-mocked via `vi.mock("./llm.js")`, so every iteration
// runs fully in-memory: the controller makes the stubbed LLM reject across the
// documented failure shapes (401-like, 429-like, abort/timeout-like, and
// generic parse failures from `errorShapeArbitrary`). `classifyOne` retries
// once internally inside the real `callLLMJson`; here the mock rejects directly,
// which is the post-retry exhaustion state, so the catch path is taken and the
// finding degrades to its deterministic rule.
// ---------------------------------------------------------------------------

// Provider / tech vary only the prompt text built before the (rejected) LLM
// call; they never affect the deterministic fallback result, but we vary them
// so the property holds independent of call context.
const providerArb = fc.option(
  fc.constantFrom("Cloudflare", "AWS Route 53", "GoDaddy", "Namecheap"),
  { nil: null }
);

const techArb = fc.option(
  fc.record({
    server: fc.option(fc.string(), { nil: null }),
    poweredBy: fc.option(fc.string(), { nil: null }),
    detected: fc.array(fc.constantFrom("WordPress", "React", "nginx", "PHP"), {
      maxLength: 3,
    }),
  }),
  { nil: undefined }
);

describe("Feature: deterministic-fallback, Property 6: per-finding LLM failure degrades to the deterministic rule", () => {
  const llm = createLLMJsonMock(callLLMJson);

  it("returns the deterministic-rule classification tagged _source: \"fallback\" for every LLM failure shape", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArbitrary,
        errorShapeArbitrary,
        providerArb,
        techArb,
        async (finding, error, provider, tech) => {
          // Reject every call (throw / abort / unparseable). For an abort-style
          // error the controller's dedicated helper is used; otherwise reject
          // with the generated error instance.
          if (error.name === "AbortError") {
            llm.rejectAbort(error.message);
          } else {
            llm.rejectWith(error);
          }

          const [result] = await runPass1([finding], provider, tech);

          // The failure path degrades to the deterministic rule: the result is
          // the rule classification, plus the finding's `type` and the
          // `_source: "fallback"` tag — nothing more, nothing less.
          const expected = {
            ...fallbackClassify(finding),
            type: finding.type,
            _source: "fallback",
          };

          expect(result).toEqual(expected);

          // The fallback was reached via the LLM call (the failure happened on
          // the call, not before it).
          expect(llm.callCount()).toBeGreaterThanOrEqual(1);
        }
      ),
      { numRuns: 200 }
    );
  });
});
