import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST be at the top of the module so vitest hoists it above the
// `./analysis.js` import — this auto-mocks `callLLMJson` to a `vi.fn()` so Pass 1
// never touches the network and every iteration runs fully in-memory.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 8: successful classification is tagged "llm"
//
// For any finding whose Pass 1 LLM call succeeds, the resulting classification
// carries `_source: "llm"`.
//
// **Validates: Requirements 2.3**
//
// `classifyOne` is not exported, so it is exercised through its only public
// entry point, `runPass1`, which dispatches one `classifyOne` per finding.
// `callLLMJson` is auto-mocked and resolved with a valid response object (so the
// success path runs to completion); the assertion is that every returned
// classification is tagged `_source: "llm"`. The resolved value is constrained
// to a plain object (via `llmResponseArbitrary`) so the parse path succeeds and
// the call is genuinely a success — a non-object would trip classifyOne's
// try/catch and degrade to `_source: "fallback"`, which is a different property.
// ---------------------------------------------------------------------------

describe('Feature: deterministic-fallback, Property 8: successful classification is tagged "llm"', () => {
  let llm;

  beforeEach(() => {
    llm = createLLMJsonMock(callLLMJson);
  });

  it('tags every successfully classified finding with _source: "llm"', async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArbitrary,
        llmResponseArbitrary,
        async (finding, llmResponse) => {
          // A successful resolve keeps classifyOne on its happy path.
          llm.resolveWith(llmResponse);

          const [classification] = await runPass1([finding], "Cloudflare", {
            detected: [],
          });

          // The single defining outcome of a successful Pass 1 call.
          expect(classification._source).toBe("llm");
        }
      ),
      { numRuns: 200 }
    );
  });
});
