import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";

// `vi.mock` MUST run before the `./analysis.js` import so vitest hoists it above
// the module graph and `callLLMJson` is replaced by an auto-mocked vi.fn().
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";
import {
  findingArbitrary,
  llmResponseArbitrary,
  errorShapeArbitrary,
  createLLMJsonMock,
} from "./deterministic-fallback.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback, Property 7: per-finding failures are
// isolated from siblings
//
// For any list of findings in which exactly one finding's LLM call fails, every
// other finding's classification — its prose, severity, and `_source` tag — is
// identical to what it would be if no finding had failed.
//
// **Validates: Requirements 2.2**
//
// `runPass1` dispatches `classifyOne` per finding via `Promise.all`, and each
// `classifyOne` wraps its own `callLLMJson` in an isolated `try/catch`. So one
// finding's rejection degrades only that finding to `fallbackClassify` and must
// leave the rest untouched.
//
// The model boundary (`callLLMJson`) is mocked so every iteration runs fully
// in-memory. We run `runPass1` twice over the SAME findings and the SAME LLM
// success response:
//   - baseline: every call succeeds
//   - failure:  exactly one call (the target) rejects, the rest succeed
// then assert every non-target finding's result is byte-for-byte identical
// across the two runs.
// ---------------------------------------------------------------------------

// A guaranteed-unique marker injected into the target finding's `detail`.
// `classifyOne` echoes `finding.detail` into the user message it sends to
// `callLLMJson`, so the mock can recognize the target call by this substring.
// fast-check never synthesizes this exact token, so exactly one call matches.
const TARGET_SENTINEL = "ZZ__DETERMINISTIC_FALLBACK_P7_TARGET__ZZ";

const provider = "Cloudflare";
const tech = { server: null, poweredBy: null, detected: [] };

// A list of findings (>=1), a target index to fail, a single shared LLM success
// response, and the rejection error shape for the target.
const scenarioArb = fc
  .array(findingArbitrary, { minLength: 1, maxLength: 6 })
  .chain((findings) =>
    fc.record({
      findings: fc.constant(findings),
      targetIndex: fc.integer({ min: 0, max: findings.length - 1 }),
      llmResponse: llmResponseArbitrary,
      error: errorShapeArbitrary,
    })
  );

// The fields that make up a per-finding classification — compared in full so
// "prose, severity, and `_source` tag" are all covered.
function classificationSnapshot(c) {
  return {
    id: c.id,
    type: c.type,
    title: c.title,
    severity: c.severity,
    explanation: c.explanation,
    recommendation: c.recommendation,
    fixSnippet: c.fixSnippet,
    _source: c._source,
  };
}

describe("Feature: deterministic-fallback, Property 7: per-finding failures are isolated from siblings", () => {
  const llm = createLLMJsonMock(callLLMJson);

  it("leaves every sibling finding's classification unchanged when exactly one fails", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ findings, targetIndex, llmResponse, error }) => {
        // Inject the unique marker into the target finding's detail so the mock
        // can fail exactly that one call. The SAME findings array is used for
        // both runs, so siblings are identical inputs across runs.
        const markedFindings = findings.map((f, i) =>
          i === targetIndex ? { ...f, detail: `${f.detail} ${TARGET_SENTINEL}` } : f
        );

        // --- Baseline run: every call succeeds with the shared response. ---
        llm.resolveWith(llmResponse);
        const baseline = await runPass1(markedFindings, provider, tech);

        // --- Failure run: the target call rejects; every other call succeeds
        //     with the exact same shared response. ---
        llm.implement(async (opts) => {
          const content = opts.messages[0].content;
          if (content.includes(TARGET_SENTINEL)) {
            throw error;
          }
          return llmResponse;
        });
        const withFailure = await runPass1(markedFindings, provider, tech);

        // Both runs classify every finding (order preserved by Promise.all/map).
        expect(baseline).toHaveLength(markedFindings.length);
        expect(withFailure).toHaveLength(markedFindings.length);

        // Exactly one finding fell back — the target — confirming the failure
        // was real and isolated, not silently swallowed or spread to siblings.
        const fallbackCount = withFailure.filter((c) => c._source === "fallback").length;
        expect(fallbackCount).toBe(1);
        expect(withFailure[targetIndex]._source).toBe("fallback");

        // Every non-target finding is byte-for-byte identical across the two
        // runs: same prose, same severity, same `_source` tag.
        for (let i = 0; i < markedFindings.length; i++) {
          if (i === targetIndex) continue;
          expect(classificationSnapshot(withFailure[i])).toEqual(
            classificationSnapshot(baseline[i])
          );
        }
      }),
      { numRuns: 200 }
    );
  });
});
