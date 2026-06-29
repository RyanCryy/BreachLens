// tests/pass2.calllljson-retry.test.js
//
// Task 10.2 — `callLLMJson` internal-retry example test (Req 1.3)
// =============================================================================
//
// Verifies EXISTING production behavior of `callLLMJson` in
// `netlify/functions/lib/llm.js`. No production code is modified.
//
// Requirement 1.3 (paraphrased): a single logical `callLLMJson` invocation may
// perform ONE internal retry on parse failure, and Analyst_Synthesis counts
// that as exactly one LLM_Client call — it does NOT initiate a second
// synthesis call. This test pins down the seam at the source: the retry is
// parse-robustness over the SAME logical request, mapping one `callLLMJson`
// call to exactly two underlying model attempts (two `fetch` calls).
//
// Chosen seam: `callLLMJson` calls `callLLM` in the SAME module, and `callLLM`
// performs its network request through global `fetch`. Mocking the same-module
// `callLLM` is awkward (intra-module references aren't redirected by a module
// mock), so the cleanest, lowest-level seam is `global.fetch`. We exercise the
// REAL `callLLMJson` / `callLLM` implementations and only stub the network
// boundary:
//   - attempt 1 (first fetch)  -> returns unparseable text
//   - attempt 2 (second fetch) -> returns valid JSON
// and assert one parsed object comes back from a single `callLLMJson` call,
// with exactly two underlying attempts.
//
// _Requirements: 1.3_

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { vi } from "vitest";
import { callLLMJson } from "../netlify/functions/lib/llm.js";

// An OpenAI chat-completions style success response carrying `content` as the
// assistant message text — the exact shape `callLLM` parses.
function okCompletion(content) {
  return {
    ok: true,
    status: 200,
    text: async () => content,
    json: async () => ({ choices: [{ message: { content } }] }),
  };
}

describe("callLLMJson single internal retry maps one logical call to two attempts (Task 10.2, Req 1.3)", () => {
  let originalFetch;
  let hadApiKey;
  let originalApiKey;

  beforeEach(() => {
    originalFetch = global.fetch;
    hadApiKey = Object.prototype.hasOwnProperty.call(process.env, "OPENAI_API_KEY");
    originalApiKey = process.env.OPENAI_API_KEY;
    // callLLM throws early unless a key is present; give it a dummy so it
    // reaches the fetch path on both attempts.
    process.env.OPENAI_API_KEY = "test-dummy-key";
  });

  afterEach(() => {
    global.fetch = originalFetch;
    if (hadApiKey) process.env.OPENAI_API_KEY = originalApiKey;
    else delete process.env.OPENAI_API_KEY;
    vi.restoreAllMocks();
  });

  it("returns the parsed JSON from attempt 2 when attempt 1 is unparseable, via exactly two fetch calls", async () => {
    const validObj = { summary: "All clear.", topPriority: "Patch the login form first." };

    const fetchMock = vi
      .fn()
      // Attempt 1: unparseable text — no JSON object/array at all.
      .mockResolvedValueOnce(okCompletion("Sorry, I can't produce JSON right now."))
      // Attempt 2: valid JSON object.
      .mockResolvedValueOnce(okCompletion(JSON.stringify(validObj)));
    global.fetch = fetchMock;

    // ONE logical callLLMJson invocation.
    const result = await callLLMJson({
      system: "BASE SYSTEM PROMPT",
      messages: [{ role: "user", content: "synthesize" }],
      timeoutMs: 9000,
    });

    // The single logical call maps to exactly two underlying model attempts —
    // the retry is parse-robustness, NOT a second synthesis call.
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Exactly one parsed result is returned — the object from attempt 2.
    expect(result).toEqual(validObj);

    // The retry reuses the SAME logical request: attempt 2 keeps the base
    // system prompt and only appends the stricter JSON-only instruction.
    const firstBody = JSON.parse(fetchMock.mock.calls[0][1].body);
    const secondBody = JSON.parse(fetchMock.mock.calls[1][1].body);

    expect(firstBody.messages[0]).toEqual({ role: "system", content: "BASE SYSTEM PROMPT" });
    expect(secondBody.messages[0].role).toBe("system");
    expect(secondBody.messages[0].content).toContain("BASE SYSTEM PROMPT");
    expect(secondBody.messages[0].content).toContain(
      "CRITICAL: Return ONLY the raw JSON object, nothing else."
    );

    // The user message (the actual synthesis request) is identical across both
    // attempts — confirming it's the same logical call retried, not a new one.
    expect(secondBody.messages[1]).toEqual(firstBody.messages[1]);
  });

  it("does not retry when attempt 1 already parses — one logical call, one attempt", async () => {
    const validObj = { summary: "Looks healthy.", topPriority: "Maintain current posture." };

    const fetchMock = vi.fn().mockResolvedValueOnce(okCompletion(JSON.stringify(validObj)));
    global.fetch = fetchMock;

    const result = await callLLMJson({
      system: "BASE SYSTEM PROMPT",
      messages: [{ role: "user", content: "synthesize" }],
      timeoutMs: 9000,
    });

    // No parse failure -> no retry -> exactly one underlying attempt.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result).toEqual(validObj);
  });
});
