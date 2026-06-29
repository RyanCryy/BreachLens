// tests/pass1.timeout-retry.test.js
//
// Pass 1 per-call timeout / retry verification suite.
// =============================================================================
//
// This file covers the per-call bounding behavior of Pass 1 (Requirement 7).
//
//   - Task 8.1 (THIS task): via the captured `callLLMJson` opts, assert that
//     EVERY Pass 1 classification call is issued with `timeoutMs === 9000`
//     (and `temperature === 0`, `maxTokens === 600`).  (Req 7.1)
//
//   - Task 8.2 (LATER): AbortController abort + single-retry wiring inside
//     callLLMJson/callLLM, driven with mocked `global.fetch` + Vitest fake
//     timers.  (Req 7.2, 7.3, 7.4)  -> appended as additional describe blocks.
//
// Single test seam (no production change): module-mock `./llm.js`'s
// `callLLMJson` export, exactly as tests/pass1.harness.smoke.test.js does, and
// inspect the opts each Pass 1 call passes to it.
//
// _Requirements: 7.1_

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import { findingListArb } from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

const PASS1_CALL_OPTS = { maxTokens: 600, temperature: 0, timeoutMs: 9000 };

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

// =============================================================================
//  Task 8.1 — per-call timeout / config values (Req 7.1)
// =============================================================================
describe("Pass 1 per-call timeout & config values (Task 8.1, Req 7.1)", () => {
  it("passes timeoutMs: 9000, temperature: 0, maxTokens: 600 on a representative call", async () => {
    llm.setDefault(behaviors.resolveJson({ title: "ok" }));

    await runPass1(
      [{ id: "spf-missing", type: "email-auth", label: "SPF missing", detail: "No SPF record." }],
      null,
      undefined
    );

    expect(llm.callCount).toBe(1);
    expect(llm.opts()[0]).toMatchObject(PASS1_CALL_OPTS);
  });

  it("applies the same per-call timeout to EVERY call across an arbitrary finding list", async () => {
    await fc.assert(
      fc.asyncProperty(findingListArb({ minLength: 1, maxLength: 8 }), async (findings) => {
        llm.reset();
        llm.setDefault(behaviors.resolveJson({ title: "ok" }));

        await runPass1(findings, null, undefined);

        // One call per finding, and EACH carries the Pass 1 per-call config.
        expect(llm.callCount).toBe(findings.length);
        const opts = llm.opts();
        expect(opts).toHaveLength(findings.length);
        for (const o of opts) {
          expect(o.timeoutMs).toBe(9000);
          expect(o.temperature).toBe(0);
          expect(o.maxTokens).toBe(600);
        }
      }),
      { numRuns: 100 }
    );
  });

  it("uses the same per-call config even when calls fail (fallback path)", async () => {
    // The timeoutMs/temperature/maxTokens are fixed regardless of outcome:
    // a failing call still must have been issued with the bounded config.
    llm.program(
      behaviors.resolveJson({ title: "ok" }),
      behaviors.timeout(),
      behaviors.throwParse(),
      behaviors.throwGeneric()
    );

    const findings = [
      { id: "f1", type: "header", label: "L1", detail: "D1" },
      { id: "f2", type: "header", label: "L2", detail: "D2" },
      { id: "f3", type: "header", label: "L3", detail: "D3" },
      { id: "f4", type: "header", label: "L4", detail: "D4" },
    ];

    await runPass1(findings, null, undefined);

    expect(llm.callCount).toBe(findings.length);
    for (const o of llm.opts()) {
      expect(o).toMatchObject(PASS1_CALL_OPTS);
    }
  });

  it("keeps the per-call config independent of provider / tech context", async () => {
    llm.setDefault(behaviors.resolveJson({ title: "ok" }));

    await runPass1(
      [{ id: "caa-missing", type: "dns", label: "No CAA", detail: "No CAA record." }],
      "Cloudflare ⟦PROV⟧",
      { server: "nginx", poweredBy: null, detected: ["WordPress", "PHP"] }
    );

    expect(llm.opts()[0]).toMatchObject(PASS1_CALL_OPTS);
  });
});

// =============================================================================
//  Task 8.2 — AbortController abort + single-retry wiring (Req 7.2, 7.3, 7.4)
// =============================================================================
//
// Unlike the Task 8.1 block above, these are INTEGRATION tests that exercise the
// REAL `callLLM` / `callLLMJson` implementations (not the module mock). Only the
// network boundary (`global.fetch`) is mocked, and Vitest fake timers drive the
// 9000 ms per-call abort timer. We pull the genuine, unmocked exports via
// `vi.importActual` so the abort/retry wiring is truly under test.
//
//   - Req 7.2: a hanging fetch is aborted via the AbortController once the
//     9000 ms timer fires.
//   - Req 7.3: an unparseable-then-valid sequence triggers EXACTLY ONE retry,
//     and the retry's system prompt carries the stricter JSON-only suffix.
//   - Req 7.4: both attempts failing makes `callLLMJson` throw, so `classifyOne`
//     (reached through `runPass1`) returns the `_source: "fallback"` result.
//
// _Requirements: 7.2, 7.3, 7.4_

// An AbortError-shaped rejection, matching what a real fetch raises when its
// AbortSignal fires.
function abortError() {
  const e = new Error("The operation was aborted");
  e.name = "AbortError";
  return e;
}

// A fetch that never settles on its own — it only rejects when its AbortSignal
// fires. This lets the test prove the AbortController (driven by the 9000 ms
// timer) is what tears the in-flight request down.
function makeHangingFetch() {
  return vi.fn((_url, init) => {
    return new Promise((_resolve, reject) => {
      const signal = init && init.signal;
      if (signal && signal.aborted) {
        reject(abortError());
        return;
      }
      if (signal) {
        signal.addEventListener("abort", () => reject(abortError()));
      }
    });
  });
}

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

describe("Pass 1 AbortController abort + single-retry wiring (Task 8.2, Req 7.2/7.3/7.4)", () => {
  let realLlm;
  let originalFetch;
  let hadApiKey;
  let originalApiKey;

  beforeEach(async () => {
    // Genuine, unmocked llm.js — bypasses the file-level callLLMJson mock so the
    // real abort/retry logic is exercised.
    realLlm = await vi.importActual("../netlify/functions/lib/llm.js");

    originalFetch = global.fetch;
    hadApiKey = Object.prototype.hasOwnProperty.call(process.env, "OPENAI_API_KEY");
    originalApiKey = process.env.OPENAI_API_KEY;
    // callLLM throws early unless a key is present; give it a dummy so it reaches
    // the fetch/abort path.
    process.env.OPENAI_API_KEY = "test-dummy-key";

    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();

    // Restore fetch.
    global.fetch = originalFetch;

    // Restore the API key exactly as it was.
    if (hadApiKey) process.env.OPENAI_API_KEY = originalApiKey;
    else delete process.env.OPENAI_API_KEY;
  });

  it("aborts the in-flight fetch via AbortController once the 9000 ms timer fires (Req 7.2)", async () => {
    const fetchMock = makeHangingFetch();
    global.fetch = fetchMock;

    // Kick off the call; capture rejection so it doesn't surface as unhandled.
    let caught;
    const p = realLlm
      .callLLM({
        system: "sys",
        messages: [{ role: "user", content: "hi" }],
        timeoutMs: 9000,
      })
      .catch((e) => {
        caught = e;
      });

    // The fetch has been issued, with a not-yet-aborted signal.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const signal = fetchMock.mock.calls[0][1].signal;
    expect(signal.aborted).toBe(false);

    // Anything short of the timeout must NOT abort.
    await vi.advanceTimersByTimeAsync(8999);
    expect(signal.aborted).toBe(false);

    // The 9000 ms timer fires -> controller.abort() -> fetch rejects.
    await vi.advanceTimersByTimeAsync(1);
    await p;

    expect(signal.aborted).toBe(true);
    expect(caught).toBeInstanceOf(Error);
  });

  it("retries exactly once with the stricter JSON-only suffix after an unparseable response (Req 7.3)", async () => {
    const validObj = { title: "ok", value: 42 };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okCompletion("totally not json — no object here"))
      .mockResolvedValueOnce(okCompletion(JSON.stringify(validObj)));
    global.fetch = fetchMock;

    const result = await realLlm.callLLMJson({
      system: "BASE SYSTEM PROMPT",
      messages: [{ role: "user", content: "classify" }],
      timeoutMs: 9000,
    });

    // Exactly one retry: two fetches total, no more.
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const firstBody = JSON.parse(fetchMock.mock.calls[0][1].body);
    const secondBody = JSON.parse(fetchMock.mock.calls[1][1].body);

    // Attempt 1 carries the unmodified base system prompt.
    expect(firstBody.messages[0]).toEqual({ role: "system", content: "BASE SYSTEM PROMPT" });

    // Attempt 2 (the retry) keeps the base prompt AND appends the stricter
    // JSON-only suffix.
    expect(secondBody.messages[0].role).toBe("system");
    expect(secondBody.messages[0].content).toContain("BASE SYSTEM PROMPT");
    expect(secondBody.messages[0].content).toContain(
      "CRITICAL: Return ONLY the raw JSON object, nothing else."
    );

    // And the retry's parsed output is returned.
    expect(result).toEqual(validObj);
  });

  it("throws after both attempts fail to parse, so classifyOne falls back to _source: 'fallback' (Req 7.4)", async () => {
    // Route the file-level callLLMJson mock to the REAL implementation so that
    // runPass1 -> classifyOne genuinely drives the abort/retry/throw wiring.
    mockCallLLMJson.mockImplementation((opts) => realLlm.callLLMJson(opts));

    // Both the initial attempt and the single retry return unparseable output.
    const fetchMock = vi.fn().mockResolvedValue(okCompletion("<<< not json at all >>>"));
    global.fetch = fetchMock;

    const findings = [
      { id: "spf-missing", type: "email-auth", label: "SPF missing", detail: "No SPF record." },
    ];

    const results = await runPass1(findings, null, undefined);

    // callLLMJson threw -> classifyOne degraded -> exactly one fallback result.
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("spf-missing");
    expect(results[0].type).toBe("email-auth");
    expect(results[0]._source).toBe("fallback");

    // Two attempts (initial + single retry) were made before the throw.
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
