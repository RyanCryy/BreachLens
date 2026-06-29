import { describe, it, expect, beforeEach, vi } from "vitest";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so that the
// `callLLMJson` dependency inside `classifyOne`/`runPass1` is the auto-mocked
// vi.fn — no network, fully in-memory, and fully controllable by this test.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass1 } from "./analysis.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — Example/edge test
// Requirement 2.5: "THE Scanner SHALL initiate the classification of all
// Findings in Pass_1 concurrently and await their collective completion before
// proceeding."
//
// This is an example/edge test (not a numbered Property), so it carries no
// "Property N" tag. It pins the concurrency contract of `runPass1`, which
// dispatches every finding's `classifyOne` via `Promise.all`.
//
// Strategy ("all dispatched before any resolves"):
//   - Replace `callLLMJson` with a spy that records each call's initiation
//     ORDER synchronously and returns a *pending* deferred promise (it does NOT
//     resolve immediately).
//   - Invoke `runPass1(findings, ...)` WITHOUT awaiting. Because `runPass1`
//     maps every finding through an async `classifyOne` that runs synchronously
//     up to its first `await callLLMJson(...)`, all N calls are initiated
//     before any one of them is allowed to settle.
//   - Assert the spy was initiated exactly once per finding while every call is
//     still pending (nothing has resolved yet) — i.e. concurrent dispatch, not
//     sequential one-at-a-time awaiting.
//   - Only then resolve all deferreds, await `runPass1`, and assert it returns
//     exactly one result per finding (collective completion).
// ---------------------------------------------------------------------------

// A representative spread of pre-classification findings (shapes accepted by
// `classifyOne` / `fallbackClassify`). Content is irrelevant to concurrency;
// the count is what matters.
const FINDINGS = [
  { id: "spf-missing", type: "email-auth", label: "Missing SPF record", detail: "No SPF TXT record found." },
  { id: "dmarc-missing", type: "email-auth", label: "Missing DMARC record", detail: "No DMARC policy found." },
  { id: "hdr-hsts", type: "header", label: "Missing HSTS", detail: "No Strict-Transport-Security header." },
  { id: "exposed-file-/.env", type: "exposure", path: "/.env", label: "Exposed .env", detail: "/.env is reachable." },
  { id: "subdomain-admin", type: "subdomain", label: "admin subdomain", detail: "admin.example.com is public." },
];

describe("Feature: deterministic-fallback — runPass1 dispatches all findings concurrently (Requirement 2.5)", () => {
  beforeEach(() => {
    callLLMJson.mockReset();
  });

  it("initiates the LLM call for every finding before any call resolves, and returns one result per finding", async () => {
    // Deferred plumbing: one externally-resolvable promise per call.
    const deferreds = [];
    const initiationOrder = [];
    let resolvedCount = 0;

    callLLMJson.mockImplementation((opts) => {
      // Record initiation ORDER synchronously, the instant the call is made.
      initiationOrder.push(callLLMJson.mock.calls.length - 1);
      return new Promise((resolve) => {
        deferreds.push(() => {
          resolvedCount += 1;
          // Minimal valid Pass 1 prose; severity is set deterministically by
          // production regardless of this payload.
          resolve({
            title: "t",
            explanation: "e",
            recommendation: "r",
            fixSnippet: null,
          });
        });
      });
    });

    // Kick off Pass 1 but DO NOT await it yet.
    const pending = runPass1(FINDINGS, null, null);

    // Synchronously after dispatch, every finding's call must already be in
    // flight: the map ran each async classifyOne up to its first
    // `await callLLMJson(...)`, so all N calls were initiated.
    expect(callLLMJson).toHaveBeenCalledTimes(FINDINGS.length);
    expect(deferreds.length).toBe(FINDINGS.length);

    // Let any pending microtasks drain — still nothing should have resolved,
    // because the deferreds are held open. This proves the calls were
    // dispatched concurrently rather than awaited sequentially (a sequential
    // implementation would have initiated only the first call and be blocked
    // awaiting it here).
    await Promise.resolve();
    expect(resolvedCount).toBe(0);
    expect(callLLMJson).toHaveBeenCalledTimes(FINDINGS.length);

    // Initiation order is dense 0..N-1 — every finding got exactly one call.
    expect(initiationOrder).toEqual(FINDINGS.map((_, i) => i));

    // Now release every deferred and await collective completion.
    deferreds.forEach((resolveIt) => resolveIt());
    const results = await pending;

    // Exactly one result per finding, in input order, all tagged from a
    // successful LLM call.
    expect(results).toHaveLength(FINDINGS.length);
    expect(results.map((r) => r.id)).toEqual(FINDINGS.map((f) => f.id));
    for (const r of results) {
      expect(r._source).toBe("llm");
    }
  });
});
