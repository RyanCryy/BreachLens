// tests/pass1.property9.oneach.test.js
//
// Property 9 — onEach is invoked once per finding and is failure-isolated.
//
// Feature: finding-classification, Property 9: onEach is invoked once per finding
// and is failure-isolated — For any non-empty list of findings with a supplied
// onEach callback, the callback is invoked exactly once per finding with that
// finding's Classification_Result; and for any such list where onEach always
// throws, runPass1 still resolves with exactly one result per input finding
// without rejecting.
//
// Validates: Requirements 10.1, 10.2
//
// Confirmed against the frozen implementation (analysis.js runPass1):
//
//   findings.map(async (f) => {
//     const result = await classifyOne(f, provider, tech);
//     if (typeof onEach === "function") {
//       try { onEach(result); } catch (_) {}
//     }
//     return result;
//   })
//
// So onEach is called once per finding, with the EXACT Classification_Result
// object that is also returned in the results array, and any throw from onEach
// is swallowed by the try/catch so the pass never rejects. Because runPass1 fans
// out concurrently and each call settles after a randomized delay, the ORDER in
// which onEach fires can differ from input order — the property is therefore
// asserted by object identity (set equality against the returned array), not by
// position, which makes "exactly once per finding with that finding's result" a
// genuine claim. An arbitrary subset of LLM calls fail so the callback receives
// a mix of _source === "llm" and _source === "fallback" results.
//
// This file authors NO production change — the only seam is the module-mock of
// ./llm.js's callLLMJson, exactly as the harness smoke test establishes.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { ParseError } from "./helpers/llm-double.js";
import { findingListArb } from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Build the thrown error for a programmed failure kind.
function failureError(kind) {
  if (kind === "timeout") {
    const e = new Error("The operation was aborted due to timeout");
    e.name = "AbortError";
    return e;
  }
  if (kind === "parse") return new ParseError();
  return new Error("LLM call failed");
}

// A scenario: a non-empty finding list plus a per-finding plan that decides
// whether its LLM call succeeds or fails (so the callback sees both llm- and
// fallback-sourced results), the failure kind, and a randomized settle delay
// that makes the onEach callbacks fire out of input order.
const scenarioArb = findingListArb({ minLength: 1, maxLength: 6 }).chain((findings) =>
  fc.record({
    findings: fc.constant(findings),
    plans: fc.array(
      fc.record({
        fail: fc.boolean(),
        failKind: fc.constantFrom("timeout", "parse", "generic"),
        delayMs: fc.integer({ min: 0, max: 12 }),
      }),
      { minLength: findings.length, maxLength: findings.length }
    ),
  })
);

// Wire the double from a per-finding plan list. Dispatch order of callLLMJson
// matches findings order (findings.map invokes each async classifyOne up to its
// first await), so a call counter binds each invocation to its plan.
function programFromPlans(plans) {
  let callIndex = 0;
  mockCallLLMJson.mockImplementation(async () => {
    const plan = plans[callIndex++];
    await delay(plan.delayMs);
    if (plan.fail) throw failureError(plan.failKind);
    return {
      title: "Generated title",
      explanation: "Generated explanation.",
      recommendation: "Generated recommendation.",
      fixSnippet: null,
    };
  });
}

beforeEach(() => {
  mockCallLLMJson.mockReset();
});

describe("Pass 1 — Property 9: onEach is invoked once per finding and is failure-isolated", () => {
  it("invokes onEach exactly once per finding with that finding's Classification_Result (Req 10.1)", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ findings, plans }) => {
        programFromPlans(plans);

        const onEach = vi.fn();
        const results = await runPass1(findings, null, undefined, onEach);

        // Exactly one result per input finding.
        expect(results).toHaveLength(findings.length);

        // onEach invoked exactly once per finding (Req 10.1).
        expect(onEach).toHaveBeenCalledTimes(findings.length);

        // Each invocation receives a single argument that is the EXACT
        // Classification_Result object also present in the returned array.
        // Asserting by object identity (set equality) proves "once per finding
        // with that finding's result" independent of callback firing order.
        const callArgs = onEach.mock.calls.map((c) => {
          expect(c).toHaveLength(1); // sole argument
          return c[0];
        });

        // Every returned result was passed to onEach exactly once (identity).
        for (const result of results) {
          const matches = callArgs.filter((arg) => arg === result);
          expect(matches).toHaveLength(1);
        }
        // ...and no callback received an object not in the results array.
        for (const arg of callArgs) {
          expect(results).toContain(arg);
        }
      }),
      { numRuns: 150 }
    );
  });

  it("resolves with one result per finding and does not reject when onEach always throws (Req 10.2)", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ findings, plans }) => {
        programFromPlans(plans);

        // An onEach that throws on every invocation. The frozen runPass1 wraps
        // the call in try/catch, so this must be swallowed.
        const throwCount = { n: 0 };
        const onEach = vi.fn(() => {
          throwCount.n++;
          throw new Error("onEach boom");
        });

        // Must resolve (not reject) despite every callback throwing.
        const results = await runPass1(findings, null, undefined, onEach);

        // Still exactly one result per input finding (Req 10.2).
        expect(results).toHaveLength(findings.length);

        // The callback was invoked once per finding and threw each time, yet the
        // pass completed and every result is still present.
        expect(onEach).toHaveBeenCalledTimes(findings.length);
        expect(throwCount.n).toBe(findings.length);
        for (const result of results) {
          expect(result).toHaveProperty("id");
          expect(result).toHaveProperty("type");
          expect(["llm", "fallback"]).toContain(result._source);
        }
      }),
      { numRuns: 150 }
    );
  });

  it("explicit example: out-of-order callback firing still delivers each result once", async () => {
    const findings = [
      { id: "spf-missing", type: "email-auth", label: "L0", detail: "D0" },
      { id: "hdr-hsts", type: "header", label: "L1", detail: "D1" },
      { id: "exposed-file-/.env", type: "exposure", path: "/.env", label: "L2", detail: "D2" },
      { id: "subdomain-dev.example.com", type: "subdomain", label: "L3", detail: "D3" },
    ];

    // Later findings settle FIRST, so onEach fires in reverse-ish order.
    let callIndex = 0;
    mockCallLLMJson.mockImplementation(async () => {
      const i = callIndex++;
      await delay((findings.length - 1 - i) * 5);
      return { title: `T${i}`, explanation: "e", recommendation: "r", fixSnippet: null };
    });

    const received = [];
    const onEach = vi.fn((r) => received.push(r));

    const results = await runPass1(findings, null, undefined, onEach);

    expect(results).toHaveLength(findings.length);
    expect(onEach).toHaveBeenCalledTimes(findings.length);
    // Same set of objects, regardless of order.
    expect(new Set(received)).toEqual(new Set(results));
  });
});
