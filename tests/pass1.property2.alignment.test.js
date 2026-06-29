// tests/pass1.property2.alignment.test.js
//
// Property 2 — Output is positionally aligned and identity-preserving.
//
// Feature: finding-classification, Property 2: Output is positionally aligned and
// identity-preserving — For any list of findings (with arbitrary per-call
// completion ordering), runPass1 returns a list of the same length where, for
// every index i, result[i].id === findings[i].id and result[i].type ===
// findings[i].type, regardless of whether each result came from the LLM or the
// fallback.
//
// Validates: Requirements 2.3, 9.2, 12.1, 12.2
//
// runPass1 fans out over findings via Promise.all. Promise.all preserves input
// order regardless of the order in which the individual calls settle, so to make
// this a GENUINE test of positional alignment we drive the controllable LLM
// double to settle OUT OF ORDER: each per-call behavior waits a randomized,
// fast-check-generated delay before resolving (LLM-sourced result) or rejecting
// (fallback-sourced result). An arbitrary subset of calls fail, so the returned
// list mixes _source === "llm" and _source === "fallback" entries — and the
// property must hold across both.
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

// A scenario: a non-empty finding list plus a parallel "plan" per finding that
// decides whether its LLM call succeeds or fails, the failure kind, and the
// randomized settle delay that induces out-of-order completion.
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

beforeEach(() => {
  mockCallLLMJson.mockReset();
});

describe("Pass 1 — Property 2: positional alignment & identity preservation", () => {
  it("preserves id/type at every index across randomized completion order and mixed sources", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async ({ findings, plans }) => {
        // Dispatch order of classifyOne (and therefore of callLLMJson) matches
        // findings order, because findings.map() invokes each async classifyOne
        // synchronously up to its first await (the callLLMJson call). We use a
        // call counter to bind each invocation to its finding's plan, then await
        // a randomized delay so calls SETTLE out of order while Promise.all must
        // still return results in input order.
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

        const results = await runPass1(findings, null, undefined);

        // Same length: exactly one result per input finding (Req 9.2, 12.x).
        expect(results).toHaveLength(findings.length);

        // Positional alignment + identity preservation at every index, for BOTH
        // llm-sourced and fallback-sourced results (Req 2.3, 12.1, 12.2).
        for (let i = 0; i < findings.length; i++) {
          expect(results[i].id).toBe(findings[i].id);
          expect(results[i].type).toBe(findings[i].type);
          // Provenance is derived from this index's plan (dispatch order = input
          // order), confirming the assertion spans both sources.
          expect(results[i]._source).toBe(plans[i].fail ? "fallback" : "llm");
        }
      }),
      { numRuns: 150 }
    );
  });

  it("holds when calls settle in strict reverse order (explicit out-of-order example)", async () => {
    const findings = [
      { id: "spf-missing", type: "email-auth", label: "L0", detail: "D0" },
      { id: "hdr-hsts", type: "header", label: "L1", detail: "D1" },
      { id: "exposed-file-/.env", type: "exposure", path: "/.env", label: "L2", detail: "D2" },
      { id: "subdomain-dev.example.com", type: "subdomain", label: "L3", detail: "D3" },
    ];

    // Later findings resolve FIRST: invocation i waits (N-1-i)*5 ms, forcing the
    // last finding to settle before the first.
    let callIndex = 0;
    mockCallLLMJson.mockImplementation(async () => {
      const i = callIndex++;
      await delay((findings.length - 1 - i) * 5);
      return { title: `T${i}`, explanation: "e", recommendation: "r", fixSnippet: null };
    });

    const results = await runPass1(findings, null, undefined);

    expect(results).toHaveLength(findings.length);
    results.forEach((r, i) => {
      expect(r.id).toBe(findings[i].id);
      expect(r.type).toBe(findings[i].type);
    });
  });
});
