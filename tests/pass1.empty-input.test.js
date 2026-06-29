// tests/pass1.empty-input.test.js
//
// Task 7.1 — empty-input short-circuit and callback boundaries.
// =============================================================================
//
// EXAMPLE-BASED edge-case tests (NOT a property test) for `runPass1`'s two
// boundary behaviors:
//
//   1. Empty findings list short-circuits: `runPass1([])` returns `[]`, issues
//      ZERO LLM calls (the callLLMJson double is never invoked), never runs the
//      per-finding classification routine, and never invokes a supplied `onEach`
//      callback.  (Req 1.4, 2.4, 10.4, 11.1, 11.2, 11.3)
//
//   2. Non-function / omitted `onEach`: a NON-EMPTY finding list classifies
//      fully and returns exactly one result per finding WITHOUT throwing and
//      WITHOUT any callback invocation, whether `onEach` is omitted, undefined,
//      null, or a non-function value.  (Req 10.3)
//
// The frozen production guards being exercised (analysis.js):
//   - `if (findings.length === 0) return [];`        → short-circuit
//   - `if (typeof onEach === "function") { ... }`    → non-function guard
//
// This file authors NO production change — the only seam is the standard
// vi.mock of ./llm.js (matching the harness smoke test), so we can assert the
// callLLMJson double was never called on the empty path.
//
// _Requirements: 1.4, 2.4, 10.3, 10.4, 11.1, 11.2, 11.3_

import { describe, it, expect, beforeEach, vi } from "vitest";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// A small non-empty list for the non-function-onEach cases.
const FINDINGS = [
  { id: "spf-missing", type: "email-auth", label: "SPF record missing", detail: "No SPF record found." },
  { id: "hdr-hsts", type: "header", label: "HSTS header missing", detail: "No HSTS header returned." },
  { id: "exposed-file-/.env", type: "exposure", path: "/.env", label: "Exposed file: /.env", detail: "GET /.env returned 200." },
];

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  // Default any (unexpected) call to a harmless valid JSON resolve so the
  // non-empty cases classify cleanly via the llm path.
  llm = attachDouble(mockCallLLMJson, {
    default: behaviors.resolveJson({
      title: "t",
      explanation: "x",
      recommendation: "y",
      fixSnippet: null,
    }),
  });
});

describe("Pass 1 empty-input short-circuit (Task 7.1)", () => {
  it("returns an empty list for an empty findings list (Req 1.4, 11.1)", async () => {
    const results = await runPass1([], null, undefined);
    expect(results).toEqual([]);
    expect(Array.isArray(results)).toBe(true);
    expect(results).toHaveLength(0);
  });

  it("issues ZERO LLM calls on empty input — no per-finding routine runs (Req 2.4, 11.2, 11.3)", async () => {
    await runPass1([], null, undefined);
    // The callLLMJson double is the only path classifyOne can take to reach the
    // model; a zero call count proves classifyOne was never invoked for any
    // finding (there are none) and no LLM call was issued.
    expect(llm.callCount).toBe(0);
    expect(mockCallLLMJson).not.toHaveBeenCalled();
  });

  it("never invokes a supplied onEach callback on empty input (Req 10.4)", async () => {
    const onEach = vi.fn();
    const results = await runPass1([], null, undefined, onEach);
    expect(results).toEqual([]);
    expect(onEach).not.toHaveBeenCalled();
    expect(llm.callCount).toBe(0);
  });

  it("short-circuits regardless of provider/tech context (Req 1.4, 11.1, 11.2)", async () => {
    const onEach = vi.fn();
    const results = await runPass1([], "Cloudflare", { detected: ["nginx"] }, onEach);
    expect(results).toEqual([]);
    expect(onEach).not.toHaveBeenCalled();
    expect(llm.callCount).toBe(0);
  });
});

describe("Pass 1 non-function / omitted onEach (Task 7.1, Req 10.3)", () => {
  it("classifies a non-empty list with onEach OMITTED — one result per finding, no throw", async () => {
    // onEach argument not supplied at all.
    const results = await runPass1(FINDINGS, null, undefined);
    expect(results).toHaveLength(FINDINGS.length);
    expect(results.map((r) => r.id)).toEqual(FINDINGS.map((f) => f.id));
    expect(llm.callCount).toBe(FINDINGS.length);
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["a number", 42],
    ["a string", "not-a-function"],
    ["an object", { call: true }],
    ["true", true],
  ])("classifies fully when onEach is %s, without throwing or any callback (Req 10.3)", async (_label, badOnEach) => {
    const results = await runPass1(FINDINGS, null, undefined, badOnEach);

    // Full classification: exactly one result per input finding, in order.
    expect(results).toHaveLength(FINDINGS.length);
    expect(results.map((r) => r.id)).toEqual(FINDINGS.map((f) => f.id));
    expect(results.map((r) => r.type)).toEqual(FINDINGS.map((f) => f.type));

    // The non-function guard means the value is never invoked. The only kinds of
    // value that COULD be invoked are functions; we assert the run completed and
    // produced results without error for every non-function shape above.
    expect(llm.callCount).toBe(FINDINGS.length);
    expect(results.every((r) => r._source === "llm")).toBe(true);
  });
});
