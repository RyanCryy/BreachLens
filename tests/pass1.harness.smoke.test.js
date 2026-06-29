// tests/pass1.harness.smoke.test.js
//
// Harness self-test for Task 1.1. Confirms:
//   - Vitest discovers tests under tests/ via **/*.test.js
//   - the single test seam (vi.mock of ./llm.js with importOriginal) works
//   - the controllable LLM double records every `opts` and can be programmed
//     per-call to resolve JSON, throw generic/parse errors, or time out
//   - the frozen runPass1 actually routes through callLLMJson (so later property
//     tests can assert prompt content + isolation through this seam)
//
// This file authors NO production change — llm.js, analysis.js, findings.js are
// untouched. It only mocks the llm.js module boundary.
//
// _Requirements: design "Testing Strategy" (property-based testing harness, controllable LLM double)_

import { describe, it, expect, beforeEach, vi } from "vitest";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export (extractJson,
// LLMError, callLLM) — identical to tests/chat.branches.test.js.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// A couple of plain findings — enough to exercise fan-out + per-call programming.
const FINDINGS = [
  { id: "spf-missing", type: "email-auth", label: "SPF record missing", detail: "No SPF record found." },
  { id: "dmarc-missing", type: "email-auth", label: "DMARC record missing", detail: "No DMARC record found." },
];

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 1 verification harness (Task 1.1)", () => {
  it("routes each finding through the mocked callLLMJson seam", async () => {
    llm.program(
      behaviors.resolveJson({ title: "A", explanation: "x", recommendation: "y", fixSnippet: null }),
      behaviors.resolveJson({ title: "B", explanation: "x", recommendation: "y", fixSnippet: null })
    );

    const results = await runPass1(FINDINGS, null, undefined);

    expect(llm.callCount).toBe(FINDINGS.length);
    expect(results).toHaveLength(FINDINGS.length);
    expect(results.every((r) => r._source === "llm")).toBe(true);
  });

  it("records every opts (system + messages content) for later assertions", async () => {
    llm.setDefault(behaviors.resolveJson({ title: "ok" }));

    await runPass1(FINDINGS, "Cloudflare", { detected: ["nginx"] });

    const opts = llm.opts();
    expect(opts).toHaveLength(FINDINGS.length);
    // system prompt is captured and non-empty
    expect(llm.systems().every((s) => typeof s === "string" && s.length > 0)).toBe(true);
    // user content carries the per-finding label, and Pass 1 config is visible
    expect(llm.userContents()[0]).toContain("SPF record missing");
    expect(opts[0]).toMatchObject({ maxTokens: 600, temperature: 0, timeoutMs: 9000 });
  });

  it("can program a generic error, a parse error, and a timeout per call", async () => {
    llm.program(
      behaviors.throwGeneric("boom"),
      behaviors.throwParse(),
      behaviors.timeout()
    );

    const findings = [
      { id: "f1", type: "header", label: "L1", detail: "D1" },
      { id: "f2", type: "header", label: "L2", detail: "D2" },
      { id: "f3", type: "header", label: "L3", detail: "D3" },
    ];

    const results = await runPass1(findings, null, undefined);

    // All three calls failed, so classifyOne degrades every finding to fallback.
    expect(llm.callCount).toBe(3);
    expect(results).toHaveLength(3);
    expect(results.every((r) => r._source === "fallback")).toBe(true);
  });

  it("does not invoke the seam for an empty finding list", async () => {
    const results = await runPass1([], null, undefined);
    expect(results).toEqual([]);
    expect(llm.callCount).toBe(0);
  });
});
