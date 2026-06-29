// tests/pass2.harness.smoke.test.js
//
// Task 1.1 — Confirm the `callLLMJson` module-mock seam supports `runPass2`
// without a production refactor.
//
// Feature: analyst-synthesis
// Validates: Requirements 1.1
//
// This is a HARNESS SMOKE TEST. Its sole purpose is to prove that the existing
// single test seam — a `vi.mock` of `netlify/functions/lib/llm.js`'s
// `callLLMJson` export (keeping every other real export) — is sufficient to
// drive `runPass2` hermetically, exactly as the Pass 1 suite drives `runPass1`
// (see tests/pass1.property2.alignment.test.js).
//
// It demonstrates three things through the seam, with NO production change:
//   1. The spy is invoked exactly once for a non-empty finding set.
//   2. The spy captures `opts` (system + messages) handed to `callLLMJson`.
//   3. A programmed resolve flows back into `runPass2` (prose used, _source "llm")
//      AND a programmed throw flows back into `runPass2` (deterministic fallback,
//      _source "fallback").
//
// Because `runPass2` is the synthesis function exercised by the `aiPipeline`
// orchestration in scan.js, proving the seam here proves the whole stack is
// testable through it — so no behavior-preserving seam needs to be added to
// analysis.js or scan.js.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export
// (extractJson, callLLM, LLMError, ...) intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// A minimal, valid non-empty Classified_Finding set (one finding is enough for
// a smoke test). `recommendation` is present so the topPriority fallback path
// has a deterministic value to read.
const classified = [
  {
    id: "hdr-hsts",
    type: "header",
    title: "Missing HSTS header",
    severity: "high",
    explanation: "The site does not send Strict-Transport-Security.",
    recommendation: "Add a Strict-Transport-Security response header.",
    fixSnippet: null,
    _source: "llm",
  },
];

const domain = "example.com";
const tech = { detected: ["nginx"] };

let llm;

beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 2 harness smoke — callLLMJson module-mock seam drives runPass2", () => {
  it("invokes the spy exactly once and captures opts (system + messages)", async () => {
    llm.program(behaviors.resolveJson({ summary: "s", topPriority: "p" }));

    await runPass2(classified, domain, tech);

    // The seam captured the single call.
    expect(llm.callCount).toBe(1);

    // opts (system + messages) were handed to callLLMJson through the seam.
    const [opts] = llm.opts();
    expect(opts).toBeTruthy();
    expect(typeof opts.system).toBe("string");
    expect(opts.system.length).toBeGreaterThan(0);
    expect(Array.isArray(opts.messages)).toBe(true);
    expect(opts.messages.length).toBeGreaterThan(0);
    // The user message content is a non-empty string the test can inspect.
    expect(typeof opts.messages[0].content).toBe("string");
    expect(opts.messages[0].content.length).toBeGreaterThan(0);
  });

  it("flows a programmed resolve back into runPass2 (prose used, _source 'llm')", async () => {
    llm.program(
      behaviors.resolveJson({
        summary: "Programmed executive summary.",
        topPriority: "Programmed top priority.",
      })
    );

    const report = await runPass2(classified, domain, tech);

    // The resolved value programmed onto the spy flowed back into runPass2.
    expect(report.summary).toBe("Programmed executive summary.");
    expect(report.topPriority).toBe("Programmed top priority.");
    expect(report._source).toBe("llm");
  });

  it("flows a programmed throw back into runPass2 (deterministic fallback, _source 'fallback')", async () => {
    llm.program(behaviors.throwGeneric("simulated synthesis failure"));

    const report = await runPass2(classified, domain, tech);

    // The thrown error programmed onto the spy was caught inside runPass2 and
    // produced the deterministic fallback report.
    expect(llm.callCount).toBe(1);
    expect(report._source).toBe("fallback");
    // Fallback topPriority is the (sorted) top finding's recommendation.
    expect(report.topPriority).toBe(classified[0].recommendation);
    expect(typeof report.summary).toBe("string");
    expect(report.summary.length).toBeGreaterThan(0);
  });
});
