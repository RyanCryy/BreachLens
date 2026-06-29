// tests/pass2.prompt-content.test.js
//
// Task 10.1 — Prompt-content example test.
//
// Feature: analyst-synthesis
// Validates: Requirements 4.2, 4.3, 4.4
//
// This is an EXAMPLE-BASED unit test (NOT a property test). It verifies the
// EXISTING production wording of the `PASS2_SYSTEM` prompt in
// netlify/functions/lib/analysis.js. No production code is modified.
//
// `PASS2_SYSTEM` is not exported, so we capture it through the single test seam
// the rest of this suite uses: module-mock `callLLMJson` and read the `system`
// string actually handed to it when `runPass2` is driven once (same pattern as
// tests/pass2.harness.smoke.test.js).
//
// Assertions on the captured system prompt:
//   (a) Req 4.2 — declares the provided risk level authoritative and asks the
//       model to write consistently with it.
//   (b) Req 4.3 — instructs the model NOT to output its own score / risk level.
//   (c) Req 4.4 — requests a JSON object whose only fields are `summary` and
//       `topPriority`.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { attachDouble, behaviors } from "./helpers/llm-double.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export intact.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass2 } from "../netlify/functions/lib/analysis.js";

// A minimal, valid non-empty Classified_Finding set so runPass2 reaches the
// LLM_Client call and the seam captures opts.system.
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

describe("Pass 2 prompt content — PASS2_SYSTEM wording (Req 4.2–4.4)", () => {
  async function captureSystemPrompt() {
    llm.program(behaviors.resolveJson({ summary: "s", topPriority: "p" }));
    await runPass2(classified, domain, tech);
    expect(llm.callCount).toBe(1);
    const [opts] = llm.opts();
    expect(opts).toBeTruthy();
    expect(typeof opts.system).toBe("string");
    return opts.system;
  }

  it("declares the provided risk level authoritative (Req 4.2)", async () => {
    const system = await captureSystemPrompt();

    // States the provided risk level is authoritative.
    expect(system).toMatch(/risk level as authoritative/i);
    // Asks the model to write prose consistent with that risk level.
    expect(system).toMatch(/consistent(ly)?\s+with\s+it/i);
  });

  it("forbids the model from emitting its own score / risk level (Req 4.3)", async () => {
    const system = await captureSystemPrompt();

    // Explicit instruction not to output its own score or risk level.
    expect(system).toMatch(/do\s*not\s+output\s+your\s+own\s+score\s+or\s+risk\s+level/i);
  });

  it("requests a JSON object whose only fields are summary and topPriority (Req 4.4)", async () => {
    const system = await captureSystemPrompt();

    // Asks for ONLY a JSON object.
    expect(system).toMatch(/return only a json object/i);
    // The exact shape names both fields and no others.
    expect(system).toMatch(/"summary"\s*:\s*string/i);
    expect(system).toMatch(/"topPriority"\s*:\s*string/i);

    // Verify the declared object shape contains exactly summary + topPriority.
    const shapeMatch = system.match(/\{[^{}]*"summary"[^{}]*\}/);
    expect(shapeMatch).toBeTruthy();
    const shape = shapeMatch[0];
    const fieldNames = [...shape.matchAll(/"([A-Za-z0-9_]+)"\s*:/g)].map((m) => m[1]);
    expect(fieldNames.sort()).toEqual(["summary", "topPriority"]);
  });
});
