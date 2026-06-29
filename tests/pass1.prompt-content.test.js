// tests/pass1.prompt-content.test.js
//
// Task 6.1 — Fixed prompt-content example test.
//
// Drives ONE runPass1 call through the controllable LLM double and asserts the
// captured `system` string contains the static directives that pass1System
// emits. This is an EXAMPLE-based test (not a property test): the prompt wording
// is fixed and does not vary with input, so we assert the real, literal phrasing
// produced by the frozen netlify/functions/lib/analysis.js `pass1System`.
//
// The single test seam is the vi.mock of ./llm.js (callLLMJson) — identical to
// the harness smoke test. NO production file is edited.
//
// Asserted directives (matching the exact phrasing in analysis.js):
//   - score-one-finding-in-isolation directive            (Req 1.2)
//   - exact JSON-shape instruction + "do NOT assign a severity" rule (Req 3.4)
//   - email-auth/CAA inline-literal-record instruction    (Req 6.1)
//   - never-infer/guess-a-provider line                   (Req 4.3)
//   - with provider = null, the generic provider-agnostic branch (Req 4.2)
//   - with non-empty tech.detected, the optional-guidance tech framing (Req 5.2)
//
// _Requirements: 1.2, 3.4, 6.1, 4.3, 4.2, 5.2_

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

// A single finding is enough — the system prompt is identical for every call in
// a given runPass1 invocation (it depends only on provider + tech).
const FINDING = {
  id: "spf-missing",
  type: "email-auth",
  label: "Missing SPF record",
  detail: "No SPF TXT record was found.",
};

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
  llm.setDefault(behaviors.resolveJson({ title: "ok", explanation: "x", recommendation: "y", fixSnippet: null }));
});

describe("Pass 1 fixed prompt content (Task 6.1)", () => {
  it("captures the system prompt with provider=null and a non-empty tech stack", async () => {
    // provider = null exercises the generic provider-agnostic branch (Req 4.2);
    // non-empty tech.detected exercises the optional tech-context line (Req 5.2).
    await runPass1([FINDING], null, { detected: ["nginx", "WordPress"] });

    expect(llm.callCount).toBe(1);
    const system = llm.systems()[0];
    expect(typeof system).toBe("string");
    expect(system.length).toBeGreaterThan(0);
  });

  it("contains the score-one-finding-in-isolation directive (Req 1.2)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    expect(system).toContain("scoring exactly ONE finding in isolation");
    expect(system).toContain(
      "do NOT assume the presence or absence of other issues"
    );
  });

  it("contains the exact JSON-shape instruction and the do-NOT-assign-a-severity rule (Req 3.4)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    // The exact JSON shape the model is told to return.
    expect(system).toContain("Return ONLY a JSON object with this exact shape:");
    expect(system).toContain(
      '{ "title": string, "explanation": string, "recommendation": string, "fixSnippet": string | null }'
    );

    // The explicit instruction that the model must not assign severity.
    expect(system).toContain(
      "Do NOT assign a severity — severity is determined separately by a fixed deterministic rule, not by you."
    );
  });

  it("contains the email-auth/CAA inline-literal-record instruction (Req 6.1)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    expect(system).toContain(
      "For email-authentication (SPF, DMARC) and CAA findings specifically, the recommendation text MUST contain the exact, literal, copy-pasteable record value inline"
    );
  });

  it("contains the never-infer/guess-a-provider line (Req 4.3)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    expect(system).toContain(
      "NEVER infer, guess, or name a specific DNS/hosting provider yourself."
    );
    expect(system).toContain(
      "Only reference a provider by name if one was explicitly given to you above as a confidently-matched value."
    );
  });

  it("emits the generic, provider-agnostic branch when provider is null (Req 4.2)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    expect(system).toContain(
      "The DNS/hosting provider could NOT be confidently identified. You MUST give generic, provider-agnostic fix instructions"
    );
    expect(system).toContain(
      "Do NOT name or guess any specific provider, platform, or registrar."
    );

    // And with provider=null it must NOT emit the "confidently identified ... as <name>" tailoring branch.
    expect(system).not.toContain("has been CONFIDENTLY identified");
  });

  it("frames the tech-stack line as optional guidance when tech.detected is non-empty (Req 5.2)", async () => {
    await runPass1([FINDING], null, { detected: ["nginx", "WordPress"] });
    const system = llm.systems()[0];

    // The detected technologies are listed...
    expect(system).toContain("The site appears to be built with: nginx, WordPress.");
    // ...and the line frames their use as optional / confidence-gated, not required.
    expect(system).toContain("but only when you are confident it applies.");
  });

  it("omits the tech-stack line entirely when no technologies are detected (Req 5.2 boundary)", async () => {
    await runPass1([FINDING], null, undefined);
    const system = llm.systems()[0];

    expect(system).not.toContain("The site appears to be built with:");
    expect(system).not.toContain("but only when you are confident it applies.");
  });
});
