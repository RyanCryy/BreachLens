// tests/pass1.property8.snippet-passthrough.test.js
//
// Property 8 — suggestedSnippet is passed to the model verbatim.
//
// For any finding carrying a suggestedSnippet, the user content built for that
// finding (and captured at the LLM boundary) contains the snippet value
// VERBATIM (substring match). classifyOne emits the line:
//   `- Pre-computed correct record value for this domain (use this verbatim in
//      both the recommendation and fixSnippet): ${finding.suggestedSnippet}`
// so the raw snippet must appear unaltered in opts.messages[].content.
//
// This file authors NO production change — the single seam is the vi.mock of
// ./llm.js's callLLMJson, identical to the existing harness.
//
// Feature: finding-classification, Property 8: suggestedSnippet is passed to the model verbatim
// Validates: Requirements 6.2

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  snippetCarryingFindingArb,
  providerArb,
  techArb,
} from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The ONLY seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson, {
    default: behaviors.resolveJson({ title: "ok" }),
  });
});

describe("Pass 1 Property 8: suggestedSnippet is passed to the model verbatim", () => {
  it("includes each finding's suggestedSnippet verbatim in that finding's user content", async () => {
    await fc.assert(
      fc.asyncProperty(
        // A non-empty list of findings each GUARANTEED to carry a suggestedSnippet.
        fc.array(snippetCarryingFindingArb, { minLength: 1, maxLength: 6 }),
        providerArb,
        techArb,
        async (findings, provider, tech) => {
          llm.reset();
          llm.setDefault(behaviors.resolveJson({ title: "ok" }));

          const results = await runPass1(findings, provider, tech);

          // One call per finding, recorded in input order (synchronous map dispatch).
          expect(llm.callCount).toBe(findings.length);
          expect(results).toHaveLength(findings.length);

          const userContents = llm.userContents();
          for (let i = 0; i < findings.length; i++) {
            const snippet = findings[i].suggestedSnippet;
            // Sanity: the generator really did attach a snippet.
            expect(typeof snippet).toBe("string");
            // The snippet appears VERBATIM (substring) in this finding's user content.
            expect(userContents[i]).toContain(snippet);
          }
        }
      ),
      { numRuns: 200 }
    );
  });

  it("preserves the snippet exactly even with special/record characters (single finding)", async () => {
    await fc.assert(
      fc.asyncProperty(snippetCarryingFindingArb, async (finding) => {
        llm.reset();
        llm.setDefault(behaviors.resolveJson({ title: "ok" }));

        await runPass1([finding], null, undefined);

        const [userContent] = llm.userContents();
        expect(userContent).toContain(finding.suggestedSnippet);
      }),
      { numRuns: 100 }
    );
  });
});
