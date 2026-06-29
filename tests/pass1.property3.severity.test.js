// tests/pass1.property3.severity.test.js
//
// Property 3: Severity is always the deterministic rule value.
//
// For ANY finding and ANY LLM output — including one that supplies a conflicting
// or bogus `severity` field — the classified result's severity equals
// `fallbackClassify(finding).severity`. Classifying the same finding repeatedly
// yields a byte-identical severity, and toggling tech-stack context (present vs
// absent) never changes it.
//
// Frozen production code is exercised through the single test seam: a vi.mock of
// ../netlify/functions/lib/llm.js's callLLMJson export. No production file is
// edited. The expected-value oracle is the REAL fallbackClassify re-exported from
// the fixtures (never a reimplementation).
//
// **Feature: finding-classification, Property 3: Severity is always the deterministic rule value**
// **Validates: Requirements 3.1, 3.2, 3.3, 5.4, 3.5**

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  fallbackClassify,
  findingArb,
  providerArb,
  techArb,
  techWithDetectedArb,
} from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// A "severity" value the LLM might (wrongly) try to supply. Includes valid
// severities that conflict with the rule, bogus tokens, and non-strings — none
// of which may ever influence the result's deterministic severity.
const bogusSeverityArb = fc.oneof(
  fc.constantFrom("critical", "high", "medium", "low"),
  fc.constantFrom("CRITICAL", "Catastrophic", "informational", "none", "", "blocker"),
  fc.integer(),
  fc.boolean(),
  fc.constant(null)
);

// A full LLM JSON payload that always carries a conflicting/bogus severity field.
const llmJsonWithBogusSeverityArb = fc.record({
  title: fc.constantFrom("Fix it", "Security finding", "Action required"),
  explanation: fc.constantFrom("This matters.", "An attacker could abuse this."),
  recommendation: fc.constantFrom("Do A then B.", "Configure the header."),
  fixSnippet: fc.oneof(fc.constant(null), fc.constant("v=spf1 -all")),
  severity: bogusSeverityArb,
});

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 1 Property 3 — severity is always the deterministic rule value", () => {
  it("ignores any conflicting/bogus LLM severity and uses fallbackClassify(finding).severity", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        techArb,
        llmJsonWithBogusSeverityArb,
        async (finding, provider, tech, llmJson) => {
          // Fresh per iteration; default behavior returns the bogus-severity JSON.
          llm.reset().setDefault(behaviors.resolveJson(llmJson));

          const [result] = await runPass1([finding], provider, tech);

          const expected = fallbackClassify(finding).severity;
          // The result severity must equal the deterministic rule value and must
          // NOT have been swayed by the LLM's bogus severity (Req 3.1, 3.2).
          expect(result.severity).toBe(expected);
        }
      ),
      { numRuns: 150 }
    );
  });

  it("yields a byte-identical severity when the same finding is classified repeatedly (Req 3.3)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        llmJsonWithBogusSeverityArb,
        async (finding, provider, llmJson) => {
          llm.reset().setDefault(behaviors.resolveJson(llmJson));

          const severities = [];
          for (let i = 0; i < 3; i++) {
            const [result] = await runPass1([finding], provider, undefined);
            severities.push(result.severity);
          }

          // Every repeat scan produces the exact same severity string.
          expect(severities[1]).toBe(severities[0]);
          expect(severities[2]).toBe(severities[0]);
          expect(severities[0]).toBe(fallbackClassify(finding).severity);
        }
      ),
      { numRuns: 100 }
    );
  });

  it("never changes severity when tech-stack context is present vs absent (Req 5.4)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        techWithDetectedArb,
        llmJsonWithBogusSeverityArb,
        async (finding, provider, tech, llmJson) => {
          // With tech context supplied.
          llm.reset().setDefault(behaviors.resolveJson(llmJson));
          const [withTech] = await runPass1([finding], provider, tech);

          // With tech context absent.
          llm.reset().setDefault(behaviors.resolveJson(llmJson));
          const [withoutTech] = await runPass1([finding], provider, undefined);

          const expected = fallbackClassify(finding).severity;
          expect(withTech.severity).toBe(expected);
          expect(withoutTech.severity).toBe(expected);
          // Toggling tech context leaves severity byte-identical.
          expect(withTech.severity).toBe(withoutTech.severity);
        }
      ),
      { numRuns: 100 }
    );
  });

  it("still assigns the deterministic severity when the LLM call fails (Req 3.5)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        techArb,
        fc.constantFrom("generic", "parse", "timeout"),
        async (finding, provider, tech, failureKind) => {
          const failure =
            failureKind === "generic"
              ? behaviors.throwGeneric()
              : failureKind === "parse"
              ? behaviors.throwParse()
              : behaviors.timeout();

          llm.reset().setDefault(failure);

          const [result] = await runPass1([finding], provider, tech);

          // Degraded to fallback, but severity is still the deterministic value.
          expect(result._source).toBe("fallback");
          expect(result.severity).toBe(fallbackClassify(finding).severity);
        }
      ),
      { numRuns: 100 }
    );
  });
});
