// tests/pass1.property7.prompt-injection.test.js
//
// Property 7: Conditional provider and tech-stack prompt injection.
//
// For ANY non-null `provider`, the system prompt built by Pass 1 names that
// provider AND carries the tailoring clause ("MAY tailor" to a "CONFIDENTLY
// identified" provider). For ANY `tech` whose `detected` list is non-empty, the
// system prompt contains a SINGLE comma-joined line listing EVERY detected
// technology, framed as OPTIONAL guidance. For ANY `tech` that is absent, lacks
// `detected`, or has an empty `detected` list, NO tech-context line appears
// (no detected-tech sentinel, no "appears to be built with").
//
// Frozen production code is exercised through the single test seam: a vi.mock of
// ../netlify/functions/lib/llm.js's callLLMJson export. The captured `system`
// string (llm.systems()) is the assertion surface. No production file is edited.
//
// **Feature: finding-classification, Property 7: Conditional provider and tech-stack prompt injection**
// **Validates: Requirements 4.1, 5.1, 5.3, 5.2**

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  findingArb,
  providerArb,
  nonNullProviderArb,
  techWithDetectedArb,
  techEmptyDetectedArb,
  techMissingDetectedArb,
  techAbsentArb,
  PROVIDER_SENTINEL,
  TECH_SENTINEL,
} from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// The fixed substring that marks the optional-guidance framing of the tech line
// in pass1System (".. but only when you are confident it applies.").
const TECH_LINE_MARKER = "appears to be built with";
const TECH_OPTIONAL_MARKER = "only when you are confident it applies";

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

// Drive a single classification and return the captured system prompt. The
// system prompt is identical for every finding in a call (pass1System(provider,
// tech)), so one finding is sufficient to inspect prompt injection.
async function captureSystem(finding, provider, tech) {
  llm.reset().setDefault(behaviors.resolveJson({ title: "t" }));
  await runPass1([finding], provider, tech);
  return llm.systems()[0];
}

describe("Pass 1 Property 7 — conditional provider and tech-stack prompt injection", () => {
  it("includes a non-null provider name plus the tailoring clause (Req 4.1)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        nonNullProviderArb,
        // Tech is irrelevant here; vary it to confirm provider injection is
        // independent of the tech branch.
        fc.oneof(techWithDetectedArb, techEmptyDetectedArb, techAbsentArb),
        async (finding, provider, tech) => {
          const system = await captureSystem(finding, provider, tech);

          // The confidently-matched provider name reached the prompt verbatim.
          expect(system).toContain(provider);
          expect(system).toContain(PROVIDER_SENTINEL);
          // ...framed as a confident match the model MAY tailor to.
          expect(system).toContain("CONFIDENTLY identified");
          expect(system).toContain("MAY tailor");
        }
      ),
      { numRuns: 120 }
    );
  });

  it("includes a single comma-joined optional line listing EVERY detected technology (Req 5.1, 5.2)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        techWithDetectedArb,
        async (finding, provider, tech) => {
          const system = await captureSystem(finding, provider, tech);

          // Exactly ONE tech-context line exists.
          const techLines = system
            .split("\n")
            .filter((line) => line.includes(TECH_LINE_MARKER));
          expect(techLines).toHaveLength(1);
          const techLine = techLines[0];

          // The line is the comma-joined list of EVERY detected technology.
          const joined = tech.detected.join(", ");
          expect(techLine).toContain(joined);
          for (const t of tech.detected) {
            expect(techLine).toContain(t);
          }
          // Every detected entry carries the tech sentinel by construction.
          const sentinelCount = (techLine.match(new RegExp(TECH_SENTINEL, "g")) || [])
            .length;
          expect(sentinelCount).toBe(tech.detected.length);

          // Framed as OPTIONAL guidance, applied only when confidently relevant.
          expect(techLine).toContain(TECH_OPTIONAL_MARKER);
        }
      ),
      { numRuns: 120 }
    );
  });

  it("omits the tech-context line entirely when detected is absent/empty/missing (Req 5.3)", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingArb,
        providerArb,
        fc.oneof(techEmptyDetectedArb, techMissingDetectedArb, techAbsentArb),
        async (finding, provider, tech) => {
          const system = await captureSystem(finding, provider, tech);

          // No tech-context line, and no detected-technology sentinel leaked in.
          expect(system).not.toContain(TECH_LINE_MARKER);
          expect(system).not.toContain(TECH_SENTINEL);
        }
      ),
      { numRuns: 120 }
    );
  });
});
