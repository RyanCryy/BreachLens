// tests/pass1.property1.isolation.test.js
//
// Feature: finding-classification, Property 1: Exactly one isolated LLM call per finding
//
// For any non-empty list of N findings, runPass1 issues exactly N LLM calls, and
// each call's content references the data of exactly one finding and no other
// finding's label, detail, type, or suggestedSnippet.
//
// Validates: Requirements 1.1, 1.3, 2.1, 2.2
//
// This file authors NO production change. The ONLY seam is module-mocking the
// `callLLMJson` export of netlify/functions/lib/llm.js (matching the harness in
// tests/pass1.harness.smoke.test.js). Each generated finding carries a unique,
// bracketed sentinel (via injectSentinels) embedded in its label/detail/
// suggestedSnippet so we can prove, per call, that exactly one finding's data is
// present and no other finding's distinguishing data leaked in.
//
// NOTE on `type` isolation: `finding.type` is a shared CATEGORY (e.g. several
// findings may all be "header"), so a literal "no other finding's type string"
// check is impossible — a call legitimately contains its own finding's type,
// which can equal another finding's type. The unique sentinel embedded in each
// finding's label/detail/suggestedSnippet is the real isolation oracle: if any
// other finding's label/detail/suggestedSnippet (each of which carries that
// finding's unique sentinel) leaked into this call, the foreign sentinel would
// appear. We therefore assert exactly-one-sentinel-per-call plus explicit
// non-leakage of every other finding's full label/detail/suggestedSnippet.

import { describe, it, expect, beforeEach, vi } from "vitest";
import fc from "fast-check";
import { attachDouble, behaviors } from "./helpers/llm-double.js";
import {
  findingListArb,
  sentinelFor,
  providerArb,
  techArb,
  llmJsonArb,
} from "./helpers/pass1-fixtures.js";

// Hoisted spy so the (hoisted) vi.mock factory below can reference it.
const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));

// The single test seam: replace callLLMJson, keep every other real export.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

import { runPass1 } from "../netlify/functions/lib/analysis.js";

// Combine a captured opts object into the full system+user text for one call.
function combine(opts) {
  if (!opts) return "";
  const system = opts.system || "";
  const user = (opts.messages || [])
    .map((m) => m && m.content)
    .filter(Boolean)
    .join("\n");
  return `${system}\n${user}`;
}

let llm;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  llm = attachDouble(mockCallLLMJson);
});

describe("Pass 1 — Property 1: exactly one isolated LLM call per finding", () => {
  // Feature: finding-classification, Property 1: Exactly one isolated LLM call per finding
  // Validates: Requirements 1.1, 1.3, 2.1, 2.2
  it("issues exactly N calls, each referencing exactly one finding with no cross-finding leakage", async () => {
    await fc.assert(
      fc.asyncProperty(
        findingListArb({ minLength: 1, maxLength: 6 }),
        providerArb,
        techArb,
        llmJsonArb,
        async (findings, provider, tech, json) => {
          llm.reset();
          llm.setDefault(behaviors.resolveJson(json));

          const results = await runPass1(findings, provider, tech);

          // Req 1.1 / 2.1 / 2.2: exactly one LLM call per finding (N total),
          // and exactly one result per finding (no batching).
          expect(llm.callCount).toBe(findings.length);
          expect(results).toHaveLength(findings.length);

          // Full system+user text captured for every call, in call order.
          const calls = llm.opts().map(combine);

          // (a) Every call contains exactly ONE finding's sentinel — i.e. each
          // call references the data of exactly one finding. (Req 1.3)
          for (const text of calls) {
            const present = findings.filter((_, j) => text.includes(sentinelFor(j)));
            expect(present).toHaveLength(1);
          }

          // (b) Every finding's sentinel appears in exactly ONE call — i.e. each
          // finding is scored by its own dedicated call, none skipped or doubled.
          for (let j = 0; j < findings.length; j++) {
            const s = sentinelFor(j);
            const hits = calls.filter((text) => text.includes(s)).length;
            expect(hits).toBe(1);
          }

          // (c) For each call, match it to its finding by sentinel, then assert
          // NO OTHER finding's label / detail / suggestedSnippet leaked in.
          // (Req 1.3 — the user content carries only THIS finding's data.)
          for (const text of calls) {
            const mineIdx = findings.findIndex((_, j) => text.includes(sentinelFor(j)));
            expect(mineIdx).toBeGreaterThanOrEqual(0);

            for (let j = 0; j < findings.length; j++) {
              if (j === mineIdx) continue;
              const other = findings[j];
              expect(text.includes(other.label)).toBe(false);
              expect(text.includes(other.detail)).toBe(false);
              if (typeof other.suggestedSnippet === "string") {
                expect(text.includes(other.suggestedSnippet)).toBe(false);
              }
            }
          }
        }
      ),
      { numRuns: 200 }
    );
  });

  // A concrete, deterministic sanity example to aid debugging if the property
  // ever regresses (still drives the same isolation guarantees explicitly).
  it("keeps two same-category findings isolated in separate calls", async () => {
    llm.setDefault(behaviors.resolveJson({ title: "t", explanation: "e", recommendation: "r", fixSnippet: null }));

    const findings = [
      { id: "hdr-hsts", type: "header", label: "Missing HSTS ⟦A⟧", detail: "no hsts ⟦A⟧" },
      { id: "hdr-csp", type: "header", label: "Missing CSP ⟦B⟧", detail: "no csp ⟦B⟧" },
    ];

    const results = await runPass1(findings, null, undefined);

    expect(llm.callCount).toBe(2);
    expect(results).toHaveLength(2);

    const calls = llm.opts().map(combine);
    const callA = calls.find((t) => t.includes("⟦A⟧"));
    const callB = calls.find((t) => t.includes("⟦B⟧"));

    expect(callA).toBeDefined();
    expect(callB).toBeDefined();
    // No cross-contamination of the other finding's distinguishing data.
    expect(callA.includes("⟦B⟧")).toBe(false);
    expect(callB.includes("⟦A⟧")).toBe(false);
  });
});
