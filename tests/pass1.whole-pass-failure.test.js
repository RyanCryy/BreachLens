// tests/pass1.whole-pass-failure.test.js
//
// Task 9.1 — Assert orchestration-level fallback when `runPass1` throws entirely.
// =============================================================================
//
// REQUIREMENT UNDER TEST
// ----------------------
// Req 9.3: "IF the `runPass1` invocation itself fails entirely, THEN THE top-level
// orchestration SHALL classify all findings through the Deterministic_Classifier
// with `_source` set to `\"fallback\"`."
//
// The orchestration is `analyze()` in netlify/functions/lib/analysis.js:
//
//     let classified;
//     try {
//       classified = await runPass1(findings, provider, techStack);
//     } catch (e) {
//       // Total Pass 1 failure -> classify everything deterministically
//       classified = findings.map((f) => ({
//         ...fallbackClassify(f),
//         type: f.type,
//         _source: "fallback",
//       }));
//     }
//
// THE TEST SEAM (and why a runPass1 module-mock does NOT work)
// -----------------------------------------------------------
// `analyze()` calls `runPass1(...)` through its own *lexical* binding inside the
// same module. A partial `vi.mock("../netlify/functions/lib/analysis.js", ...)`
// that overrides only `runPass1` while keeping the real `analyze` therefore
// CANNOT intercept that internal call — the real `analyze` still invokes the
// real, closure-scoped `runPass1`. (Confirmed against the frozen source.)
//
// So to make the REAL `runPass1` reject *entirely* (not per-finding) without
// editing any production file, we drive the only collaborator `analyze` reaches
// through the module boundary: `deriveFindings` (an IMPORTED symbol from
// findings.js, hence interceptable). We mock findings.js to:
//   - keep the REAL `fallbackClassify` + `defaultFixSnippet` (so the catch's
//     deterministic classification is the genuine oracle — never reimplemented), and
//   - override ONLY `deriveFindings` to return a crafted finding list in which one
//     finding makes `classifyOne` throw OUTSIDE its try/catch.
//
// `classifyOne` builds its user content BEFORE the try block:
//     const userContent = [ ..., `- Details: ${finding.detail}`, ... ];
// A finding whose `detail` is a throwing getter therefore throws during user-
// content construction — before classifyOne's own try/catch can convert it to a
// per-finding fallback. That rejection propagates through `Promise.all`, so the
// REAL `runPass1` rejects ENTIRELY, which is exactly the Req 9.3 trigger.
//
// The throwing-getter finding uses id "hdr-hsts": `fallbackClassify` never reads
// `.detail` for that id (only the dmarc-missing branch reads detail), so the
// catch's `findings.map(fallbackClassify)` still classifies every finding cleanly.
//
// `analyze()` returns the Pass 2 report, whose `.findings` IS the `classified`
// array (sorted) — so the orchestration-level fallback is observable there.
// callLLMJson is also mocked so the downstream Pass 2 / Pass 3 calls stay
// network-free; they cannot affect the `_source` of the classified findings.
//
// NO production file is edited.
//
// _Requirements: 9.3_

import { describe, it, expect, beforeEach, vi } from "vitest";

// --- Hoisted spies so the (hoisted) vi.mock factories below can reference them. ---
const { mockCallLLMJson, mockDeriveFindings } = vi.hoisted(() => ({
  mockCallLLMJson: vi.fn(),
  mockDeriveFindings: vi.fn(),
}));

// Seam 1: keep every real llm.js export, swap only callLLMJson (keeps Pass 2/3
// off the network). Identical pattern to tests/chat.branches.test.js.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, callLLMJson: mockCallLLMJson };
});

// Seam 2: keep the REAL fallbackClassify + defaultFixSnippet (the genuine oracle),
// override only deriveFindings so we control the findings analyze() classifies.
vi.mock("../netlify/functions/lib/findings.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, deriveFindings: mockDeriveFindings };
});

import { analyze } from "../netlify/functions/lib/analysis.js";
import { fallbackClassify } from "../netlify/functions/lib/findings.js";

// A representative list spanning fixed + dynamic ids. Exactly ONE finding makes
// runPass1 reject entirely (its `detail` getter throws during classifyOne's
// user-content build, escaping classifyOne's per-finding try/catch).
function buildFindings() {
  return [
    {
      id: "spf-missing",
      type: "email-auth",
      label: "Missing SPF record",
      detail: "No SPF TXT record was found.",
      suggestedSnippet: "v=spf1 -all",
    },
    {
      id: "dmarc-missing",
      type: "email-auth",
      label: "Missing DMARC record",
      detail: "No DMARC policy record was found at _dmarc.example.com.",
      suggestedSnippet: "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    },
    {
      // The poison pill: a getter that throws while classifyOne builds its
      // user content, BEFORE classifyOne's try block — so the whole pass rejects.
      // fallbackClassify never reads `.detail` for "hdr-hsts", so the catch path
      // still classifies this finding deterministically.
      id: "hdr-hsts",
      type: "header",
      label: "Missing HTTP Strict-Transport-Security header",
      get detail() {
        throw new Error("simulated total Pass 1 failure");
      },
    },
    {
      id: "exposed-file-/.env",
      type: "exposure",
      path: "/.env",
      label: "Publicly accessible file: /.env",
      detail: "A request to /.env returned HTTP 200.",
    },
    {
      id: "subdomain-dev.example.com",
      type: "subdomain",
      label: "Sensitive-looking subdomain exposed: dev.example.com",
      detail: "The subdomain dev.example.com is publicly discoverable.",
    },
  ];
}

const SCAN = { domain: "example.com" };

let findings;
beforeEach(() => {
  mockCallLLMJson.mockReset();
  // Pass 2 / Pass 3 calls resolve harmlessly; they cannot change a finding's _source.
  mockCallLLMJson.mockResolvedValue({ summary: "s", topPriority: "p", attackScenario: "", ifUnaddressed: "" });

  findings = buildFindings();
  mockDeriveFindings.mockReset();
  // techStack.detected is empty so attachTechStack appends no extra display finding,
  // keeping "exactly one classified entry per derived finding" observable.
  mockDeriveFindings.mockReturnValue({
    findings,
    provider: null,
    techStack: { server: null, poweredBy: null, detected: [] },
  });
});

describe("Pass 1 whole-pass failure → orchestration-level fallback (Task 9.1, Req 9.3)", () => {
  it("classifies EVERY finding via the deterministic classifier with _source 'fallback' when runPass1 throws entirely", async () => {
    const report = await analyze(SCAN);

    // analyze()'s returned report.findings IS the `classified` array (sorted).
    const classified = report.findings;

    // Req 9.3 / 9.2: exactly one classified entry per derived finding.
    expect(classified).toHaveLength(findings.length);

    // Req 9.3: every entry is sourced from the deterministic fallback.
    expect(classified.every((c) => c._source === "fallback")).toBe(true);

    // The set of classified entries corresponds 1:1 to the derived findings.
    expect(new Set(classified.map((c) => c.id))).toEqual(new Set(findings.map((f) => f.id)));
  });

  it("each fallback entry matches the genuine fallbackClassify oracle and preserves the finding's type", async () => {
    const report = await analyze(SCAN);
    const byId = new Map(report.findings.map((c) => [c.id, c]));

    for (const f of findings) {
      const got = byId.get(f.id);
      expect(got, `missing classified entry for ${f.id}`).toBeDefined();

      // Recompute the oracle WITHOUT touching the poison getter: for the only
      // finding carrying a throwing `detail`, fallbackClassify(id="hdr-hsts")
      // does not read `.detail`, so this is safe.
      const oracle = fallbackClassify(f);

      // Req 9.4: severity, explanation, recommendation come from the deterministic
      // classifier; the finding's type is preserved.
      expect(got._source).toBe("fallback");
      expect(got.type).toBe(f.type);
      expect(got.severity).toBe(oracle.severity);
      expect(got.explanation).toBe(oracle.explanation);
      expect(got.recommendation).toBe(oracle.recommendation);
      expect(got.id).toBe(f.id);
    }
  });

  it("confirms the whole pass failed (not a per-finding degradation): the real runPass1 rejects", async () => {
    // Importing runPass1 directly and handing it the SAME poison list proves the
    // failure is at the whole-pass level — Promise.all rejects rather than each
    // finding independently degrading to a per-finding fallback.
    const { runPass1 } = await import("../netlify/functions/lib/analysis.js");
    await expect(runPass1(findings, null, undefined)).rejects.toThrow("simulated total Pass 1 failure");
  });
});
