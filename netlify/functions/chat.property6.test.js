// Property-based test for the chat recheck-intent resolution stage (chat.js).
//
// Property 6: Chat intent resolution never targets a fabricated finding.
//
// For any set of candidate Finding_Ids produced by the intent-resolution step and
// any current report, the set of ids the chat path resolves to is a SUBSET of the
// Finding_Ids actually present in that report — ids not present in the report are
// discarded before the router is invoked.
//
// Validates: Requirements 7.2

import { describe, it, expect, beforeAll } from "vitest";
import fc from "fast-check";

// Force the deterministic keyword-fallback path: with no OPENAI_API_KEY configured,
// callLLMJson throws (the LLM primary path is unavailable), so resolveRecheckIntent
// degrades to its keyword resolver. Both paths still intersect against the report's
// ids, so the subset guarantee under test holds either way; pinning this here makes
// the property run deterministically in-memory with no network access.
beforeAll(() => {
  delete process.env.OPENAI_API_KEY;
});

import { resolveRecheckIntent } from "./chat.js";

// A realistic mix of known recheckable family ids plus arbitrary junk ids, so reports
// contain ids the resolver recognizes as well as ones it doesn't.
const knownIds = [
  "spf-missing",
  "dmarc-missing",
  "caa-missing",
  "hdr-hsts",
  "hdr-csp",
  "hdr-xfo",
  "hdr-xcto",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "mixed-content",
  "robots-sensitive",
  "ssl-expired",
  "ssl-expiring-soon",
  "exposed-file-/.env",
  "subdomain-dev",
];

const findingIdArb = fc.oneof(
  fc.constantFrom(...knownIds),
  fc.string({ minLength: 1, maxLength: 20 }),
);

// One finding: an id plus an arbitrary (possibly missing) title.
const findingArb = fc.record({
  id: findingIdArb,
  title: fc.option(fc.string({ maxLength: 40 }), { nil: undefined }),
});

// A report: an arbitrary (possibly empty) findings array. domain is incidental here.
const reportArb = fc.record({
  domain: fc.option(fc.domain(), { nil: undefined }),
  findings: fc.array(findingArb, { maxLength: 8 }),
});

// Messages: arbitrary free text PLUS deliberately crafted re-check phrasings that
// mention finding ids/keywords — including ids that are NOT in the report — to push
// the resolver toward returning candidates that must then be filtered to a subset.
const messageArb = fc.oneof(
  fc.string({ maxLength: 60 }),
  fc.constantFrom(...knownIds).map((id) => `re-check ${id}`),
  fc.constantFrom(...knownIds).map((id) => `is ${id} fixed?`),
  fc.constantFrom(...knownIds).map((id) => `can you check ${id} again`),
  fc.constantFrom("spf", "dmarc", "caa", "hsts", "csp", "ssl", "cookie", "robots", "mixed content")
    .map((kw) => `re-check the ${kw} issue`),
  // References to ids that are very unlikely to be in the report (fabrication bait).
  fc.string({ minLength: 1, maxLength: 12 }).map((s) => `re-check ${s}-finding-${s}`),
);

describe("Feature: finding-recheck, Property 6: Chat intent resolution never targets a fabricated finding", () => {
  it("resolves only to ids present in the report, with no duplicates", async () => {
    await fc.assert(
      fc.asyncProperty(messageArb, reportArb, async (message, report) => {
        const result = await resolveRecheckIntent({ message, report });

        // Shape sanity: findingIds is always an array.
        expect(Array.isArray(result.findingIds)).toBe(true);

        // The authoritative set of ids actually present in the report.
        const reportIds = new Set(
          (report.findings || [])
            .map((f) => (f && typeof f.id === "string" ? f.id : null))
            .filter((id) => typeof id === "string" && id.length > 0),
        );

        // SUBSET guarantee: every resolved id must exist in the report (Req 7.2).
        for (const id of result.findingIds) {
          expect(reportIds.has(id)).toBe(true);
        }

        // No duplicates among the resolved ids.
        expect(new Set(result.findingIds).size).toBe(result.findingIds.length);
      }),
      { numRuns: 200 },
    );
  });

  // Edge: with no findings in the report, the empty set is the only possible subset,
  // so the resolver can never surface a fabricated target — findingIds must be empty
  // regardless of how strongly the message expresses a re-check intent.
  it("resolves to an empty id set when the report has no findings", async () => {
    await fc.assert(
      fc.asyncProperty(messageArb, async (message) => {
        const report = { domain: "example.com", findings: [] };
        const result = await resolveRecheckIntent({ message, report });
        expect(Array.isArray(result.findingIds)).toBe(true);
        expect(result.findingIds).toEqual([]);
      }),
      { numRuns: 200 },
    );
  });
});
