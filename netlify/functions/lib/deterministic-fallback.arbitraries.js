// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — shared test scaffolding
//
// Reusable fast-check arbitraries and a `callLLMJson` mock controller shared by
// the deterministic-fallback property tests
// (deterministic-fallback.property*.test.js) and the example/edge tests.
//
// This is a documentation / formalization spec for behavior that ALREADY exists
// in `findings.js`, `analysis.js`, and `scan.js`. Nothing here changes
// production logic — these generators only feed the existing functions
// (`fallbackClassify`, `classifyOne`, `runPass1`, `runPass2`, `runPass3`,
// `computeFallbackScore`, `scoreToLevel`, `buildFallbackReport`) so that 100+
// iterations stay fast and fully in-memory.
//
// Design (Testing Strategy): property tests stub `callLLMJson` via
// `vi.mock("./llm.js")` so every iteration runs with no network access.
//
// Conventions follow `analysis.pass3.arbitraries.js` and
// `scan-engine.property3.test.js` (ESM `import`, named fast-check arbitraries
// declared at module scope, in-memory only).
// ---------------------------------------------------------------------------

import fc from "fast-check";

// ---------------------------------------------------------------------------
// Mirrored deterministic tables
//
// `SEVERITY_MAP` and `EXPOSED_FILE_INFO` are private to `findings.js`, so the
// known id/path sets are mirrored here purely to DRIVE the generators toward
// the deterministic rule's known branches. The production tables remain the
// single source of truth; these lists only choose inputs. If `findings.js`
// gains a new known id/path, adding it here simply broadens generator coverage.
// ---------------------------------------------------------------------------

// Ids present in `findings.js`'s `SEVERITY_MAP`.
export const KNOWN_FINDING_IDS = [
  "spf-missing",
  "dmarc-missing",
  "ssl-error",
  "ssl-expired",
  "ssl-expiring",
  "ssl-expiring-soon",
  "hdr-hsts",
  "hdr-csp",
  "hdr-xfo",
  "hdr-xcto",
  "subdomain-surface",
  "caa-missing",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "mixed-content",
  "robots-sensitive",
];

// Paths present in `findings.js`'s `EXPOSED_FILE_INFO` (each maps an
// `exposure` finding to a known severity); plus unknown paths exercise the
// `exposure` default (`high`).
export const KNOWN_EXPOSED_PATHS = [
  "/.git/config",
  "/.git/HEAD",
  "/.env",
  "/wp-config.php.bak",
  "/.DS_Store",
];

// ---------------------------------------------------------------------------
// findingArbitrary
//
// Emits the full range of pre-classification finding shapes consumed by
// `fallbackClassify` / `classifyOne`:
//   - known-id findings (ids drawn from SEVERITY_MAP)
//   - `exposure` findings whose `path` is drawn from EXPOSED_FILE_INFO keys
//     PLUS unknown paths (default-`high` branch)
//   - `subdomain` findings (default-`medium` branch)
//   - unknown-id / unknown-type findings (the total-coverage `low` branch)
// `suggestedSnippet` is present on some records and absent on others.
//
// Exercises totality (Property 10) and snippet backfill.
// ---------------------------------------------------------------------------

// A short label/detail string — kept non-empty so title/detail-derived prose is
// realistic, but content is irrelevant to severity.
const labelArb = fc.string({ minLength: 1, maxLength: 40 });
const detailArb = fc.string({ minLength: 1, maxLength: 120 });

// `suggestedSnippet` present (a paste-ready-looking literal) or absent.
const suggestedSnippetValueArb = fc.oneof(
  fc.constantFrom(
    "v=spf1 -all",
    "v=spf1 include:_spf.google.com -all",
    "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    '0 issue "letsencrypt.org"'
  ),
  fc.string({ minLength: 1, maxLength: 60 })
);

// Known-id finding: id from SEVERITY_MAP, with optional suggestedSnippet.
const knownIdFindingArb = fc.record(
  {
    id: fc.constantFrom(...KNOWN_FINDING_IDS),
    type: fc.constantFrom("email-auth", "tls", "header", "dns", "cookie", "mixed-content", "info-leak"),
    label: labelArb,
    detail: detailArb,
    suggestedSnippet: suggestedSnippetValueArb,
  },
  { requiredKeys: ["id", "type", "label", "detail"] }
);

// Exposure finding: dynamic id `exposed-file-<path>`, path known or unknown.
const exposureFindingArb = fc
  .record(
    {
      path: fc.oneof(
        fc.constantFrom(...KNOWN_EXPOSED_PATHS),
        fc.string({ minLength: 1, maxLength: 40 }).map((s) => `/${s}`)
      ),
      label: labelArb,
      detail: detailArb,
      suggestedSnippet: suggestedSnippetValueArb,
    },
    { requiredKeys: ["path", "label", "detail"] }
  )
  .map((f) => ({ ...f, id: `exposed-file-${f.path}`, type: "exposure" }));

// Subdomain finding: dynamic id `subdomain-<name>`, default-medium branch.
const subdomainFindingArb = fc
  .record(
    {
      name: fc.constantFrom("dev", "staging", "admin", "test", "vpn", "jenkins", "backup"),
      label: labelArb,
      detail: detailArb,
    },
    { requiredKeys: ["name", "label", "detail"] }
  )
  .map((f) => ({ id: `subdomain-${f.name}`, type: "subdomain", label: f.label, detail: f.detail }));

// `SEVERITY_MAP` is a plain object literal, so a finding `id` that collides with
// an inherited `Object.prototype` property name (e.g. "constructor",
// "toString", "__proto__", "valueOf") resolves to the inherited member rather
// than `undefined` — a production quirk in `fallbackClassify`. Real finding ids
// are kebab-case slugs and never such names, so the unknown-id generator
// excludes them to stay within the genuine input space.
const PROTO_PROPERTY_NAMES = Object.getOwnPropertyNames(Object.prototype);

function isGenuineUnknownId(s) {
  return !KNOWN_FINDING_IDS.includes(s) && !PROTO_PROPERTY_NAMES.includes(s);
}

// Unknown-id / unknown-type finding: exercises the total-coverage `low` branch
// (Property 10). Ids and types are arbitrary strings deliberately excluded from
// the known sets above.
const unknownFindingArb = fc.record(
  {
    id: fc.string({ minLength: 1, maxLength: 30 }).filter(isGenuineUnknownId),
    type: fc
      .string({ minLength: 1, maxLength: 20 })
      .filter((s) => !["exposure", "subdomain"].includes(s)),
    label: labelArb,
    detail: detailArb,
    suggestedSnippet: suggestedSnippetValueArb,
  },
  { requiredKeys: ["id", "type", "label", "detail"] }
);

export const findingArbitrary = fc.oneof(
  knownIdFindingArb,
  exposureFindingArb,
  subdomainFindingArb,
  unknownFindingArb
);

// Findings restricted to unknown ids/types — used directly by the totality
// property (Property 10), which asserts the `low` + generic-prose branch.
export const unknownFindingArbitrary = unknownFindingArb;

// ---------------------------------------------------------------------------
// severityArbitrary
//
// Emits mixed-case recognized values, the `info` sentinel, and junk /
// unrecognized strings — to exercise case-normalization and the
// weight-0-for-unknown rule (Property 3).
// ---------------------------------------------------------------------------
export const severityArbitrary = fc.oneof(
  // Mixed-case recognized values.
  fc.constantFrom(
    "critical",
    "Critical",
    "CRITICAL",
    "high",
    "HIGH",
    "High",
    "medium",
    "Medium",
    "MEDIUM",
    "low",
    "Low",
    "LOW"
  ),
  // The informational sentinel (weight 0).
  fc.constantFrom("info", "Info", "INFO"),
  // Junk / unrecognized values (weight 0).
  fc.constantFrom("severe", "trivial", "unknown", "", "  ", "123", "null"),
  fc.string()
);

// ---------------------------------------------------------------------------
// llmResponseArbitrary
//
// A raw LLM JSON response object covering both Pass 1
// (`{ title, explanation, recommendation, fixSnippet }`) and Pass 2
// (`{ summary, topPriority }`) consumers. Each field may be present (normal
// string / empty / whitespace-only / non-string) or absent entirely, and
// unrelated extra keys may appear — to exercise per-field substitution
// (Properties 9, 12).
// ---------------------------------------------------------------------------

// A single field value as it might appear in a raw LLM JSON response:
// a normal string, whitespace-only, empty, realistic prose, or a non-string
// (number / bool / null / object / array).
export const llmFieldValueArb = fc.oneof(
  fc.string(), // arbitrary string (may be empty)
  fc.constantFrom("", "   ", "\t", "\n  \n"), // empty / whitespace-only
  fc.lorem(), // realistic non-empty prose
  fc.integer(), // non-string
  fc.boolean(), // non-string
  fc.constant(null), // non-string
  fc.record({ nested: fc.string() }), // non-string (object)
  fc.array(fc.string()) // non-string (array)
);

export const llmResponseArbitrary = fc.record(
  {
    // Pass 1 fields.
    title: llmFieldValueArb,
    explanation: llmFieldValueArb,
    recommendation: llmFieldValueArb,
    fixSnippet: llmFieldValueArb,
    // Pass 2 fields.
    summary: llmFieldValueArb,
    topPriority: llmFieldValueArb,
    // An unrelated extra key that the code should ignore.
    extra: fc.string(),
    // A bogus severity the LLM must NEVER be allowed to set (Property 2).
    severity: fc.oneof(fc.string(), severityArbitrary),
  },
  { requiredKeys: [] }
);

// ---------------------------------------------------------------------------
// errorShapeArbitrary
//
// Emits 401-like, 429-like, and timeout/abort-like rejections (varying
// `status`, `name`, and `message`) so layer-selection tests are error-type
// agnostic (Property 20). Each produces a real `Error` instance carrying the
// shape attributes a caller might branch on (but the production code never
// does).
// ---------------------------------------------------------------------------

// Build an abort-style error matching an aborted fetch / AbortController
// rejection, used to simulate the per-call timeout path.
export function abortError(message = "The operation was aborted") {
  const err = new Error(message);
  err.name = "AbortError";
  return err;
}

// A 401-like authorization failure (e.g. missing/invalid API key).
function unauthorizedError(message = "OpenAI API 401: invalid api key") {
  const err = new Error(message);
  err.name = "LLMError";
  err.status = 401;
  return err;
}

// A 429-like rate-limit failure.
function rateLimitError(message = "OpenAI API 429: rate limit exceeded") {
  const err = new Error(message);
  err.name = "LLMError";
  err.status = 429;
  return err;
}

export const errorShapeArbitrary = fc.oneof(
  // 401-like.
  fc
    .string({ maxLength: 40 })
    .map((m) => unauthorizedError(`OpenAI API 401: ${m || "unauthorized"}`)),
  // 429-like.
  fc
    .string({ maxLength: 40 })
    .map((m) => rateLimitError(`OpenAI API 429: ${m || "rate limited"}`)),
  // timeout / abort-like.
  fc.string({ maxLength: 40 }).map((m) => abortError(m || "The operation was aborted")),
  // a generic throw (e.g. unparseable JSON from extractJson).
  fc.string({ maxLength: 40 }).map((m) => new Error(m || "Unexpected end of JSON input"))
);

// ---------------------------------------------------------------------------
// callLLMJson mock controller
//
// Modeled on `analysis.pass3.arbitraries.js`. Usage (in each test file —
// `vi.mock` MUST be at the top so vitest hoists it above the `./analysis.js`
// import):
//
//   import { vi } from "vitest";
//   vi.mock("./llm.js");                 // auto-mock -> callLLMJson is a vi.fn()
//   import { callLLMJson } from "./llm.js";
//   import { classifyOne, runPass1 } from "./analysis.js";
//   import { createLLMJsonMock } from "./deterministic-fallback.arbitraries.js";
//
//   const llm = createLLMJsonMock(callLLMJson);
//   llm.resolveWith({ title: "x", explanation: "y" });
//   await runPass1(findings, provider, tech);
//   expect(llm.callCount()).toBe(findings.length);
//
// The controller wraps the auto-mocked `callLLMJson` vi.fn: it captures call
// args and lets a test choose the return value or make it throw / reject
// (including an abort-style rejection), or supply a per-call implementation
// (e.g. fail exactly one finding by inspecting its payload).
// ---------------------------------------------------------------------------
export function createLLMJsonMock(callLLMJsonMock) {
  if (!callLLMJsonMock || typeof callLLMJsonMock.mockImplementation !== "function") {
    throw new Error(
      'createLLMJsonMock expects the auto-mocked callLLMJson vi.fn (did you call vi.mock("./llm.js")?)'
    );
  }

  const controller = {
    fn: callLLMJsonMock,

    // Make the next (and subsequent) calls resolve with `value`.
    resolveWith(value) {
      callLLMJsonMock.mockReset();
      callLLMJsonMock.mockResolvedValue(value);
      return controller;
    },

    // Make calls reject with `error` (defaults to a generic Error). Use for the
    // "LLM throws" / "parse failure after retry" failure modes.
    rejectWith(error = new Error("LLM failure")) {
      callLLMJsonMock.mockReset();
      callLLMJsonMock.mockRejectedValue(error);
      return controller;
    },

    // Make calls reject with an abort-style error, simulating the timeout path.
    rejectAbort(message) {
      return controller.rejectWith(abortError(message));
    },

    // Provide a custom async implementation (advanced cases, e.g. fail exactly
    // one finding while the rest succeed — Property 7).
    implement(impl) {
      callLLMJsonMock.mockReset();
      callLLMJsonMock.mockImplementation(impl);
      return controller;
    },

    // How many times callLLMJson was invoked.
    callCount() {
      return callLLMJsonMock.mock.calls.length;
    },

    // The options object passed to the most recent call.
    lastCallArgs() {
      const calls = callLLMJsonMock.mock.calls;
      return calls[calls.length - 1];
    },

    // The options object passed to an arbitrary call index.
    callArgsAt(index) {
      return callLLMJsonMock.mock.calls[index];
    },

    // Reset captured calls and implementation between iterations.
    reset() {
      callLLMJsonMock.mockReset();
      return controller;
    },
  };

  return controller;
}
