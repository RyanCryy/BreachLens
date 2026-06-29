// ---------------------------------------------------------------------------
// Feature: exploit-narrative (Pass 3) — shared test scaffolding
//
// Reusable fast-check arbitraries and a `callLLMJson` mock controller shared by
// the Pass 3 property tests (analysis.pass3.property*.test.js) and the
// example/unit tests (analysis.pass3.unit.test.js).
//
// Design: Testing Strategy — property-based tests stub `callLLMJson` so every
// iteration runs fully in-memory with no network access. Arbitraries here feed
// `runPass3(baseReport, domain)` generated base reports and let tests choose the
// stubbed LLM response (or make it throw / reject, including an abort).
//
// Conventions follow `scan-engine.property3.test.js` (ESM `import`, named
// fast-check arbitraries declared at module scope, in-memory only).
// ---------------------------------------------------------------------------

import fc from "fast-check";
import { vi } from "vitest";

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

// Severity values exercised by the scored-finding filter
// (`f.severity !== "info"`). We deliberately include:
//   - the exact excluded sentinel `"info"`
//   - mixed-case variants (`"Info"`, `"INFO"`) that are NOT excluded, since the
//     filter is case-sensitive and only excludes the exact lowercase `"info"`
//   - ordinary scored severities (critical/high/medium/low and mixed case)
export const severityArb = fc.constantFrom(
  "info",
  "Info",
  "INFO",
  "critical",
  "Critical",
  "CRITICAL",
  "high",
  "HIGH",
  "High",
  "medium",
  "Medium",
  "low",
  "Low"
);

// The `informational` flag drives the second half of the exclusion rule
// (`!f.informational`). We vary across truthy, falsy, and absent so the filter
// is exercised on every shape:
//   - truthy: `true`, `1`, `"yes"`, a non-empty object
//   - falsy:  `false`, `0`, `""`, `null`
//   - absent: the key is omitted entirely
const INFORMATIONAL_PRESENT = fc.oneof(
  fc.boolean(),
  fc.constantFrom(0, 1),
  fc.constantFrom("", "yes"),
  fc.constant(null)
);

// A single finding. `informational` is present on some records and omitted on
// others (requiredKeys excludes it) so the "absent" case is covered too. Extra
// fields (`id`, `recommendation`) are included to confirm Pass 3 maps only
// `title`, `severity`, `explanation` and ignores everything else.
export const findingArb = fc.record(
  {
    title: fc.string(),
    severity: severityArb,
    explanation: fc.string(),
    informational: INFORMATIONAL_PRESENT,
    id: fc.string(),
    recommendation: fc.string(),
  },
  { requiredKeys: ["title", "severity", "explanation"] }
);

// A base report as consumed by `runPass3`. Pass 3 only reads `findings`,
// `riskLevel`, and `overallRiskScore`; other fields are irrelevant.
export const baseReportArb = fc.record({
  findings: fc.array(findingArb, { maxLength: 12 }),
  riskLevel: fc.string(),
  overallRiskScore: fc.double({ noNaN: true }),
});

// A domain string for the second `runPass3` argument.
export const domainArb = fc.domain ? fc.domain() : fc.string({ minLength: 1 });

// One narrative field value as it might appear in a raw LLM JSON response:
// a normal string, whitespace-only, empty, or a non-string (number/bool/null/
// object/array). Used inside `llmResponseArb` where the key may also be absent.
const narrativeFieldValueArb = fc.oneof(
  fc.string(), // arbitrary string (may be empty)
  fc.constantFrom("", "   ", "\t", "\n  \n"), // empty / whitespace-only
  fc.lorem(), // realistic non-empty prose
  fc.integer(), // non-string
  fc.boolean(), // non-string
  fc.constant(null), // non-string
  fc.record({ nested: fc.string() }), // non-string (object)
  fc.array(fc.string()) // non-string (array)
);

// A raw LLM JSON response object. `attackScenario` / `ifUnaddressed` may each be
// present (string / whitespace-only / empty / non-string) or absent entirely,
// and unrelated extra keys may appear. This drives the trim / coercion / null
// contract in `runPass3`.
export const llmResponseArb = fc.record(
  {
    attackScenario: narrativeFieldValueArb,
    ifUnaddressed: narrativeFieldValueArb,
    extra: fc.string(),
  },
  { requiredKeys: [] }
);

// ---------------------------------------------------------------------------
// Payload capture
// ---------------------------------------------------------------------------

// `runPass3` calls `callLLMJson({ system, messages: [{ role, content }], ... })`
// where the user message content embeds the payload as
// `...:\n\n${JSON.stringify(payload, null, 2)}`. Given the options object passed
// to a single `callLLMJson` invocation, parse and return that embedded payload.
export function parsePayloadFromCallArgs(callArgs) {
  const opts = callArgs && callArgs[0];
  const content = opts && opts.messages && opts.messages[0] && opts.messages[0].content;
  if (typeof content !== "string") {
    throw new Error("callLLMJson was not called with a user message string");
  }
  const start = content.indexOf("{");
  if (start === -1) throw new Error("No JSON payload found in user message");
  return JSON.parse(content.slice(start));
}

// ---------------------------------------------------------------------------
// callLLMJson mock controller
// ---------------------------------------------------------------------------
//
// Usage (in each test file — `vi.mock` MUST be called at the top of the test
// module so vitest can hoist it above the `./analysis.js` import):
//
//   import { vi } from "vitest";
//   vi.mock("./llm.js");                 // auto-mock -> callLLMJson is a vi.fn()
//   import { callLLMJson } from "./llm.js";
//   import { runPass3 } from "./analysis.js";
//   import { createLLMJsonMock } from "./analysis.pass3.arbitraries.js";
//
//   const llm = createLLMJsonMock(callLLMJson);
//   llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });
//   await runPass3(report, "example.com");
//   const payload = llm.lastPayload();   // serialized payload Pass 3 sent
//
// The controller wraps the auto-mocked `callLLMJson` vi.fn: it captures the args
// (so payload assertions can read the serialized payload) and lets a test choose
// the return value or make it throw / reject (including an abort-style
// rejection).

// Build an abort-style error matching what an aborted fetch / AbortController
// rejection looks like, so failure tests can simulate the 10 s timeout path.
export function abortError(message = "The operation was aborted") {
  const err = new Error(message);
  err.name = "AbortError";
  return err;
}

export function createLLMJsonMock(callLLMJsonMock) {
  if (!callLLMJsonMock || typeof callLLMJsonMock.mockImplementation !== "function") {
    throw new Error(
      "createLLMJsonMock expects the auto-mocked callLLMJson vi.fn (did you call vi.mock(\"./llm.js\")?)"
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
    // "LLM throws" and "parse failure after retry" failure modes.
    rejectWith(error = new Error("LLM failure")) {
      callLLMJsonMock.mockReset();
      callLLMJsonMock.mockRejectedValue(error);
      return controller;
    },

    // Make calls reject with an abort-style error, simulating the 10 s timeout.
    rejectAbort(message) {
      return controller.rejectWith(abortError(message));
    },

    // Provide a custom async implementation (advanced cases).
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

    // The serialized payload Pass 3 embedded in the most recent call.
    lastPayload() {
      return parsePayloadFromCallArgs(controller.lastCallArgs());
    },

    // The serialized payload for an arbitrary call index.
    payloadAt(index) {
      return parsePayloadFromCallArgs(callLLMJsonMock.mock.calls[index]);
    },

    // Reset captured calls and implementation between iterations.
    reset() {
      callLLMJsonMock.mockReset();
      return controller;
    },
  };

  return controller;
}
