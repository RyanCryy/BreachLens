import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  normalizeOutcome,
  CHECK_STATUS,
  CHECK_IDS,
  TIMEOUT_SENTINEL,
  ERROR_SENTINEL,
} from "./scan-engine.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 3: Status trichotomy
//
// For any raw check result and behavior, the outcome normalizer SHALL assign
// exactly one status:
//   - Unavailable when the check errored or timed out;
//   - Success     when the check ran and produced one or more findings;
//   - Empty       when the check ran and produced zero findings.
//
// **Validates: Requirements 2.4, 2.5**
//
// `normalizeOutcome(id, settled)` is a pure function, so every iteration runs
// in-memory with no real network access. We drive the Success/Empty boundary
// with a `findings` arbitrary (arrays of arbitrary length, including empty), and
// the Unavailable branch with the three unavailability shapes the engine emits:
// TIMEOUT_SENTINEL, ERROR_SENTINEL(msg), and a raw Error.
// ---------------------------------------------------------------------------

const ALL_STATUSES = [
  CHECK_STATUS.SUCCESS,
  CHECK_STATUS.EMPTY,
  CHECK_STATUS.UNAVAILABLE,
];

// A finding is an opaque object as far as the normalizer is concerned — only the
// array length drives the Success/Empty boundary. Arrays of arbitrary length
// (including empty) exercise both sides of that boundary.
const findingsArb = fc.array(
  fc.record({
    type: fc.string(),
    detail: fc.oneof(fc.string(), fc.integer(), fc.boolean()),
  }),
  { maxLength: 10 }
);

// A check id from the canonical set (plus arbitrary strings, since the normalizer
// must echo whatever id it is given unchanged).
const idArb = fc.oneof(fc.constantFrom(...CHECK_IDS), fc.string({ minLength: 1 }));

// The three "could not run / complete" shapes the resolve phase produces.
const unavailableArb = fc.oneof(
  // Timed out.
  fc.constant({ kind: "timeout", settled: TIMEOUT_SENTINEL }),
  // Errored with a sanitized message.
  fc
    .string()
    .map((msg) => ({ kind: "error-sentinel", settled: ERROR_SENTINEL(msg) })),
  // A raw Error that slipped through to the normalizer.
  fc
    .string()
    .map((msg) => ({ kind: "raw-error", settled: new Error(msg) }))
);

function assertExactlyOneStatus(outcome) {
  // The status is one of the three enum values...
  expect(ALL_STATUSES).toContain(outcome.status);
  // ...and it is unambiguous: exactly one of the three matches.
  const matches = ALL_STATUSES.filter((s) => s === outcome.status);
  expect(matches).toHaveLength(1);
}

describe("Feature: passive-scan-engine, Property 3: Status trichotomy", () => {
  it("assigns Success for a ran check with >= 1 finding, Empty for 0 findings", () => {
    fc.assert(
      fc.property(idArb, findingsArb, (id, findings) => {
        const outcome = normalizeOutcome(id, { findings });

        assertExactlyOneStatus(outcome);
        expect(outcome.id).toBe(id);

        if (findings.length > 0) {
          // Ran with >= 1 finding -> Success.
          expect(outcome.status).toBe(CHECK_STATUS.SUCCESS);
          expect(outcome.findings).toEqual(findings);
          expect(outcome.error).toBeNull();
        } else {
          // Ran with 0 findings -> Empty (never Unavailable).
          expect(outcome.status).toBe(CHECK_STATUS.EMPTY);
          expect(outcome.findings).toEqual([]);
          expect(outcome.error).toBeNull();
        }
      }),
      { numRuns: 200 }
    );
  });

  it("assigns Unavailable when the check errored or timed out", () => {
    fc.assert(
      fc.property(idArb, unavailableArb, (id, { settled }) => {
        const outcome = normalizeOutcome(id, settled);

        assertExactlyOneStatus(outcome);
        expect(outcome.id).toBe(id);

        // Could not run / complete -> Unavailable, never Success/Empty.
        expect(outcome.status).toBe(CHECK_STATUS.UNAVAILABLE);
        expect(outcome.findings).toEqual([]);
        // A sanitized, human-readable reason is carried (never null/empty).
        expect(typeof outcome.error).toBe("string");
        expect(outcome.error.length).toBeGreaterThan(0);
      }),
      { numRuns: 200 }
    );
  });
});
