import { describe, it, expect, afterEach, vi } from "vitest";
import fc from "fast-check";
import { recheckFinding, STATUS, defaultDeps } from "./recheck.js";
import { checkFileStatus } from "./checks.js";

// Property-based test for the finding-recheck Recheck_Router.
//
// Feature: finding-recheck, Property 5: Exposed-file re-checks inspect only the HTTP
// status code and never the body.
//
// Validates: Requirements 3.11
//
// The exposed-file route probes a single user-supplied path that may hold real
// secrets. The ethical contract (Requirement 3.11, design "Exposed-file (3.11)") is
// that a re-check inspects ONLY the HTTP status code and never reads, stores, or
// returns the response body. We pin this two ways:
//
//   1. Orchestrator level — inject a `checkFileStatus` into `recheckFinding`'s deps
//      that wraps a Response-like double whose body accessors push to a shared
//      recorder and throw on access. After every `recheckFinding` call the recorder
//      must be empty and the returned status must be a valid STATUS value. This proves
//      the orchestrator (and the status-only contract the fake mirrors) never touches
//      the body for any exposed-file-{path} id or any HTTP status.
//
//   2. Primitive level — run the REAL `checkFileStatus` from checks.js once per
//      iteration with global `fetch` stubbed to return the same body-recording double,
//      asserting the recorder stays empty. This pins the actual primitive the default
//      deps wire in, not just the in-test fake.

const STATUS_VALUES = new Set([STATUS.RESOLVED, STATUS.UNRESOLVED, STATUS.INDETERMINATE]);

// Build a Response-like double whose body accessors record their name (so the test can
// assert the set stayed empty) and throw (so any accidental access also blows up loudly).
// `body` is a getter, so even *reading* the property — not just calling a method — trips it.
function makeBodyRecordingResponse(status, recorder) {
  const trip = (name) => {
    recorder.push(name);
    throw new Error(`response body was accessed via ${name}`);
  };
  const res = {
    status,
    headers: new Map(),
    text: () => trip("text"),
    json: () => trip("json"),
    arrayBuffer: () => trip("arrayBuffer"),
    blob: () => trip("blob"),
    formData: () => trip("formData"),
  };
  Object.defineProperty(res, "body", {
    get() {
      trip("body");
    },
    enumerable: true,
  });
  return res;
}

// A `checkFileStatus` double that mirrors the real status-only contract: it holds a
// body-recording Response double, reads ONLY `res.status`, and returns the normalized
// `{ reachable, status, exposed }` shape the orchestrator consumes — never the body.
function makeStatusOnlyCheckFileStatus(status, recorder) {
  return async (_domain, _path) => {
    const res = makeBodyRecordingResponse(status, recorder);
    return { reachable: true, status: res.status, exposed: res.status === 200 };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Recheck_Router — exposed-file status-only inspection (Property 5)", () => {
  it("Feature: finding-recheck, Property 5: Exposed-file re-checks inspect only the HTTP status code and never the body", async () => {
    await fc.assert(
      fc.asyncProperty(
        // Arbitrary file paths encoded into an exposed-file-{path} Finding_Id.
        fc.string(),
        // Arbitrary HTTP statuses, with 200 (the "still exposed" case) guaranteed to appear.
        fc.oneof(
          fc.constant(200),
          fc.integer({ min: 100, max: 599 })
        ),
        fc.domain(),
        async (path, status, domain) => {
          const findingId = `exposed-file-${path}`;

          // --- 1) Orchestrator level: inject a body-recording status-only probe. ---
          const orchestratorRecorder = [];
          const deps = {
            ...defaultDeps,
            checkFileStatus: makeStatusOnlyCheckFileStatus(status, orchestratorRecorder),
          };

          const result = await recheckFinding({ domain, findingId }, deps);

          // The orchestrator must never have caused a body read...
          expect(orchestratorRecorder).toEqual([]);
          // ...and must echo the id with a valid status drawn from the enum.
          expect(result.findingId).toBe(findingId);
          expect(STATUS_VALUES.has(result.status)).toBe(true);

          // --- 2) Primitive level: pin the REAL checkFileStatus from checks.js. ---
          const primitiveRecorder = [];
          vi.stubGlobal(
            "fetch",
            vi.fn(async () => makeBodyRecordingResponse(status, primitiveRecorder))
          );

          const probe = await checkFileStatus(domain, path);

          // The real primitive reads only the status code — body accessors stay untouched.
          expect(primitiveRecorder).toEqual([]);
          expect(probe.reachable).toBe(true);
          expect(probe.status).toBe(status);

          vi.unstubAllGlobals();
        }
      ),
      { numRuns: 100 }
    );
  });
});
