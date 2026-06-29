// tests/helpers/llm-double.js
//
// Reusable, controllable test double for the Pass 1 LLM boundary.
// =============================================================================
//
// THE SINGLE TEST SEAM
// --------------------
// Pass 1 (`runPass1` / `classifyOne` in netlify/functions/lib/analysis.js) reaches
// the language model exclusively through the `callLLMJson` export of
// `netlify/functions/lib/llm.js`. The ONLY seam this verification suite uses is to
// module-mock that export with Vitest — exactly as the existing
// tests/chat.branches.test.js already does for `callLLM` / `callLLMJson`.
//
// NO PRODUCTION FILE IS EDITED to enable testing. There is no test-only export, no
// dependency-injection parameter, and no environment flag added to analysis.js,
// findings.js, llm.js, or scan.js. Capturing the `opts` passed to this double lets
// us assert the system prompt and per-finding user content (and therefore prove
// isolation, prompt injection, snippet passthrough, etc.) without exporting
// `pass1System` or `classifyOne`.
//
// Usage pattern (copy into each property/example test file). The factory is
// referenced through a `vi.hoisted` block so the `vi.mock` factory — which is
// hoisted to the top of the module — can see it:
//
//   import { describe, it, expect, vi } from "vitest";
//   import { createLLMDouble, behaviors } from "./helpers/llm-double.js";
//
//   const llm = vi.hoisted(() => {
//     // NB: require inside hoisted so it runs before imports are evaluated.
//     // (Vitest hoists vi.mock above imports; this keeps the double available.)
//     return null; // placeholder — see note below
//   });
//
// In practice the simplest, robust wiring (matching chat.branches.test.js) is to
// hoist a bare `vi.fn()` spy and drive it with the helpers exported here:
//
//   const { mockCallLLMJson } = vi.hoisted(() => ({ mockCallLLMJson: vi.fn() }));
//
//   vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
//     const actual = await importOriginal();           // keep real extractJson, LLMError, callLLM
//     return { ...actual, callLLMJson: mockCallLLMJson };
//   });
//
//   import { runPass1 } from "../netlify/functions/lib/analysis.js";
//
//   // then, per test, program behavior onto the spy:
//   const double = attachDouble(mockCallLLMJson);
//   double.program(behaviors.resolveJson({ title: "t" }));
//
// `attachDouble` wraps an existing hoisted `vi.fn()` with the same programmable
// queue + accessor API as `createLLMDouble`, so either entry point works.
//
// Per-call programming supports the four behaviors the design's "controllable LLM
// double" calls for:
//   1. resolve a JSON object        -> behaviors.resolveJson(obj)
//   2. throw a generic error        -> behaviors.throwGeneric(msg?)
//   3. throw a parse-style error    -> behaviors.throwParse(msg?)
//   4. simulate a timeout rejection -> behaviors.timeout(msg?)
//
// =============================================================================

import { vi } from "vitest";

/**
 * A parse-style error that mimics what `extractJson` / `JSON.parse` raises when
 * the model returns unparseable output. `callLLMJson` would surface this after
 * its single retry; `classifyOne` then degrades to the deterministic fallback.
 */
export class ParseError extends SyntaxError {
  constructor(message = "Unexpected token < in JSON at position 0") {
    super(message);
    this.name = "SyntaxError";
  }
}

/**
 * Behavior builders. Each returns a plain descriptor consumed by the double.
 * Keeping them as data (not closures) makes test intent readable and lets a
 * single behavior be reused across many generated iterations.
 */
export const behaviors = {
  /** Resolve the call with a JSON object (what a healthy model returns). */
  resolveJson: (obj = {}) => ({ kind: "resolve", value: obj }),

  /** Throw a generic Error (any non-parse exception path). */
  throwGeneric: (message = "LLM call failed") => ({
    kind: "throw",
    error: new Error(message),
  }),

  /** Throw a JSON parse-style error (unparseable model output after retry). */
  throwParse: (message) => ({ kind: "throw", error: new ParseError(message) }),

  /** Simulate a per-call timeout rejection (AbortController abort). */
  timeout: (message = "The operation was aborted due to timeout") => {
    const error = new Error(message);
    error.name = "AbortError";
    return { kind: "throw", error };
  },
};

// Resolve a behavior that may be either a descriptor or a function of the call opts.
function resolveBehavior(behavior, callOpts) {
  const b = typeof behavior === "function" ? behavior(callOpts) : behavior;
  return b;
}

// Turn a behavior descriptor into a resolved value or a thrown error.
async function enact(behavior, callOpts) {
  const b = resolveBehavior(behavior, callOpts);

  // No behavior programmed and no default => resolve a minimal valid JSON object,
  // so an un-configured double still exercises the LLM-success path harmlessly.
  if (b == null) return {};

  // Allow a bare object to be treated as a resolve value for convenience.
  if (typeof b === "object" && !("kind" in b)) return b;

  switch (b.kind) {
    case "resolve":
      return b.value;
    case "throw":
      throw b.error;
    default:
      return {};
  }
}

/**
 * Attach the programmable queue + accessor API to an existing `vi.fn()` spy.
 * Use this when the spy must be hoisted (so a top-level `vi.mock` factory can
 * reference it). The spy's implementation is (re)set to consume the queue.
 *
 * @param {ReturnType<typeof vi.fn>} spy - a hoisted vi.fn()
 * @param {object} [opts]
 * @param {*} [opts.default] - default behavior (descriptor or fn(opts)) used when
 *                             the per-call queue is empty.
 * @returns the control surface (see createLLMDouble for the shape)
 */
export function attachDouble(spy, { default: defaultBehavior } = {}) {
  const queue = [];

  spy.mockImplementation(async (callOpts) => {
    const behavior = queue.length > 0 ? queue.shift() : defaultBehavior;
    return enact(behavior, callOpts);
  });

  const control = {
    /** The underlying vi.fn() spy — pass this into the vi.mock factory. */
    fn: spy,

    /** Queue one or more per-call behaviors, consumed in FIFO order. */
    program(...behaviorList) {
      queue.push(...behaviorList);
      return control;
    },

    /** Set the fallback behavior used once the queue is drained. */
    setDefault(behavior) {
      defaultBehavior = behavior;
      return control;
    },

    /** Clear the queue and the spy's recorded calls. */
    reset() {
      queue.length = 0;
      spy.mockClear();
      return control;
    },

    /** Number of times the double was invoked. */
    get callCount() {
      return spy.mock.calls.length;
    },

    /** Every `opts` object the double was called with, in call order. */
    opts() {
      return spy.mock.calls.map((c) => c[0]);
    },

    /** Every captured `system` prompt string, in call order. */
    systems() {
      return control.opts().map((o) => (o && o.system) || "");
    },

    /**
     * Every captured user-message content, concatenated per call. The Pass 1
     * user content lives in opts.messages[].content; joining lets tests scan a
     * single string per call for sentinels / snippet passthrough.
     */
    userContents() {
      return control.opts().map((o) =>
        ((o && o.messages) || []).map((m) => m && m.content).filter(Boolean).join("\n")
      );
    },

    /** The combined system+user text for a given call index (isolation checks). */
    combinedAt(index) {
      const o = spy.mock.calls[index] && spy.mock.calls[index][0];
      if (!o) return "";
      const user = (o.messages || []).map((m) => m && m.content).filter(Boolean).join("\n");
      return `${o.system || ""}\n${user}`;
    },
  };

  return control;
}

/**
 * Create a brand-new controllable double backed by a fresh `vi.fn()`.
 * Convenient when the spy does not need to be hoisted (e.g. when the mock
 * factory imports the helper directly). Returns the same control surface as
 * `attachDouble`, with `.fn` being the spy to hand to `vi.mock`.
 *
 * @param {object} [opts]
 * @param {*} [opts.default] - default behavior when the per-call queue is empty.
 */
export function createLLMDouble(opts = {}) {
  return attachDouble(vi.fn(), opts);
}
