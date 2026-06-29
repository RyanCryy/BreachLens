# Implementation Plan: deterministic-fallback

## Overview

This is a **documentation / formalization** spec for behavior that already exists in
`netlify/functions/lib/findings.js`, `netlify/functions/lib/analysis.js`, and
`netlify/functions/scan.js`. The production fallback logic is **not** rewritten or refactored — this
plan is a **test-authoring plan** that locks in the four-layer guarantee by:

1. Implementing each of the 22 Correctness Properties from `design.md` as a single fast-check +
   Vitest property-based test (≥ 100 iterations, tagged with its design property).
2. Implementing the example / edge-case tests called out in the design's Testing Strategy
   (Pass 1 concurrency, Pass 2 empty short-circuit, budget timing with fake timers, pipeline
   rejection within budget, fatal/DNS failure, and the frontend banner).
3. Building the shared fast-check generators (`findingArbitrary`, `severityArbitrary`,
   `llmResponseArbitrary`, `errorShapeArbitrary`) and the `callLLMJson` mock.

Tests run with `npm test` (`vitest run`). New tests follow the conventions of the existing
`netlify/functions/lib/*.property*.test.js` files (ESM imports, module-scope arbitraries,
`vi.mock("./llm.js")` to keep every iteration in-memory). All new test files are placed in
`netlify/functions/lib/` with a `deterministic-fallback.*` prefix so they never collide with the
existing `analysis.pass3.property*` suite.

**Production-code policy:** No production fallback logic is changed. The *only* permitted production
edit is the minimal test seam in Task 1.2 (adding `export` to two already-existing pure functions so
Property 4 can be exercised across the full 0–100 score range). Every other task only adds test
files. Each test task ends by running the suite and confirming it passes against the existing
implementation.

## Tasks

- [x] 1. Build shared test infrastructure and the minimal pure-helper test seam
  - [x] 1.1 Create the shared arbitraries and `callLLMJson` mock
    - Create `netlify/functions/lib/deterministic-fallback.arbitraries.js`.
    - `findingArbitrary`: emits both **known-id** findings (ids drawn from `SEVERITY_MAP`,
      `exposure` findings with `path` drawn from `EXPOSED_FILE_INFO` keys plus unknown paths,
      `subdomain` findings) **and** unknown-id / unknown-type findings, including `suggestedSnippet`
      present/absent — to exercise totality (Property 10) and snippet backfill.
    - `severityArbitrary`: emits mixed-case (`"Critical"`, `"HIGH"`, `"Low"`) and junk/unrecognized
      values plus `"info"`, to exercise normalization (Property 3).
    - `llmResponseArbitrary`: emits partial / empty / whitespace-only / non-string field sets for
      `{ title, explanation, recommendation, fixSnippet }` (Pass 1) and `{ summary, topPriority }`
      (Pass 2), with keys present or absent — to exercise per-field substitution (Properties 9, 12).
    - `errorShapeArbitrary`: emits 401-like, 429-like, and timeout/abort-like rejections (varying
      `status`/`name`/`message`) so layer-selection tests are error-type agnostic (Property 20).
    - Export a `callLLMJson` mock controller (modeled on `analysis.pass3.arbitraries.js`:
      `resolveWith`, `rejectWith`, `rejectAbort`, `implement`, `callCount`, `lastCallArgs`) for use
      with `vi.mock("./llm.js")`.
    - _Requirements: 2.4, 2.6, 1.6, 6.1_

  - [x] 1.2 Expose the two pure scoring helpers as a test seam
    - In `netlify/functions/lib/analysis.js`, add the `export` keyword to the **existing**
      `computeFallbackScore` and `scoreToLevel` functions. No logic change of any kind.
    - Justification: Property 4 must assert `scoreToLevel` over *every* integer in 0..100, which the
      weighted-sum weights (40/22/10/3) cannot reach via findings alone; direct access is required.
    - Confirm nothing else in the file changes and `npm test` still passes for the existing suite.
    - _Requirements: 1.3, 1.4_

- [x] 2. Property tests for the deterministic scoring engine (Properties 1, 3, 4, 5, 10)
  - [x] 2.1 Property 1 — severity is always a valid deterministic value
    - Create `deterministic-fallback.property1.test.js`; drive `fallbackClassify` with
      `findingArbitrary`; assert the returned `severity` is always in
      `{critical, high, medium, low}` (with `info` reserved for the tech item), never an
      LLM-supplied value. Tag: `Feature: deterministic-fallback, Property 1: ...`; `numRuns >= 100`.
    - _Requirements: 1.1_

  - [x] 2.2 Property 10 — the deterministic rule is total
    - Create `deterministic-fallback.property10.test.js`; with `findingArbitrary` restricted to
      unknown ids/types, assert `fallbackClassify` returns `severity: "low"` plus non-empty generic
      `explanation` and `recommendation`. Tag with Property 10; `numRuns >= 100`.
    - _Requirements: 2.6_

  - [x] 2.3 Property 3 — risk score is the clamped, case-normalized weighted sum
    - Create `deterministic-fallback.property3.test.js`; with a multiset of `severityArbitrary`
      values (mixed-case + junk), assert `computeFallbackScore` equals
      `min(100, Σ weight(lower(severity)))` with `{critical:40,high:22,medium:10,low:3}` and
      `info`/unrecognized contributing 0. Tag with Property 3; `numRuns >= 100`.
    - _Requirements: 1.3, 1.6_

  - [x] 2.4 Property 4 — risk level partitions the score range
    - Create `deterministic-fallback.property4.test.js`; over `fc.integer({min:0,max:100})`, assert
      `scoreToLevel` returns exactly one of Critical (≥70) / High (45–69) / Medium (20–44) /
      Low (0–19), confirming mutual exclusivity and exhaustiveness. Tag with Property 4;
      `numRuns >= 100`.
    - _Requirements: 1.4_

  - [x] 2.5 Property 5 — score and level are order-independent and deterministic
    - Create `deterministic-fallback.property5.test.js`; generate a list of findings and a
      permutation, then assert `computeFallbackScore` is byte-identical and `scoreToLevel` returns an
      identical string for both orderings (also verifiable end-to-end via `buildFallbackReport`).
      Tag with Property 5; `numRuns >= 100`.
    - _Requirements: 1.5_

- [x] 3. Checkpoint — scoring-engine property tests
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Property + example tests for Pass 1 per-finding fallback (Properties 2, 6, 7, 8, 9)
  - [x] 4.1 Property 2 — the LLM never sets severity
    - Create `deterministic-fallback.property2.test.js`; `vi.mock("./llm.js")`, resolve
      `callLLMJson` with `llmResponseArbitrary` (including a bogus `severity` field); assert
      `classifyOne` returns `severity === fallbackClassify(finding).severity` while using the LLM's
      `title`/`explanation`/`recommendation`. Tag with Property 2; `numRuns >= 100`.
    - _Requirements: 1.2, 2.7_

  - [x] 4.2 Property 8 — successful classification is tagged `"llm"`
    - Create `deterministic-fallback.property8.test.js`; resolve `callLLMJson` successfully; assert
      `classifyOne` returns `_source: "llm"`. Tag with Property 8; `numRuns >= 100`.
    - _Requirements: 2.3_

  - [x] 4.3 Property 9 — missing or empty LLM fields fall back per-field
    - Create `deterministic-fallback.property9.test.js`; resolve `callLLMJson` with
      `llmResponseArbitrary` that omits/empties a subset of
      `{title, explanation, recommendation, fixSnippet}`; assert each missing/empty field takes the
      deterministic rule value (or `defaultFixSnippet` for `fixSnippet`) while supplied fields are
      retained. Tag with Property 9; `numRuns >= 100`.
    - _Requirements: 2.4_

  - [x] 4.4 Property 6 — per-finding LLM failure degrades to the deterministic rule
    - Create `deterministic-fallback.property6.test.js`; reject `callLLMJson` with
      `errorShapeArbitrary` (throw / abort / unparseable); assert `classifyOne` returns
      `{ ...fallbackClassify(finding), type, _source: "fallback" }`. Tag with Property 6;
      `numRuns >= 100`.
    - _Requirements: 2.1_

  - [x] 4.5 Property 7 — per-finding failures are isolated from siblings
    - Create `deterministic-fallback.property7.test.js`; for a generated list of findings, make
      `callLLMJson` fail for exactly one (by matching its payload) and succeed for the rest via the
      mock `implement`; assert every other finding's prose, severity, and `_source` match a
      no-failure baseline run. Tag with Property 7; `numRuns >= 100`.
    - _Requirements: 2.2_

  - [x] 4.6 Example — Pass 1 dispatches all findings concurrently
    - Create `deterministic-fallback.pass1-concurrency.test.js`; spy on `callLLMJson` so it records
      call-initiation order and resolves on a deferred; assert `runPass1` initiates the call for
      every finding before any awaiting completes, and returns exactly one result per finding.
    - _Requirements: 2.5_

- [x] 5. Property + example tests for Pass 2 whole-report fallback (Properties 11, 12, 13)
  - [x] 5.1 Property 11 — Pass 2 failure yields a deterministic fallback report
    - Create `deterministic-fallback.property11.test.js`; with a non-empty classified list and
      `callLLMJson` rejecting (via `errorShapeArbitrary`), assert `runPass2` returns
      `buildFallbackReport(domain, sorted)` shape tagged `_source: "fallback"`, carrying the
      deterministic score/level, severity-ordered findings (Pass 1 prose preserved), a synthesized
      summary, and a `topPriority`. Tag with Property 11; `numRuns >= 100`.
    - _Requirements: 3.1, 3.7_

  - [x] 5.2 Property 12 — Pass 2 success keeps LLM prose with deterministic numbers, substituting empties
    - Create `deterministic-fallback.property12.test.js`; with `callLLMJson` resolving via
      `llmResponseArbitrary` (`summary`/`topPriority` present, empty, whitespace, or absent), assert
      `_source: "llm"`, score/level/order are the deterministic values, `summary`/`topPriority` use
      the LLM value when non-empty, else fall back to the synthesized summary and the
      highest-severity finding's recommendation respectively. Tag with Property 12; `numRuns >= 100`.
    - _Requirements: 3.2, 3.3, 3.4_

  - [x] 5.3 Property 13 — Pass 2 findings are severity-ordered
    - Create `deterministic-fallback.property13.test.js`; for any classified list, assert
      `runPass2` output `findings` are ordered by severity rank Critical > High > Medium > Low. Tag
      with Property 13; `numRuns >= 100`.
    - _Requirements: 3.6_

  - [x] 5.4 Example — Pass 2 empty short-circuit (no LLM call)
    - Create `deterministic-fallback.pass2-empty.test.js`; call `runPass2([], domain, tech)` with a
      spied `callLLMJson`; assert `_source: "none"`, `overallRiskScore` 5, `riskLevel` "Low", empty
      `findings`, and that `callLLMJson` was **not** invoked.
    - _Requirements: 3.5_

- [x] 6. Checkpoint — Pass 1 and Pass 2 tests
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Property tests for Pass 3 narrative omission (Properties 14, 15, 16, 17)
  - [x] 7.1 Property 15 — both narrative fields empty means absent
    - Create `deterministic-fallback.property15.test.js`; resolve `callLLMJson` with
      `attackScenario` and `ifUnaddressed` both empty/whitespace; assert `runPass3` returns `null`.
      Tag with Property 15; `numRuns >= 100`.
    - _Requirements: 4.2_

  - [x] 7.2 Property 16 — one non-empty narrative field means present
    - Create `deterministic-fallback.property16.test.js`; resolve with exactly one of the two fields
      non-empty; assert `runPass3` returns an object carrying both trimmed values. Tag with
      Property 16; `numRuns >= 100`.
    - _Requirements: 4.3_

  - [x] 7.3 Property 14 — a failed narrative is truly absent with the core report intact
    - Create `deterministic-fallback.property14.test.js`; given any base report, simulate Pass 3
      failure (reject) or absent narrative, then apply the handler's attach rule
      (`if (narrative) {...}`); assert the report has no `attackScenario`/`ifUnaddressed` keys, no
      placeholder content, and every other field is unchanged — whether Pass 2 succeeded or fell
      back. Tag with Property 14; `numRuns >= 100`.
    - _Requirements: 4.1, 4.4, 4.6_

  - [x] 7.4 Property 17 — the base report is deterministic regardless of pass outcomes
    - Create `deterministic-fallback.property17.test.js`; for any list of Pass 1 findings, build the
      base report (`buildFallbackReport` over sorted findings) and assert its score, level, and
      finding ordering are identical across simulated Pass 2/Pass 3 outcomes
      (success/fallback/null). Tag with Property 17; `numRuns >= 100`.
    - _Requirements: 4.5_

- [x] 8. Property + example/edge tests for the top-level budget race and composition (Properties 18, 19, 20, 21, 22)
  - [x] 8.1 Property 22 — report source tag is always within the allowed domain
    - Create `deterministic-fallback.property22.test.js`; across generated findings and mocked
      pipeline outcomes, assert every produced report's `_source` is one of
      `"llm" | "fallback" | "none" | "deterministic"` and never `"error"`. Tag with Property 22;
      `numRuns >= 100`.
    - _Requirements: 7.1_

  - [x] 8.2 Property 18 — the deterministic report re-derives everything from scratch
    - Create `deterministic-fallback.property18.test.js`; for any list of findings, assert the
      deterministic report's classifications equal `fallbackClassify` applied independently to each
      finding (no in-flight Pass 1 output), sorted by severity rank, tagged `_source: "fallback"`.
      Drive via the handler timeout path (fake timers) or the equivalent re-derivation used by
      `deterministicReport`. Tag with Property 18; `numRuns >= 100`.
    - _Requirements: 5.4, 5.5_

  - [x] 8.3 Property 21 — the two fallback reports agree on numbers and differ on prose
    - Create `deterministic-fallback.property21.test.js`; for findings carrying Pass 1 LLM-authored
      prose, compare the Pass 2 Fallback_Report (`runPass2` with rejecting LLM, prose retained)
      against the re-derived Deterministic_Report (`fallbackClassify` + `buildFallbackReport`);
      assert identical per-finding severity, `overallRiskScore`, and `riskLevel`, both tagged
      `_source: "fallback"`, differing only in prose where LLM prose existed. Tag with Property 21;
      `numRuns >= 100`.
    - _Requirements: 6.4, 6.5_

  - [x] 8.4 Property 20 — layer selection is latency-driven, not error-typed
    - Create `deterministic-fallback.property20.test.js`; `vi.mock("./llm.js")` rejecting with
      `errorShapeArbitrary` (401/429/timeout-like) settling *before* the 14000 ms budget; assert the
      AI pipeline resolves with the Pass 2 Fallback_Report and the top-level `deterministicReport()`
      is not invoked — outcome independent of error type. Tag with Property 20; `numRuns >= 100`.
    - _Requirements: 6.1, 6.2_

  - [x] 8.5 Property 19 — exactly one Result_Event per scan
    - Create `deterministic-fallback.property19.test.js`; with a mocked pipeline and fake timers,
      parameterize the timing scenario (resolve fast / resolve slow / reject; budget elapsing or
      not) and assert exactly one `{type:"result"}` event is emitted to the stream, carrying either
      the AI report or the Deterministic_Report but never both. Tag with Property 19;
      `numRuns >= 100`.
    - _Requirements: 5.8_

  - [x] 8.6 Example — budget race timing with fake timers
    - Create `deterministic-fallback.scan-budget.test.js`; using `vi.useFakeTimers()` and a
      controllable pipeline: (a) pipeline pending past 14000 ms ships the Deterministic_Report;
      (b) pipeline resolving first ships the AI report and calls `clearTimeout`; (c) the pipeline
      rejecting within budget ships the Deterministic_Report; (d) a timer firing *after* the result
      produces no additional event.
    - _Requirements: 5.1, 5.2, 5.3, 5.6, 5.7_

  - [x] 8.7 Example — fatal handler error and DNS-resolution failure emit a Stream_Error_Event
    - Create `deterministic-fallback.scan-error.test.js`; force a handler exception and a
      `RESOLUTION_FAILURE` from the engine; assert a `{type:"error", message}` event is emitted, the
      stream closes, and no `{type:"result"}` report event (and no `_source: "error"`) is produced.
    - _Requirements: 5.9, 7.2_

- [x] 9. Frontend banner example tests (known gap, Requirement 7)
  - [x] 9.1 Assert the fallback banner rendering and document the dead `"error"` branch
    - Create `deterministic-fallback.frontend.test.js` (jsdom); render with
      `report._source === "fallback"` and assert the banner is visible; assert the
      `report._source === "error"` branch in `public/app.js` is unreachable from the backend by a
      code-level assertion that no backend path sets `_source: "error"` (cross-checked against
      Task 8.7). Treat the dead branch as recorded, not fixed.
    - _Requirements: 7.3, 7.4_

- [x] 10. Final checkpoint — full suite green against the existing implementation
  - Run `npm test`; confirm all 22 property tests (≥ 100 iterations each) and every example/edge
    test pass without any change to production fallback logic beyond the Task 1.2 export seam.
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- This is a documentation/formalization spec: the only production edit is the minimal `export` seam
  in Task 1.2. No fallback logic is rewritten.
- Every one of Properties 1–22 is implemented by exactly one property-based test file, each tagged
  `Feature: deterministic-fallback, Property {number}: {property_text}` and run with
  `numRuns >= 100`.
- All example/edge tests from the design's Testing Strategy are covered: Pass 1 concurrency (4.6),
  Pass 2 empty short-circuit (5.4), budget timing (8.6), pipeline rejection within budget (8.6),
  fatal/DNS failure (8.7), and the frontend banner (9.1).
- Each task references the specific design property and requirements clause it validates, and names
  the exact test file to create and what to assert.
- The `callLLMJson` mock keeps every iteration in-memory and deterministic; handler timing tests use
  Vitest fake timers against the 14000 ms `ANALYSIS_BUDGET_MS`.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "2.2", "2.3", "2.4", "2.5"] },
    { "id": 2, "tasks": ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6"] },
    { "id": 3, "tasks": ["5.1", "5.2", "5.3", "5.4"] },
    { "id": 4, "tasks": ["7.1", "7.2", "7.3", "7.4"] },
    { "id": 5, "tasks": ["8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7"] },
    { "id": 6, "tasks": ["9.1"] }
  ]
}
```
