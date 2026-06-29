# Implementation Plan: Finding Classification (Pass 1) — Verification Suite

## Overview

This plan builds a **verification and test suite** that proves the *already-implemented, working* Pass 1 classifier conforms to the documented requirements and the 9 correctness properties in the design.

The production implementation (`netlify/functions/lib/analysis.js` — `runPass1`, `classifyOne`, `pass1System`, `normalizeSnippet`; with collaborators in `findings.js`, `llm.js`, `scan.js`) is **frozen**. No task below modifies, rewrites, or refactors production code. All work is test-only authoring in the existing `tests/` directory.

Implementation language: **JavaScript (ESM)** — matching the existing codebase and the existing Vitest + fast-check setup (`package.json`, `vitest.config.js`).

Test seam (no production change): the LLM boundary is controlled by mocking the `./llm.js` module's `callLLMJson` export with Vitest's `vi.mock(..., async (importOriginal) => ...)`, exactly as the existing `tests/chat.branches.test.js` already does. Capturing the `opts` passed to that double lets us assert prompt content and isolation without exporting `pass1System` / `classifyOne`, so **no production seam needs to be added**. The `llm.js` timeout/retry tests mock `global.fetch` instead and drive Vitest fake timers; again, no production change.

Each property test is tagged with a comment in the form:
`Feature: finding-classification, Property {N}: {property_text}` and runs a **minimum of 100 iterations**.

## Tasks

- [x] 1. Establish the Pass 1 verification harness and shared fixtures
  - [x] 1.1 Add the LLM-double mock scaffold and confirm test discovery
    - Verify (do not change) that `package.json` carries `vitest` + `fast-check` devDeps and the `test` script, and that `vitest.config.js` includes `tests/` via `**/*.test.js`
    - Create `tests/helpers/llm-double.js`: a reusable factory that builds a configurable `callLLMJson` stand-in (a `vi.fn()`-style spy) which records every `opts` it is called with (so `system` + `messages` content can be asserted) and can be programmed per-call to resolve a JSON object, throw a generic error, throw a parse-style error, or simulate a timeout rejection
    - Document the `vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => ({ ...await importOriginal(), callLLMJson: <double> }))` pattern as the single test seam; assert NO production file is edited
    - _Requirements: design "Testing Strategy" (property-based testing harness, controllable LLM double)_

  - [x] 1.2 Build shared fast-check generators and oracle helpers
    - Create `tests/helpers/pass1-fixtures.js` with fast-check arbitraries that produce: finding lists spanning every `type` (`email-auth`, `tls`, `header`, `subdomain`, `dns`, `cookie`, `mixed-content`, `info-leak`, `exposure`), both fixed ids (e.g. `spf-missing`) and dynamic ids (`exposed-file-/path`, `subdomain-<name>`); findings with and without `suggestedSnippet`; arbitrary `fixSnippet` strings including whitespace-padded, empty, whitespace-only, and `"null"`/`"NULL"` variants; `provider` arbitraries (null and non-null with a unique sentinel substring); and `tech` arbitraries with non-empty, empty, missing-`detected`, and absent forms
    - Re-export `fallbackClassify` / `defaultFixSnippet` from `findings.js` as the expected-value oracle (the suite compares production output against the real deterministic functions, never a reimplementation)
    - Add a per-finding sentinel injector so each generated finding embeds a unique marker in `label`/`detail`/`suggestedSnippet`, enabling cross-finding leakage assertions
    - _Requirements: design "Testing Strategy" (generators); supports Properties 1–9_

- [x] 2. Implement isolation, alignment, and severity property tests
  - [x] 2.1 Property test — exactly one isolated LLM call per finding
    - Create `tests/pass1.property1.isolation.test.js`; for N findings assert `callLLMJson` is called exactly N times and each call's captured `system`+`user` content contains that finding's sentinel and **no other** finding's `label`/`detail`/`type`/`suggestedSnippet`
    - **Feature: finding-classification, Property 1: Exactly one isolated LLM call per finding**
    - **Validates: Requirements 1.1, 1.3, 2.1, 2.2**

  - [x] 2.2 Property test — output is positionally aligned and identity-preserving
    - Create `tests/pass1.property2.alignment.test.js`; with randomized per-call resolution order, assert `result.length === findings.length` and for every `i`, `result[i].id === findings[i].id` and `result[i].type === findings[i].type`, across both llm- and fallback-sourced results
    - **Feature: finding-classification, Property 2: Output is positionally aligned and identity-preserving**
    - **Validates: Requirements 2.3, 9.2, 12.1, 12.2**

  - [x] 2.3 Property test — severity is always the deterministic rule value
    - Create `tests/pass1.property3.severity.test.js`; even when the LLM double returns a conflicting/bogus `severity`, assert `result.severity === fallbackClassify(finding).severity`; assert repeated classification is byte-identical and that toggling `tech` context never changes severity
    - **Feature: finding-classification, Property 3: Severity is always the deterministic rule value**
    - **Validates: Requirements 3.1, 3.2, 3.3, 5.4, 3.5**

- [x] 3. Implement degradation, backfill, and snippet property tests
  - [x] 3.1 Property test — per-finding failure degrades to deterministic fallback in isolation
    - Create `tests/pass1.property4.degradation.test.js`; program an arbitrary subset of calls to fail (timeout/parse/exception) and assert each failing finding equals `fallbackClassify(finding)` with `type` preserved and `_source === "fallback"`, non-failing findings have `_source === "llm"`, and the list still has exactly one result per input
    - **Feature: finding-classification, Property 4: Per-finding failure degrades to a deterministic fallback in isolation**
    - **Validates: Requirements 1.5, 2.5, 7.5, 9.1, 9.4, 12.4**

  - [x] 3.2 Property test — successful results are marked and prose-backfilled
    - Create `tests/pass1.property5.backfill.test.js`; for llm-sourced results assert `_source === "llm"` and that empty/missing `title`/`explanation`/`recommendation` are replaced by `finding.label` / deterministic explanation / deterministic recommendation respectively
    - **Feature: finding-classification, Property 5: Successful results are marked and backfilled**
    - **Validates: Requirements 12.3, 12.5, 12.6, 12.7**

  - [x] 3.3 Property test — fixSnippet is always a clean literal or null
    - Create `tests/pass1.property6.fixsnippet.test.js`; for arbitrary LLM `fixSnippet` values assert the result is either `null` or a trimmed non-empty string that is not `"null"` (case-insensitive); when the LLM value is unusable, assert it falls back to `defaultFixSnippet(finding)` (suggestedSnippet → per-type literal → null); and a whitespace-padded usable token is retained trimmed
    - **Feature: finding-classification, Property 6: fixSnippet is always a clean literal or null**
    - **Validates: Requirements 6.3, 6.4, 6.5, 6.6**

- [x] 4. Checkpoint — Ensure all property tests so far pass
  - Run the suite for Properties 1–6 against the frozen implementation; if any property fails, treat it as a finding to report (do NOT change production code), ask the user if questions arise.

- [x] 5. Implement prompt-injection, snippet-passthrough, and callback property tests
  - [x] 5.1 Property test — conditional provider and tech-stack prompt injection
    - Create `tests/pass1.property7.prompt-injection.test.js`; for non-null `provider` assert the captured system prompt contains the provider name + tailoring clause; for non-empty `tech.detected` assert a single comma-joined optional-guidance line listing every technology; for absent/empty/missing-`detected` assert no tech-context line appears
    - **Feature: finding-classification, Property 7: Conditional provider and tech-stack prompt injection**
    - **Validates: Requirements 4.1, 5.1, 5.3, 5.2**

  - [x] 5.2 Property test — suggestedSnippet is passed to the model verbatim
    - Create `tests/pass1.property8.snippet-passthrough.test.js`; for any finding carrying a `suggestedSnippet`, assert the captured user content for that finding contains the snippet value verbatim
    - **Feature: finding-classification, Property 8: suggestedSnippet is passed to the model verbatim**
    - **Validates: Requirements 6.2**

  - [x] 5.3 Property test — onEach is invoked once per finding and is failure-isolated
    - Create `tests/pass1.property9.oneach.test.js`; for a non-empty list with a supplied `onEach`, assert it is invoked exactly once per finding with that finding's result; for an always-throwing `onEach`, assert `runPass1` still resolves with exactly one result per input and does not reject
    - **Feature: finding-classification, Property 9: onEach is invoked once per finding and is failure-isolated**
    - **Validates: Requirements 10.1, 10.2**

- [x] 6. Implement fixed prompt-content example tests
  - [x] 6.1 Assert the static `pass1System` directives via captured prompt
    - Create `tests/pass1.prompt-content.test.js`; drive one `runPass1` call through the LLM double and assert the captured `system` string contains: the score-one-finding-in-isolation directive (Req 1.2); the exact JSON-shape instruction plus the explicit "do NOT assign a severity" rule (Req 3.4); the email-auth/CAA inline-literal-record instruction (Req 6.1); the never-infer/guess-a-provider line (Req 4.3); and, with `provider = null`, the generic provider-agnostic branch (Req 4.2)
    - Assert that with non-empty `tech.detected` the tech line is framed as optional ("only when ... confident", Req 5.2)
    - _Requirements: 1.2, 3.4, 6.1, 4.3, 4.2, 5.2_

- [x] 7. Implement empty-input and callback edge-case tests
  - [x] 7.1 Assert empty-input short-circuit and callback boundaries
    - Create `tests/pass1.empty-input.test.js`; assert `runPass1([])` returns `[]`, the `callLLMJson` double is never called, and a supplied `onEach` is never invoked (Req 1.4, 2.4, 10.4, 11.1–11.3)
    - Assert that with `onEach` omitted or set to a non-function, a non-empty list classifies fully and returns without throwing and without callback invocation (Req 10.3)
    - _Requirements: 1.4, 2.4, 10.3, 10.4, 11.1, 11.2, 11.3_

- [x] 8. Implement timeout / retry integration tests
  - [x] 8.1 Assert the per-call timeout value passed by `classifyOne`
    - Create `tests/pass1.timeout-retry.test.js`; via the captured `callLLMJson` opts assert `timeoutMs === 9000` (and `temperature === 0`, `maxTokens === 600`) for every Pass 1 call (Req 7.1)
    - _Requirements: 7.1_

  - [x] 8.2 Assert AbortController abort + single retry wiring in `callLLMJson`/`callLLM`
    - In `tests/pass1.timeout-retry.test.js`, mock `global.fetch` and use Vitest fake timers; assert a hanging fetch is aborted via `AbortController` once the 9000 ms timer fires (Req 7.2); assert an unparseable-then-valid sequence triggers exactly one retry whose system prompt carries the stricter JSON-only suffix (Req 7.3); and assert both attempts failing makes `callLLMJson` throw so `classifyOne` returns the `_source: "fallback"` result (Req 7.4)
    - Set `process.env.OPENAI_API_KEY` to a dummy value for these cases so `callLLM` reaches the fetch/abort path
    - _Requirements: 7.2, 7.3, 7.4_

- [x] 9. Implement whole-pass failure example test
  - [x] 9.1 Assert orchestration-level fallback when `runPass1` throws entirely
    - Create `tests/pass1.whole-pass-failure.test.js`; mock `analysis.js`'s `runPass1` to reject and assert `analyze` classifies every finding via `fallbackClassify` with `_source: "fallback"` and one result per finding (Req 9.3)
    - _Requirements: 9.3_

- [x] 10. Implement scan.js AI-phase budget race integration tests
  - [x] 10.1 Assert the 14s budget race outcomes in the scan handler
    - Create `tests/scan.budget-race.test.js`; mock `analysis.js` (`runPass1`/`runPass2`/`runPass3`) and the scan engine so the handler runs hermetically; using Vitest fake timers, assert: a pipeline resolving within `ANALYSIS_BUDGET_MS` (14000) emits the LLM `report` (Req 8.2); a never-resolving / over-budget pipeline emits the deterministic report and later sends on the closed stream are harmlessly ignored (Req 8.1, 8.3); and a pipeline rejecting before budget emits the deterministic report (Req 8.4)
    - Parse the NDJSON stream from the handler `Response` to locate the final `result` event and assert `report._source` distinguishes LLM vs deterministic
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [x] 11. Final checkpoint — Ensure the full verification suite passes
  - Run `npm test` (vitest run) across all new Pass 1 test files; confirm every property test executed at least 100 iterations. Any failing property/example is a conformance finding to surface to the user — do NOT alter the frozen production code. Ask the user if questions arise.

## Notes

- This is a **verification suite for already-shipped code**. No task edits production files; the only test seam is module-mocking `./llm.js` (and `global.fetch` for timer tests), matching the existing `tests/chat.branches.test.js` pattern.
- Property test sub-tasks are the **core deliverable** of this spec, so they are intentionally NOT marked optional (`*`). The usual "optional test" convention applies when tests supplement production code; here the tests *are* the product.
- Each property test references its design property number and the requirements clauses it validates; each runs ≥100 iterations via fast-check.
- Example/edge/integration tests cover the criteria the design classifies as non-property (fixed prompt wording, config values, timer/abort wiring, empty-input boundaries, one-shot orchestration failure, and the budget race).
- Requirement 6.1's *model compliance* (the model actually embedding the literal value) is not deterministically testable; only the prompt instruction is asserted (task 6.1), as noted in the design.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["2.1", "2.2", "2.3", "3.1", "3.2", "3.3", "5.1", "5.2", "5.3", "6.1", "7.1", "8.1", "9.1", "10.1"] },
    { "id": 3, "tasks": ["8.2"] }
  ]
}
```
