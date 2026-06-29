# Implementation Plan: Analyst Synthesis (Pass 2)

## Overview

This spec documents existing, working production code: `runPass2` and its deterministic
helpers in `netlify/functions/lib/analysis.js`, the `callLLMJson` client in
`netlify/functions/lib/llm.js`, and the `aiPipeline` orchestration in
`netlify/functions/scan.js`. The production logic is already shipped and correct.

Therefore these tasks do **not** rebuild that logic. They **verify the existing behavior
against the requirements and the 13 correctness properties** by:

1. Reusing the existing test harness (Vitest + fast-check) and the controllable
   `callLLMJson` module-mock seam in `tests/helpers/llm-double.js`, and adding Pass 2
   specific generators/oracles.
2. Implementing the 13 correctness properties from `design.md` as property-based tests
   (≥100 iterations each, tagged `// Feature: analyst-synthesis, Property N: ...`).
3. Implementing the example-based unit tests called out in the Testing Strategy: fixed
   prompt content (4.2–4.4), the `callLLMJson` internal retry (1.3), and the four
   concurrency failure combinations (9.1, 9.3, 9.4, 9.6).
4. Adding a behavior-preserving seam **only if** module-mocking proves insufficient
   (it does not, based on the Pass 1 suite).

Implementation language: **JavaScript (ESM)**, matching the production code and the
existing `tests/` suite. Test runner: **Vitest**. Property library: **fast-check**.

The single test seam is a `vi.mock` of `netlify/functions/lib/llm.js`'s `callLLMJson`
export. No production file is edited to enable testing.

## Tasks

- [x] 1. Establish the Pass 2 test harness and generators
  - [x] 1.1 Confirm the `callLLMJson` module-mock seam supports `runPass2` without a production refactor
    - Add `tests/pass2.harness.smoke.test.js` that `vi.mock`s `../netlify/functions/lib/llm.js` (keeping all real exports except `callLLMJson`) via the hoisted-spy pattern from `tests/pass1.property2.alignment.test.js`
    - Drive one `runPass2(classified, domain, tech)` call through the spy: assert the spy is invoked, captures `opts` (system, messages), and that a programmed resolve/throw flows back into `runPass2`
    - This proves `runPass2`, `callLLMJson`, and the `aiPipeline` orchestration in `scan.js` are all testable through the seam; only add a behavior-preserving seam to `analysis.js`/`scan.js` if this smoke test cannot be made to pass without one
    - _Requirements: 1.1_

  - [x] 1.2 Create `tests/helpers/pass2-fixtures.js` generators and oracles
    - `classifiedFindingArb`: a Classified_Finding arbitrary with random `id`, `title`, `explanation`, `recommendation`, and a `severity` drawn from a set that deliberately includes `critical`, `high`, `medium`, `low`, `info`, mixed-case variants (e.g. `Critical`, `HIGH`), `null`, and arbitrary strings — so scoring/sorting exercise the 0-weight and rank-0 paths
    - `classifiedListArb({minLength,maxLength})`: arrays of Classified_Findings; tag each element with its original index so the sort-stability oracle can verify relative order of equal-rank items
    - `domainArb`: a domain-string arbitrary for zero-findings and request-content properties
    - `llmResponseArb`: a Pass 2 response arbitrary whose `summary`/`topPriority` are each independently present-and-nonempty, present-but-empty, non-string, or absent, and which may also include extra `score`/`riskLevel`/`overallRiskScore` fields (to prove they are ignored)
    - Oracles: `expectedScore(findings)` recomputing `min(100, Σ weights)` with weights critical=40/high=22/medium=10/low=3 and 0 otherwise (case-insensitive); `expectedLevel(score)` recomputing the bands (≥70 Critical, ≥45 High, ≥20 Medium, else Low); `expectedSorted(findings)` producing the severity-desc stable order via tagged indices
    - Re-export the real helpers used as ground truth where applicable; import the controllable double from `tests/helpers/llm-double.js`
    - _Requirements: 2.1, 2.2, 2.4, 3.1, 3.2, 3.3, 3.4, 6.6_

  - [ ]* 1.3 Add a fixtures self-check test
    - `tests/pass2.fixtures.smoke.test.js`: assert `classifiedFindingArb` produces the full severity space (including null/mixed-case/arbitrary) and that the oracles agree with hand-computed examples
    - _Requirements: 2.1, 3.1_

- [x] 2. Verify deterministic scoring and banding (Properties 3, 5, 4)
  - [x] 2.1 Property test: deterministic capped weighted-sum score
    - `tests/pass2.property3.score.test.js`
    - **Property 3: Deterministic score is the capped weighted sum within 0..100**
    - Drive `runPass2` (LLM double resolving valid prose) over `classifiedListArb`; assert `report.overallRiskScore === expectedScore(findings)` and that it lies in `[0,100]`, covering critical/high/medium/low plus info/other/absent/null = 0 (case-insensitive)
    - **Validates: Requirements 2.1, 2.2, 2.4**

  - [x] 2.2 Property test: risk-level banding is correct and total
    - `tests/pass2.property5.banding.test.js`
    - **Property 5: Risk level banding is correct and total**
    - For any integer score in 0..100, assert the level derived in the report equals `expectedLevel(score)` and is exactly one of Critical/High/Medium/Low (boundaries 70/45/20)
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6**

  - [x] 2.3 Property test: score and level are authoritative, independent of order and LLM output
    - `tests/pass2.property4.authoritative.test.js`
    - **Property 4: Score and level are authoritative — independent of finding order and of LLM output**
    - Sweep all LLM outcomes via the double (omitted score/level, equal values, conflicting values, and a thrown failure → fallback) and any permutation of findings; assert `overallRiskScore`/`riskLevel` are invariant and equal the deterministic values in every case
    - **Validates: Requirements 2.3, 2.5, 3.5, 3.7, 5.1, 5.2, 5.3, 5.4, 7.5**

- [x] 3. Checkpoint - deterministic scoring verified
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Verify LLM call count and request contents (Properties 1, 2, 6)
  - [x] 4.1 Property test: at most one LLM call for any non-empty finding set
    - `tests/pass2.property1.single-call.test.js`
    - **Property 1: At most one LLM call for any non-empty finding set**
    - Over `classifiedListArb` (min length 1), assert the `callLLMJson` double is invoked exactly once regardless of finding count
    - **Validates: Requirements 1.1, 1.2, 1.3**

  - [x] 4.2 Property test: no LLM call for an empty finding set
    - `tests/pass2.property2.no-call-empty.test.js`
    - **Property 2: No LLM call for an empty finding set**
    - For any `domainArb` and tech context, assert `runPass2([], domain, tech)` invokes the double zero times
    - **Validates: Requirements 1.4, 8.1**

  - [x] 4.3 Property test: request carries the deterministic score and level
    - `tests/pass2.property6.request-context.test.js`
    - **Property 6: The LLM request carries the deterministic score and level**
    - Capture the double's `opts`; parse the embedded JSON user content and assert it contains the deterministic integer `overallRiskScore` (0..100) and the derived `riskLevel` (one of the four bands)
    - **Validates: Requirements 4.1**

- [x] 5. Verify prose handling, ordering, and source tagging (Properties 7, 8, 9)
  - [x] 5.1 Property test: valid model prose used verbatim and tagged "llm"
    - `tests/pass2.property7.prose-verbatim.test.js`
    - **Property 7: Valid model prose is used verbatim and tagged "llm"**
    - For non-empty findings and a response whose `summary`/`topPriority` are non-empty strings, assert the report uses them verbatim and `_source === "llm"`
    - **Validates: Requirements 6.1, 6.3, 6.5**

  - [x] 5.2 Property test: missing/invalid prose falls back deterministically
    - `tests/pass2.property8.prose-fallback.test.js`
    - **Property 8: Missing or invalid model prose falls back deterministically**
    - For responses where `summary` and/or `topPriority` is absent/empty/non-string, assert `summary` defaults to `synthFallbackSummary(domain, sorted)` (naming domain, total count, per-severity counts) and/or `topPriority` defaults to the first sorted finding's `recommendation`
    - **Validates: Requirements 6.2, 6.4**

  - [x] 5.3 Property test: findings ordered by severity descending and stably
    - `tests/pass2.property9.sort-stable.test.js`
    - **Property 9: Findings are ordered by severity descending and stably**
    - Assert report findings are non-increasing by rank (critical>high>medium>low>other) and equal-rank findings preserve original relative order (verified via tagged indices)
    - **Validates: Requirements 6.6**

- [x] 6. Checkpoint - call, request, and prose behavior verified
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Verify failure fallback and zero-findings shape (Properties 10, 11)
  - [x] 7.1 Property test: any LLM failure yields the deterministic Base_Report
    - `tests/pass2.property10.failure-fallback.test.js`
    - **Property 10: Any LLM failure yields the deterministic Base_Report**
    - For non-empty findings, sweep the double over throw / timeout (AbortError) / parse-failure rejections; assert the report equals `buildFallbackReport(domain, sorted)`: deterministic score/level, templated summary, severity-sorted findings, `topPriority` = first sorted finding's `recommendation`, `_source === "fallback"`
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.6, 7.7**

  - [x] 7.2 Property test: zero-findings report has the fixed clean shape
    - `tests/pass2.property11.zero-findings.test.js`
    - **Property 11: Zero-findings report has the fixed clean shape**
    - For any `domainArb`, assert `runPass2([], domain, tech)` returns `overallRiskScore === 5`, `riskLevel === "Low"`, `findings === []`, a `summary` containing the domain verbatim and conveying no notable exposures, the fixed maintenance `topPriority`, and `_source === "none"`
    - **Validates: Requirements 8.2, 8.3, 8.4, 8.5, 8.6, 8.7**

- [x] 8. Verify orchestration independence (Properties 12, 13)
  - [x] 8.1 Property test: Pass 3 receives a deterministic base report derived only from Pass 1
    - `tests/pass2.property12.pass3-base-report.test.js`
    - **Property 12: Pass 3 receives a deterministic base report derived only from Pass 1**
    - Mock the AI passes in `scan.js` (keep `buildFallbackReport`/`attachTechStack` real, per `tests/scan.budget-race.test.js`); capture the report argument handed to `runPass3` and assert it equals `buildFallbackReport(domain, sortedClassified)` with deterministic score/level/severity-sorted findings and carries no field originating from `runPass2`
    - **Validates: Requirements 9.2**

  - [x] 8.2 Property test: Pass 2 failure substitutes the identical deterministic base report
    - `tests/pass2.property13.pass2-failure-substitute.test.js`
    - **Property 13: Pass 2 failure substitutes the identical deterministic base report**
    - With `runPass2` mocked to produce no usable result inside the concurrent `Promise.all`, assert the orchestrator ships the deterministic Base_Report identical to the one given to Pass 3, preserving `overallRiskScore`/`riskLevel`/findings
    - **Validates: Requirements 9.5**

- [x] 9. Checkpoint - failure, zero-findings, and orchestration verified
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Example-based unit tests for fixed and scenario-specific behavior
  - [x] 10.1 Prompt-content example test
    - `tests/pass2.prompt-content.test.js`
    - Assert the `PASS2_SYSTEM` string (captured via the double's `opts.system`, or asserted on the constant) declares the provided risk level authoritative, forbids the model from emitting its own score/level, and requests a JSON object whose only fields are `summary` and `topPriority`
    - _Requirements: 4.2, 4.3, 4.4_

  - [x] 10.2 `callLLMJson` internal-retry example test
    - `tests/pass2.calllljson-retry.test.js`
    - Mock the underlying `callLLM` (or global `fetch`) so attempt 1 returns unparseable text and attempt 2 returns valid JSON; assert one parsed result is returned and that a single logical `callLLMJson` call maps to two underlying attempts — confirming the retry is parse-robustness, not a second synthesis call
    - _Requirements: 1.3_

  - [x] 10.3 Concurrency and independence example test
    - `tests/pass2.concurrency-combinations.test.js`
    - With Pass 2 and Pass 3 stubbed in `scan.js`, assert both launch via `Promise.all` with independent catches and verify the four combinations: Pass 2 fails → Pass 3 narrative still included with base report substituted; Pass 3 fails → Pass 2 summary kept and narrative fields omitted; both fail → final report is the base report with no narrative fields
    - _Requirements: 9.1, 9.3, 9.4, 9.6_

- [x] 11. Final checkpoint - full Pass 2 verification suite green
  - Run `npm test` (Vitest, `--run`); ensure all 13 property tests (≥100 iterations each) and all example tests pass. Ask the user if questions arise.

## Notes

- This is a **verification spec for existing, shipped code**. The production functions
  (`runPass2`, `computeFallbackScore`, `scoreToLevel`, `sortFindings`,
  `synthFallbackSummary`, `buildFallbackReport`, `callLLMJson`, `aiPipeline`) are not
  rebuilt — the tasks confirm their behavior matches the requirements and properties.
- Property and example tests are the **primary deliverable** here, so they are not marked
  optional (the `*` convention for skippable tests does not apply to a test-only spec).
  Only the supplementary smoke/self-check task (1.3) is marked optional.
- Each property test references its design property number and the requirements clauses it
  validates, and must run a minimum of 100 iterations with the
  `// Feature: analyst-synthesis, Property N: ...` tag.
- The only test seam is the `vi.mock` of `callLLMJson`; no production file is edited unless
  task 1.1 proves a behavior-preserving seam is unavoidable.
- Orchestration properties (12, 13) and the concurrency example (10.3) drive `scan.js`
  hermetically by mocking the AI passes while keeping `buildFallbackReport`/`attachTechStack`
  real, mirroring `tests/scan.budget-race.test.js`.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "2.1", "2.2", "2.3", "4.1", "4.2", "4.3", "5.1", "5.2", "5.3", "7.1", "7.2", "8.1", "8.2", "10.1", "10.2", "10.3"] }
  ]
}
```
