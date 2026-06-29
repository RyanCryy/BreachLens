# Requirements Document

## Introduction

This document formalizes the requirements for **Pass 1 of the multi-pass AI analysis pipeline**: the per-finding classification stage implemented in `netlify/functions/lib/analysis.js` (functions `runPass1()` and `classifyOne()`), supported by `netlify/functions/lib/findings.js` (`fallbackClassify`, `defaultFixSnippet`, `deriveFindings`) and `netlify/functions/lib/llm.js` (`callLLMJson`). The overall AI-phase budget is enforced by the scan handler in `netlify/functions/scan.js`.

This specification documents the **observable behavior of already-implemented, working code**. It is written retroactively to capture the contract of the existing system; it does not propose new behavior or request code changes. Acceptance criteria are framed around the externally verifiable behavior of `runPass1` / `classifyOne` and their collaborators.

Pass 1 takes a list of discrete raw scan findings and produces, for each one, a classified result containing human-readable prose (title, explanation, recommendation, fix snippet) and a deterministically-assigned severity. Each finding is scored in isolation by a single LLM call, with graceful degradation to a deterministic rule-based classification whenever the LLM is unavailable, slow, or returns unparseable output.

## Glossary

- **Pass_1_Classifier**: The subsystem comprising `runPass1` and `classifyOne` that classifies each raw finding independently. The "system" referenced in acceptance criteria unless otherwise specified.
- **Finding**: A discrete, single security issue produced by `deriveFindings`. Each finding carries at minimum an `id`, a `type` (category), a `label`, and a `detail`, and may optionally carry a `suggestedSnippet` (a pre-computed paste-ready record value) and a `path`.
- **Classification_Result**: The object produced for a single finding, containing `id`, `type`, `title`, `severity`, `explanation`, `recommendation`, `fixSnippet`, and `_source`.
- **LLM_Call**: A single invocation of `callLLMJson` (in `llm.js`) that requests a JSON object from the language model.
- **Deterministic_Classifier**: The `fallbackClassify` function in `findings.js`, which assigns severity and default prose from fixed lookup tables keyed by finding id/type.
- **Severity**: One of `critical`, `high`, `medium`, or `low`, assigned exclusively by the Deterministic_Classifier.
- **Provider**: A DNS/hosting provider name that has been confidently identified via a verified nameserver-pattern lookup (`inferProvider`). May be absent (null) when no confident match exists.
- **Tech_Stack**: An optional object describing detected site technologies (`tech.detected` is a list of technology names). Treated as remediation context only, never as a vulnerability.
- **suggestedSnippet**: A pre-computed, literal, copy-pasteable record value attached to certain findings (SPF, DMARC, CAA) by `deriveFindings`.
- **fixSnippet**: A field on the Classification_Result that holds a paste-ready literal value (e.g. a DNS record string) or `null`. Never prose.
- **_source**: A provenance marker on each Classification_Result: `"llm"` when LLM prose was used, `"fallback"` when the finding degraded to the Deterministic_Classifier.
- **onEach_Callback**: An optional caller-supplied function invoked once per completed finding, used by the streaming scan path.
- **AI_Phase_Budget**: The fixed overall wall-clock budget (`ANALYSIS_BUDGET_MS`, 14000 ms) enforced by the scan handler for the combined AI phase (Pass 1 + Pass 2 + Pass 3 run concurrently).
- **Per_Call_Timeout**: The 9000 ms timeout applied to each individual Pass 1 classification attempt.

## Requirements

### Requirement 1: Independent per-finding classification

**User Story:** As a scan engine, I want each raw finding classified on its own merits, so that one finding's severity or prose is never influenced by the presence or absence of other findings.

#### Acceptance Criteria

1. WHEN `runPass1` classifies a non-empty list of N Findings, THE Pass_1_Classifier SHALL issue exactly one LLM_Call per Finding (N LLM_Calls total), and SHALL NOT issue any LLM_Call that references more than one Finding.
2. WHEN the Pass_1_Classifier builds the LLM_Call for a Finding, THE Pass_1_Classifier SHALL include a system instruction directing the model to judge that Finding in isolation and to not assume the presence or absence of other Findings.
3. WHEN the Pass_1_Classifier builds the user content for a Finding, THE Pass_1_Classifier SHALL include only that single Finding's issue label, detail, and category (and that Finding's own pre-computed record value when present), and SHALL NOT include the label, detail, category, or any other data of any other Finding.
4. WHEN `runPass1` is invoked with an empty list of Findings, THE Pass_1_Classifier SHALL issue zero LLM_Calls and SHALL return an empty list of Classification_Results.
5. IF the LLM_Call for a Finding fails, THEN THE Pass_1_Classifier SHALL produce a deterministic rule-based Classification_Result for that Finding and SHALL leave the Classification_Result of every other Finding unaffected.

### Requirement 2: Concurrent dispatch

**User Story:** As a scan engine operating under a tight time budget, I want all per-finding classification calls dispatched concurrently, so that total classification time is bounded by the slowest finding rather than the sum of all findings.

#### Acceptance Criteria

1. WHEN `runPass1` processes a non-empty list of findings, THE Pass_1_Classifier SHALL dispatch one classification LLM_Call per finding concurrently via `Promise.all`, and SHALL NOT return until all dispatched calls have settled.
2. THE Pass_1_Classifier SHALL NOT combine multiple findings into a single LLM_Call.
3. WHEN all per-finding classifications complete, THE Pass_1_Classifier SHALL return the Classification_Results in the same order as the input findings, with exactly one Classification_Result per input finding.
4. WHEN `runPass1` receives an empty list of findings, THE Pass_1_Classifier SHALL return an empty list of Classification_Results without dispatching any LLM_Call.
5. IF a per-finding LLM_Call fails or does not complete within its Per_Call_Timeout of 9000 ms per attempt (with one retry before failure), THEN THE Pass_1_Classifier SHALL substitute a deterministic rule-based Classification_Result for that finding and SHALL complete all remaining concurrent classifications without interruption.

### Requirement 3: Deterministic severity assignment

**User Story:** As a report consumer, I want severity to be identical across repeat scans of the same finding, so that risk scores and badges are stable and reproducible.

#### Acceptance Criteria

1. THE Pass_1_Classifier SHALL assign the Severity of every Classification_Result from the Deterministic_Classifier, selecting the value by matching the finding's `id` first, then by its `type` when the `id` is dynamic (e.g. exposure or subdomain findings), and defaulting to `low` when neither matches.
2. THE Pass_1_Classifier SHALL NOT use any LLM-provided value to determine Severity.
3. WHEN the same finding (same `id` and `type`) is classified on repeated scans, THE Pass_1_Classifier SHALL produce a byte-identical Severity value.
4. WHEN the Pass_1_Classifier builds the LLM_Call, THE Pass_1_Classifier SHALL instruct the model to supply only title, explanation, recommendation, and fixSnippet, and SHALL instruct the model not to assign a severity.
5. IF the LLM_Call for a finding fails, THEN THE Pass_1_Classifier SHALL still assign that finding's Severity from the Deterministic_Classifier.

### Requirement 4: Confident provider context

**User Story:** As a domain owner, I want fix instructions tailored to my actual DNS/hosting provider when it is known, and generic instructions otherwise, so that guidance is accurate and never names a provider that was guessed.

#### Acceptance Criteria

1. WHERE a non-null Provider value (set only via a verified nameserver-pattern lookup) has been supplied, THE Pass_1_Classifier SHALL include that Provider name in the LLM_Call system instruction and state that remediation MAY be tailored to that Provider's actual dashboard or workflow.
2. IF the supplied Provider value is null, THEN THE Pass_1_Classifier SHALL instruct the model to give generic, provider-agnostic fix instructions and SHALL instruct the model not to name or guess any specific provider, platform, or registrar.
3. THE Pass_1_Classifier SHALL instruct the model to reference a provider by name only when a non-null, confidently-matched Provider value was supplied in the system instruction, and never to infer, guess, or name a provider on its own.

### Requirement 5: Technology stack as remediation context

**User Story:** As a domain owner, I want remediation tailored to my detected technology stack when it is available, so that fixes reference the right config files or tools without treating the stack itself as a vulnerability.

#### Acceptance Criteria

1. WHERE a Tech_Stack with one or more detected technologies is supplied, THE Pass_1_Classifier SHALL include each detected technology, joined into a single comma-separated technology context line, in the LLM_Call system instruction.
2. WHERE a Tech_Stack with one or more detected technologies is supplied, THE Pass_1_Classifier SHALL present the technology context line as optional guidance that is applied to remediation steps only when confidently relevant, and SHALL NOT require its use.
3. IF the supplied Tech_Stack is absent, its detected list is absent, or its detected list contains zero technologies, THEN THE Pass_1_Classifier SHALL omit the technology context line from the LLM_Call system instruction entirely.
4. THE Pass_1_Classifier SHALL NOT represent the Tech_Stack as a vulnerability or finding, SHALL NOT assign it a severity, and SHALL NOT let it alter the deterministic rule-based severity or risk score of any finding.

### Requirement 6: Copy-pasteable record values for email-auth and CAA findings

**User Story:** As a domain owner, I want the exact DNS record value I can paste for SPF, DMARC, and CAA findings, so that I can apply the fix without translating prose into a record string.

#### Acceptance Criteria

1. WHERE a finding is of category email-authentication (SPF, DMARC) or CAA, THE Pass_1_Classifier SHALL instruct the model that the recommendation text must contain the exact, literal, copy-pasteable record value inline.
2. WHERE a finding carries a `suggestedSnippet`, THE Pass_1_Classifier SHALL pass that value to the model and instruct the model to use it verbatim in both the recommendation and the fixSnippet.
3. THE Pass_1_Classifier SHALL set `fixSnippet` to either a single paste-ready literal value containing no prose or multi-step instructions, or `null`.
4. IF the model returns a `fixSnippet` that is absent, a non-string, empty, whitespace-only, or equal to the literal text "null" (case-insensitive, after trimming), THEN THE Pass_1_Classifier SHALL set the `fixSnippet` to `null`.
5. WHEN the model returns a `fixSnippet` with surrounding whitespace around an otherwise usable value, THE Pass_1_Classifier SHALL retain the trimmed value.
6. IF an LLM-sourced result has no usable `fixSnippet`, THEN THE Pass_1_Classifier SHALL backfill the `fixSnippet` using `defaultFixSnippet`, which selects the finding's `suggestedSnippet` first, then a predefined per-finding-type literal default, then `null`.

### Requirement 7: Per-call timeout and retry bound

**User Story:** As a scan engine, I want a single slow or malformed classification to be time-bounded, so that one finding cannot stall the whole pass.

#### Acceptance Criteria

1. THE Pass_1_Classifier SHALL apply a Per_Call_Timeout of 9000 ms to each individual classification attempt (the initial attempt and the single retry).
2. WHEN a classification attempt does not complete within the Per_Call_Timeout, THE LLM_Call SHALL abort that in-flight attempt.
3. IF an LLM_Call attempt returns output that cannot be parsed as JSON, THEN THE LLM_Call SHALL retry exactly once with a stricter JSON-only instruction.
4. IF both the initial attempt and the single retry fail to parse or time out, THEN THE LLM_Call SHALL signal an error to `classifyOne`, bounding a single finding's classification at approximately 18000 ms (9000 ms × 2 attempts).
5. WHEN the LLM_Call signals an error, THE Pass_1_Classifier SHALL produce the deterministic rule-based Classification_Result for that finding and SHALL continue the pass.

### Requirement 8: Overall AI-phase budget

**User Story:** As a user awaiting a scan report, I want the report to always render within a fixed time, so that the scan never hangs on a slow language model.

#### Acceptance Criteria

1. THE scan handler SHALL bound the combined AI phase (Pass 1, Pass 2, and Pass 3 run concurrently) by an overall AI_Phase_Budget of 14000 ms, measured from the start of the AI phase.
2. WHEN the AI phase completes within the AI_Phase_Budget, THE scan handler SHALL emit the LLM report.
3. IF the AI phase does not complete within the AI_Phase_Budget, THEN THE scan handler SHALL emit the deterministic rule-based report as the scan result, and any later AI-phase output SHALL have no effect on the emitted report.
4. IF the AI pipeline fails before the AI_Phase_Budget elapses, THEN THE scan handler SHALL ship the deterministic rule-based report.

### Requirement 9: Graceful per-finding degradation

**User Story:** As a report consumer, I want a single failed classification to fall back to a rule-based result rather than failing the whole pass, so that the report is always complete.

#### Acceptance Criteria

1. IF an individual finding's classification fails due to the Per_Call_Timeout (9000 ms), a JSON parse failure, or any other exception, THEN THE Pass_1_Classifier SHALL return that finding's Deterministic_Classifier result with `_source` set to `"fallback"`.
2. WHEN one or more findings fall back to the Deterministic_Classifier, THE Pass_1_Classifier SHALL return exactly one Classification_Result per input finding (the returned result count equals the input finding count).
3. IF the `runPass1` invocation itself fails entirely, THEN THE top-level orchestration SHALL classify all findings through the Deterministic_Classifier with `_source` set to `"fallback"`.
4. WHEN a finding's Classification_Result is produced by fallback, THE Pass_1_Classifier SHALL source that result's severity, explanation, and recommendation from the Deterministic_Classifier and SHALL preserve the finding's `type`.

### Requirement 10: Per-finding completion callback

**User Story:** As the streaming scan path, I want to be notified as each finding finishes classifying, so that I can stream incremental progress to the UI.

#### Acceptance Criteria

1. WHERE a callback function is supplied as the `onEach` argument to `runPass1`, WHEN a finding completes classification, THE Pass_1_Classifier SHALL invoke the onEach_Callback exactly once for that finding, passing that finding's Classification_Result as the sole argument.
2. IF the onEach_Callback throws an error when invoked, THEN THE Pass_1_Classifier SHALL catch and suppress that error, still include the finding's Classification_Result in the returned results collection, and continue classifying the remaining findings.
3. WHERE the supplied `onEach` value is not a function (including the case where no `onEach` argument is supplied), THE Pass_1_Classifier SHALL complete classification of all findings and return their Classification_Results without invoking any callback.
4. WHEN `runPass1` is invoked with an empty findings collection, THE Pass_1_Classifier SHALL return an empty results collection without invoking the onEach_Callback.

### Requirement 11: Empty input handling

**User Story:** As a scan engine, I want an empty findings list handled trivially, so that no language model resources are consumed when there is nothing to classify.

#### Acceptance Criteria

1. WHEN `runPass1` is called with a findings list containing zero findings, THE Pass_1_Classifier SHALL return an empty list (a list containing zero classified-finding entries).
2. WHEN `runPass1` is called with a findings list containing zero findings, THE Pass_1_Classifier SHALL return without issuing any LLM_Call.
3. WHEN `runPass1` is called with a findings list containing zero findings, THE Pass_1_Classifier SHALL return without invoking the per-finding classification routine for any finding.

### Requirement 12: Result identity and provenance

**User Story:** As a downstream pass and report renderer, I want each result to preserve the finding's identity and record how it was classified, so that results can be correlated and their source audited.

#### Acceptance Criteria

1. THE Pass_1_Classifier SHALL set each Classification_Result's `id` to the originating finding's `id`, unchanged.
2. THE Pass_1_Classifier SHALL set each Classification_Result's `type` to the originating finding's `type`, unchanged.
3. WHEN a Classification_Result is produced from LLM prose, THE Pass_1_Classifier SHALL set its `_source` to `"llm"`.
4. WHEN a Classification_Result is produced by degradation to the Deterministic_Classifier, THE Pass_1_Classifier SHALL set its `_source` to `"fallback"`.
5. IF the model omits or provides an empty title, THEN THE Pass_1_Classifier SHALL set the Classification_Result's title to the finding's `label`.
6. IF the model omits or provides an empty explanation, THEN THE Pass_1_Classifier SHALL set the Classification_Result's explanation to the Deterministic_Classifier's explanation.
7. IF the model omits or provides an empty recommendation, THEN THE Pass_1_Classifier SHALL set the Classification_Result's recommendation to the Deterministic_Classifier's recommendation.
