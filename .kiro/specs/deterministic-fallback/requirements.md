# Requirements Document

## Introduction

This document formalizes an EXISTING system-wide guarantee in the domain security scanner:
a complete, well-formed report is always returned to the caller regardless of whether the
LLM (Claude) is available, fails, or times out. The guarantee is upheld not by a single
mechanism but by **four independent fallback layers** that compose because the security-bearing
fields of every report — `severity`, `overallRiskScore`, and `riskLevel` — are ALWAYS derived
deterministically from a fixed rule set, never from LLM output. The LLM only ever contributes
human-readable prose (titles, explanations, recommendations, summaries, narratives).

This spec documents behavior as it exists today across `netlify/functions/lib/findings.js`,
`netlify/functions/lib/analysis.js`, and `netlify/functions/scan.js`. It is a documentation /
formalization effort, not a change request. One known gap (a frontend check for a `_source`
value the backend never emits) is documented as-is under Requirement 7, explicitly as a recorded
fact rather than a defect to fix.

The four layers are:

1. **Pass 1 per-finding fallback** — a single finding's failed LLM classification degrades to its
   deterministic rule; sibling findings are unaffected.
2. **Pass 2 whole-report fallback** — a failed synthesis call returns a deterministic report built
   from Pass 1's already-classified findings (which may still carry LLM prose if Pass 1 succeeded).
3. **Pass 3 narrative omission** — a failed narrative call yields no narrative; the optional
   `attackScenario` / `ifUnaddressed` fields are simply absent, with no substitute content.
4. **Top-level budget race** — the entire AI pipeline races a fixed 14-second wall-clock budget;
   on timeout or pipeline failure a deterministic report is re-derived from scratch, discarding
   any in-flight LLM work.

A subtle but important property: layers 2 and 4 both tag their output `_source: "fallback"`, yet
they produce genuinely different reports for the same findings — layer 2 reuses Pass 1's LLM prose,
while layer 4 discards all LLM work and re-derives everything deterministically.

## Glossary

- **Scanner**: The overall serverless scan handler and its analysis library; the system under
  documentation. Implemented across `scan.js`, `analysis.js`, and `findings.js`.
- **Finding**: A single discrete security issue derived from raw scan data (e.g. "Missing SPF
  record"), identified by a stable `id` and `type`.
- **Classification**: The set of fields attached to a finding — `title`, `severity`, `explanation`,
  `recommendation`, `fixSnippet` — plus a `_source` tag.
- **Severity**: One of `critical`, `high`, `medium`, `low` (with `info` reserved for informational,
  non-scored items). ALWAYS assigned deterministically, never by the LLM.
- **Deterministic_Rule**: The fixed mapping from a finding to its severity and default prose,
  implemented by `fallbackClassify` and its backing tables (`SEVERITY_MAP`, `FALLBACK_TEXT`,
  `EXPOSED_FILE_INFO`) in `findings.js`.
- **Pass_1**: The analysis stage that classifies each finding independently and concurrently, with
  one isolated LLM call per finding (`runPass1` / `classifyOne` in `analysis.js`).
- **Pass_2**: The analysis stage that synthesizes an executive narrative (summary, top priority)
  over the classified findings (`runPass2` in `analysis.js`).
- **Pass_3**: The analysis stage that produces the optional attacker-narrative fields
  `attackScenario` and `ifUnaddressed` (`runPass3` in `analysis.js`).
- **Overall_Risk_Score**: An integer 0–100 computed deterministically from finding severities by
  `computeFallbackScore` in `analysis.js`.
- **Risk_Level**: One of `Low`, `Medium`, `High`, `Critical`, derived deterministically from the
  Overall_Risk_Score by `scoreToLevel` in `analysis.js`.
- **Source_Tag**: The `_source` field on a report or finding, one of `"llm"`, `"fallback"`,
  `"none"`, or `"deterministic"`, indicating how that content was produced.
- **Analysis_Budget**: The fixed wall-clock allowance for the entire AI pipeline, defined by
  `ANALYSIS_BUDGET_MS = 14000` (14 seconds) in `scan.js`.
- **AI_Pipeline**: The composed Pass 1 → (Pass 2 ∥ Pass 3) sequence executed as a single awaitable
  inside the streaming handler in `scan.js`.
- **Deterministic_Report**: The report produced by `deterministicReport()` in `scan.js`, which
  re-derives every classification from scratch using the Deterministic_Rule, ignoring any in-flight
  AI_Pipeline work.
- **Fallback_Report**: The report produced by `buildFallbackReport` in `analysis.js` from a given
  set of already-sorted findings.
- **Result_Event**: The streamed `{ type: "result", scan, report }` event that delivers the final
  report to the client.
- **Stream_Error_Event**: The streamed `{ type: "error", message }` event emitted on a fatal
  handler error or DNS-resolution failure.

## Requirements

### Requirement 1: Deterministic severity, score, and risk level

**User Story:** As a domain owner, I want the severity badges, risk score, and risk level to be
identical for identical findings on every scan, so that I can trust the numbers regardless of
whether AI prose was available.

#### Acceptance Criteria

1. THE Scanner SHALL assign each Finding's Severity from the Deterministic_Rule, independent of any LLM output, and the assigned value SHALL be one of `critical`, `high`, `medium`, `low`, or `info`.
2. WHEN Pass_1 receives a successful LLM response for a Finding, THE Scanner SHALL use the LLM text for `title`, `explanation`, and `recommendation` while still setting Severity from the Deterministic_Rule.
3. THE Scanner SHALL compute the Overall_Risk_Score from the set of finding Severities as a clamped integer in the inclusive range 0 to 100, using the fixed per-finding weights critical=40, high=22, medium=10, low=3, where `info` and any unrecognized Severity contribute weight 0.
4. THE Scanner SHALL derive the Risk_Level from the Overall_Risk_Score using mutually exclusive and exhaustive thresholds across the full 0–100 range: Critical at score 70 or above, High at 45–69, Medium at 20–44, and Low at 0–19.
5. WHERE two scans produce an identical multiset of Findings — matched on `(id, type, severity)` and independent of finding order — THE Scanner SHALL produce a byte-identical Overall_Risk_Score and an identical Risk_Level string across those scans.
6. WHEN a Severity value is compared or ranked, THE Scanner SHALL normalize the value to lowercase before lookup, and any value that remains unrecognized after normalization SHALL be treated as weight 0.

### Requirement 2: Pass 1 per-finding fallback

**User Story:** As a domain owner, I want one finding's AI failure to not affect the others, so that
a single bad LLM call still leaves me with a complete set of classified findings.

#### Acceptance Criteria

1. IF the LLM call for a single Finding fails, returns an unparseable response, or exceeds its per-attempt timeout of 9000 milliseconds across its one allowed retry (roughly 18000 milliseconds maximum), THEN THE Scanner SHALL classify that Finding using the Deterministic_Rule and tag it `_source: "fallback"`.
2. WHEN one Finding falls back during Pass_1, THE Scanner SHALL leave the classification, prose, Severity, and `_source` tag of every other Finding unaffected.
3. WHEN a Finding is classified successfully by the LLM during Pass_1, THE Scanner SHALL tag that Finding `_source: "llm"`.
4. WHEN the LLM response for a Finding omits or returns an empty value for `title`, `explanation`, `recommendation`, or `fixSnippet`, THE Scanner SHALL substitute the Deterministic_Rule value for each such field independently while retaining any field the LLM did supply.
5. THE Scanner SHALL initiate the classification of all Findings in Pass_1 concurrently and await their collective completion before proceeding.
6. THE Deterministic_Rule SHALL return a classification for every Finding, assigning Severity `low` and generic review prose for any Finding identifier or type not present in its severity tables.
7. THE Scanner SHALL set each Finding's Severity from the Deterministic_Rule even when the Pass_1 LLM call for that Finding succeeds, so that the LLM contributes prose only and never alters Severity.

### Requirement 3: Pass 2 whole-report fallback

**User Story:** As a domain owner, I want a complete report even when the executive-synthesis AI
call fails, so that I still receive a scored, ordered set of findings with a usable summary.

#### Acceptance Criteria

1. IF the Pass_2 LLM synthesis call throws an error or does not return within the 10-second Pass_2 timeout, THEN THE Scanner SHALL return a Fallback_Report tagged `_source: "fallback"` that is built from the Pass_1 classified findings and contains the deterministic Overall_Risk_Score, Risk_Level, severity-ordered findings, a synthesized summary, and a topPriority.
2. WHEN the Pass_2 call succeeds, THE Scanner SHALL return a report tagged `_source: "llm"` that carries the LLM `summary` and `topPriority` together with the deterministic Overall_Risk_Score, Risk_Level, and severity-ordered findings.
3. WHEN the Pass_2 LLM response omits the `summary` or returns a `summary` that is empty or whitespace-only, THE Scanner SHALL substitute a deterministically synthesized summary derived from the count of findings at each Severity level.
4. WHEN the Pass_2 LLM response omits the `topPriority` or returns a `topPriority` that is empty or whitespace-only, THE Scanner SHALL substitute the recommendation of the first finding in the severity-ordered findings list (the highest-severity finding).
5. WHILE the set of classified findings is empty, THE Scanner SHALL return a report tagged `_source: "none"` with Overall_Risk_Score 5 on the 0-to-100 scale, Risk_Level `Low`, an empty findings list, a synthesized summary, and a topPriority, without making any Pass_2 LLM call.
6. THE Scanner SHALL order findings in the Pass_2 output by Severity rank from highest to lowest, where the rank order is Critical (highest), then High, then Medium, then Low (lowest).
7. WHEN the Pass_2 fallback path reuses Pass_1 findings, THE Scanner SHALL preserve the LLM-authored title, explanation, recommendation, and fixSnippet that those findings acquired during a successful Pass_1.

### Requirement 4: Pass 3 narrative omission

**User Story:** As a domain owner, I want the report to render even when the optional attacker
narrative is unavailable, so that a Pass 3 failure never blocks or degrades the core report.

#### Acceptance Criteria

1. IF the Pass_3 LLM call throws an error, returns an unparseable response, or exceeds its 10-second per-call timeout across its one allowed retry, THEN THE Scanner SHALL leave the `attackScenario` and `ifUnaddressed` fields absent from the report while leaving all other report fields unchanged.
2. WHEN the Pass_3 call returns empty or whitespace-only values for both `attackScenario` and `ifUnaddressed`, THE Scanner SHALL treat the narrative as absent.
3. WHEN the Pass_3 call returns a non-empty value for exactly one of `attackScenario` or `ifUnaddressed`, THE Scanner SHALL treat the narrative as present and attach both returned values.
4. WHEN the narrative is absent, THE Scanner SHALL NOT substitute any deterministic, default, or placeholder content, and the `attackScenario` and `ifUnaddressed` fields SHALL NOT appear in the report.
5. THE Scanner SHALL run Pass_2 and Pass_3 concurrently against a deterministic base report computed from the Pass_1 findings, such that identical Pass_1 findings yield an identical base report regardless of Pass_2 and Pass_3 outcomes.
6. WHEN Pass_3 fails while Pass_2 succeeds or falls back, THE Scanner SHALL return the complete Pass_2 report with only the narrative fields omitted, so that a Pass_3 failure neither blocks nor degrades the core report.

### Requirement 5: Top-level analysis budget race

**User Story:** As a domain owner, I want a guaranteed report within a bounded time, so that a slow
or stuck LLM pipeline never causes the scan to hang.

#### Acceptance Criteria

1. THE Scanner SHALL race the AI_Pipeline against a single per-scan Analysis_Budget timer of exactly 14000 milliseconds, started when the AI_Pipeline begins.
2. IF the AI_Pipeline does not resolve before the Analysis_Budget elapses, THEN THE Scanner SHALL send the Result_Event carrying the Deterministic_Report.
3. IF the AI_Pipeline rejects before the Analysis_Budget elapses, THEN THE Scanner SHALL send the Result_Event carrying the Deterministic_Report.
4. WHEN the Scanner sends the Deterministic_Report, THE Scanner SHALL re-derive every finding classification from scratch using only Deterministic_Rule output, incorporating no in-flight or partial AI_Pipeline pass output.
5. THE Scanner SHALL tag the Deterministic_Report `_source: "fallback"`.
6. WHEN the AI_Pipeline resolves before the Analysis_Budget elapses, THE Scanner SHALL send the Result_Event carrying the AI_Pipeline report and SHALL cancel the Analysis_Budget timer.
7. WHEN the Analysis_Budget timer fires after the Result_Event has already been sent, THE Scanner SHALL discard any further pipeline output and SHALL send no additional Result_Event or error event.
8. THE Scanner SHALL send exactly one Result_Event per scan, carrying either the AI_Pipeline report or the Deterministic_Report but never both.
9. IF an unhandled error occurs in the top-level handler, THEN THE Scanner SHALL send a Stream_Error_Event and close the stream.

### Requirement 6: Failure handling is latency-driven, not error-typed

**User Story:** As a maintainer, I want to understand that the fallback path is selected purely by
timing rather than by error category, so that I can reason about which layer catches a given failure.

#### Acceptance Criteria

1. THE Scanner SHALL select which fallback layer catches a failure based solely on whether the AI_Pipeline resolves or rejects relative to the Analysis_Budget, and SHALL NOT branch on the LLM error type (for example HTTP 401, HTTP 429, or timeout).
2. WHEN every LLM call rejects before the Analysis_Budget of 14000 milliseconds elapses (for example a missing API key causing instant failures), THE Scanner SHALL resolve the AI_Pipeline with the Pass_2 Fallback_Report and SHALL NOT produce the top-level Deterministic_Report.
3. WHEN the AI_Pipeline does not resolve before the Analysis_Budget of 14000 milliseconds elapses, THE Scanner SHALL ship the top-level Deterministic_Report.
4. WHEN the same Findings are processed, THE Scanner SHALL produce a Pass_2 Fallback_Report that retains any Pass_1 LLM-authored prose and a top-level Deterministic_Report that re-derives all prose from the Deterministic_Rule, while both reports share an identical Severity per Finding, Overall_Risk_Score, and Risk_Level.
5. THE Scanner SHALL tag both the Pass_2 Fallback_Report and the top-level Deterministic_Report `_source: "fallback"`.

### Requirement 7: Known gap — unreachable frontend "error" source check

**User Story:** As a maintainer, I want the documented behavior of the frontend fallback banner to
match what the backend actually emits, so that the discrepancy is recorded as a known gap rather
than mistaken for a working path.

#### Acceptance Criteria

1. THE Scanner SHALL emit a report Source_Tag that is exactly one of `"llm"`, `"fallback"`, `"none"`, or `"deterministic"`, and SHALL NOT emit a report Source_Tag of `"error"` on any backend path.
2. WHEN a fatal handler error or DNS-resolution failure occurs, THE Scanner SHALL emit a Stream_Error_Event and SHALL NOT emit a Result_Event carrying a report.
3. WHILE the report Source_Tag is `"fallback"`, THE frontend SHALL display the fallback banner.
4. WHERE the report Source_Tag is `"error"`, THE frontend SHALL display the fallback banner, and this branch SHALL be unreachable because no backend path emits the `"error"` Source_Tag (the backend instead emits a Stream_Error_Event).
5. THE Scanner documentation SHALL record the frontend `"error"` Source_Tag check as dead defensive code that is retained as-is and is out of scope for change in this spec.
