# Requirements Document

## Introduction

Analyst Synthesis (Pass 2) is the executive-synthesis stage of the multi-pass AI analysis pipeline that runs after a passive domain scan. It takes the per-finding classifications produced by Pass 1 and produces a single executive narrative for a non-technical business owner: a plain-English `summary` and a one-sentence `topPriority`.

The defining characteristic of this stage is the strict separation between deterministic computation and LLM-generated prose. The overall risk score and risk level are computed deterministically from fixed per-severity weights BEFORE any model call, and are treated as authoritative and read-only. The LLM contributes prose only; it is explicitly forbidden from producing its own score, and any score it returns is ignored. The stage makes at most one LLM call regardless of how many findings exist, degrades gracefully to a deterministic report on any failure, and skips the model entirely when there are no findings.

This document captures the existing, working behavior of `runPass2` in `netlify/functions/lib/analysis.js` and its orchestration in `netlify/functions/scan.js`.

## Glossary

- **Analyst_Synthesis**: The Pass 2 stage implemented by the `runPass2` function. Consumes classified findings and produces an executive report fragment (`summary`, `topPriority`, plus the deterministic score/level/findings).
- **Classified_Finding**: A single finding produced by Pass 1, carrying at minimum a `title`, a deterministic `severity` (one of `critical`, `high`, `medium`, `low`, or `info`), an `explanation`, and a `recommendation`.
- **Pipeline_Orchestrator**: The `aiPipeline` logic in `scan.js` that sequences Pass 1, then runs Pass 2 and Pass 3 concurrently, and assembles the final report.
- **Pass_1**: The classification stage that produces Classified_Findings, run before Analyst_Synthesis.
- **Pass_3**: The exploit-narrative stage (`runPass3`) that runs concurrently with Analyst_Synthesis and operates on a deterministic base report derived from Pass 1.
- **LLM_Client**: The `callLLMJson` helper that performs one model request (with a single internal retry on parse failure) and returns parsed JSON, or throws on failure.
- **Severity_Weight**: The fixed numeric weight assigned per severity for scoring: critical = 40, high = 22, medium = 10, low = 3.
- **Overall_Risk_Score**: The integer risk score computed deterministically by summing Severity_Weights across findings and capping the total at 100.
- **Risk_Level**: The band derived deterministically from the Overall_Risk_Score: `Critical`, `High`, `Medium`, or `Low`.
- **Base_Report**: The deterministic report produced by `buildFallbackReport`, containing the deterministic score, level, templated summary, sorted findings, and a top recommendation.
- **Source_Tag**: The `_source` field on the returned report indicating its provenance: `"llm"`, `"fallback"`, or `"none"`.
- **Summary**: A 2-3 sentence plain-English executive narrative string in the report.
- **Top_Priority**: A one-sentence string naming the single most important item to fix first.

## Requirements

### Requirement 1: Single LLM call across all findings

**User Story:** As a system operator, I want analyst synthesis to make at most one model call for the entire finding set, so that synthesis cost and latency stay bounded regardless of how many findings a scan produces.

#### Acceptance Criteria

1. WHEN Analyst_Synthesis is invoked with one or more Classified_Findings, THE Analyst_Synthesis SHALL make exactly one invocation of the LLM_Client, passing the complete set of Classified_Findings in that single invocation.
2. WHEN Analyst_Synthesis is invoked with a count of Classified_Findings ranging from 1 to the maximum the scan produces, THE Analyst_Synthesis SHALL make exactly one invocation of the LLM_Client, such that the invocation count is independent of the number of Classified_Findings and never increases per finding.
3. WHILE a single LLM_Client invocation performs its one internal retry on parse failure, THE Analyst_Synthesis SHALL count that invocation as exactly one LLM_Client call and SHALL NOT initiate an additional LLM_Client invocation.
4. WHEN Analyst_Synthesis is invoked with zero Classified_Findings, THE Analyst_Synthesis SHALL make zero invocations of the LLM_Client.

### Requirement 2: Deterministic risk score computed before the LLM call

**User Story:** As a report consumer, I want the overall risk score computed by a fixed formula before any model call, so that identical findings always yield an identical score across repeat scans.

#### Acceptance Criteria

1. WHEN Analyst_Synthesis computes the Overall_Risk_Score, THE Analyst_Synthesis SHALL produce a non-negative integer equal to the sum of the Severity_Weight of each finding, applying the fixed weights critical = 40, high = 22, medium = 10, and low = 3, where each finding's severity value is matched case-insensitively to exactly one weight.
2. WHEN the summed Severity_Weights exceed 100, THE Analyst_Synthesis SHALL cap the Overall_Risk_Score at the integer value 100, and in all cases the Overall_Risk_Score SHALL fall within the inclusive range 0 to 100.
3. THE Analyst_Synthesis SHALL compute the Overall_Risk_Score before initiating the LLM_Client call.
4. WHERE a finding carries a severity that is `info`, is absent, is null, or is any value other than critical, high, medium, or low (compared case-insensitively), THE Analyst_Synthesis SHALL contribute a Severity_Weight of 0 for that finding to the Overall_Risk_Score.
5. WHEN Analyst_Synthesis is invoked on repeated runs with Classified_Findings having the same multiset of severity values, THE Analyst_Synthesis SHALL produce the identical Overall_Risk_Score independent of the order of findings and independent of any LLM_Client response.

### Requirement 3: Deterministic risk level banding

**User Story:** As a report consumer, I want the risk level derived from the score by fixed thresholds, so that the level is consistent and predictable.

#### Acceptance Criteria

1. IF the Overall_Risk_Score is greater than or equal to 70 and less than or equal to 100, THEN THE Analyst_Synthesis SHALL set the Risk_Level to `Critical`.
2. IF the Overall_Risk_Score is greater than or equal to 45 and less than 70, THEN THE Analyst_Synthesis SHALL set the Risk_Level to `High`.
3. IF the Overall_Risk_Score is greater than or equal to 20 and less than 45, THEN THE Analyst_Synthesis SHALL set the Risk_Level to `Medium`.
4. IF the Overall_Risk_Score is greater than or equal to 0 and less than 20, THEN THE Analyst_Synthesis SHALL set the Risk_Level to `Low`.
5. THE Analyst_Synthesis SHALL derive the Risk_Level from the deterministically computed Overall_Risk_Score before initiating the LLM_Client call.
6. WHEN Analyst_Synthesis sets the Risk_Level, THE Analyst_Synthesis SHALL set it to exactly one of `Critical`, `High`, `Medium`, or `Low`.
7. WHEN Analyst_Synthesis derives the Risk_Level from identical Overall_Risk_Score values on repeated runs, THE Analyst_Synthesis SHALL produce the identical Risk_Level.

### Requirement 4: Risk score and level passed as authoritative read-only context

**User Story:** As a security architect, I want the deterministic score and level passed into the prompt as authoritative context, so that the model writes prose consistent with the score it must not change.

#### Acceptance Criteria

1. WHEN Analyst_Synthesis constructs the LLM_Client request, THE Analyst_Synthesis SHALL include in that request the computed Overall_Risk_Score (an integer 0 to 100) and the Risk_Level (one of `Critical`, `High`, `Medium`, or `Low`).
2. THE Analyst_Synthesis SHALL instruct the LLM_Client that the provided Risk_Level is authoritative and that the model is to write prose consistent with that Risk_Level.
3. THE Analyst_Synthesis SHALL instruct the LLM_Client that the model must not output its own score or risk level.
4. THE Analyst_Synthesis SHALL request from the LLM_Client a JSON object whose only fields are a `summary` string and a `topPriority` string, with no additional fields.

### Requirement 5: Engine always uses the deterministic score regardless of model output

**User Story:** As a report consumer, I want the engine to always use its deterministic score and level, so that a model that disregards instructions cannot alter the reported risk.

#### Acceptance Criteria

1. WHEN the LLM_Client returns a successful response, THE Analyst_Synthesis SHALL set the report Overall_Risk_Score equal to the Overall_Risk_Score that was computed before the LLM_Client call per Requirement 2.
2. WHEN the LLM_Client returns a successful response, THE Analyst_Synthesis SHALL set the report Risk_Level equal to the Risk_Level that was derived before the LLM_Client call per Requirement 3.
3. IF the LLM_Client response includes a score field or a risk-level field, THEN THE Analyst_Synthesis SHALL exclude those returned values from the report and retain the deterministic Overall_Risk_Score and Risk_Level.
4. WHEN Analyst_Synthesis returns a report for a given set of Classified_Findings, THE Analyst_Synthesis SHALL produce the identical Overall_Risk_Score and Risk_Level regardless of whether the LLM_Client response omits a score and risk level, includes values equal to the deterministic values, or includes values that differ from the deterministic values.

### Requirement 6: Successful synthesis output and prose fallbacks

**User Story:** As a report consumer, I want a usable summary and top priority even when the model omits one of them, so that the report is always complete.

#### Acceptance Criteria

1. WHEN the LLM_Client returns a successful response containing a `summary` field that is a string of length one or more characters, THE Analyst_Synthesis SHALL use that `summary` string verbatim as the report Summary.
2. IF the LLM_Client response omits the `summary` field or provides a `summary` that is not a string of length one or more characters, THEN THE Analyst_Synthesis SHALL set the report Summary to a templated summary that names the scanned domain, states the total count of findings, and lists the count of findings at each of the critical, high, medium, and low severities.
3. WHEN the LLM_Client returns a successful response containing a `topPriority` field that is a string of length one or more characters, THE Analyst_Synthesis SHALL use that `topPriority` string verbatim as the report Top_Priority.
4. IF the LLM_Client response omits the `topPriority` field or provides a `topPriority` that is not a string of length one or more characters, THEN THE Analyst_Synthesis SHALL set the report Top_Priority to the `recommendation` of the highest-severity finding, selected as the first finding after the report findings are ordered by severity from highest to lowest.
5. WHEN Analyst_Synthesis returns a report derived from a successful LLM_Client response, THE Analyst_Synthesis SHALL set the Source_Tag to `"llm"`.
6. WHEN Analyst_Synthesis returns a report, THE Analyst_Synthesis SHALL order the report findings by severity from highest to lowest using the fixed ranking critical (highest), then high, then medium, then low, then any other severity value (lowest), and SHALL preserve the original relative order of any findings that share the same severity rank.

### Requirement 7: Deterministic fallback on synthesis failure

**User Story:** As a report consumer, I want a complete deterministic report when the model call fails, so that the scan always produces a result.

#### Acceptance Criteria

1. IF the LLM_Client call does not return a response within 10 seconds, THEN THE Analyst_Synthesis SHALL return a deterministic Base_Report.
2. IF the LLM_Client call throws an error, THEN THE Analyst_Synthesis SHALL return a deterministic Base_Report.
3. IF the LLM_Client response cannot be parsed as JSON after the LLM_Client's single internal retry has also failed to parse, THEN THE Analyst_Synthesis SHALL return a deterministic Base_Report.
4. WHEN Analyst_Synthesis returns a deterministic Base_Report after a failed LLM_Client call, THE Analyst_Synthesis SHALL set the Source_Tag to `"fallback"`.
5. WHEN Analyst_Synthesis returns a deterministic Base_Report after a failed LLM_Client call, THE Analyst_Synthesis SHALL set the Overall_Risk_Score and Risk_Level to the same deterministic values that were computed before the call.
6. WHEN Analyst_Synthesis returns a deterministic Base_Report, THE Analyst_Synthesis SHALL set the report Top_Priority to the recommendation of the highest-severity finding, selecting the first finding in the order received from Pass_1 when multiple findings share the highest severity.
7. WHEN Analyst_Synthesis returns a deterministic Base_Report, THE Analyst_Synthesis SHALL set the report Summary to a templated summary derived from the scanned domain and the finding severity counts.

### Requirement 8: Zero-findings handling

**User Story:** As a report consumer, I want a calm, clean report when no exposures are found, so that a healthy domain reads as reassuring without an unnecessary model call.

#### Acceptance Criteria

1. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL skip the LLM_Client call.
2. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the Overall_Risk_Score to the fixed integer value 5.
3. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the Risk_Level to `Low`.
4. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the report Summary to a templated message that contains the scanned domain identifier verbatim and conveys that no notable exposures were found.
5. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the report findings to a list containing exactly 0 elements.
6. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the Source_Tag to `"none"`.
7. WHEN Analyst_Synthesis is invoked with a finding set whose count is exactly 0, THE Analyst_Synthesis SHALL set the report Top_Priority to the value the implementation assigns for the no-findings path.

### Requirement 9: Concurrent independence of Pass 2 and Pass 3

**User Story:** As a system operator, I want analyst synthesis and the exploit-narrative stage to run concurrently and independently, so that one stage's failure never affects the other and a model round-trip is removed from the critical path.

#### Acceptance Criteria

1. WHEN Pass_1 completes, THE Pipeline_Orchestrator SHALL start Analyst_Synthesis and Pass_3 concurrently.
2. THE Pipeline_Orchestrator SHALL provide Pass_3 with a deterministic Base_Report derived solely from Pass_1 output, with findings sorted by severity from highest to lowest, and excluding any field originating from Analyst_Synthesis output.
3. IF Analyst_Synthesis fails by throwing an error, exceeding its 10-second timeout, or otherwise producing no usable result, THEN THE Pipeline_Orchestrator SHALL allow Pass_3 to complete and include its result in the final report independently.
4. IF Pass_3 fails by throwing an error or otherwise producing no usable result, THEN THE Pipeline_Orchestrator SHALL allow Analyst_Synthesis to complete and include its result in the final report independently, omitting the exploit-narrative fields.
5. IF Analyst_Synthesis fails within the concurrent execution, THEN THE Pipeline_Orchestrator SHALL substitute the deterministic Base_Report for the synthesis result, where that Base_Report is identical to the one provided to Pass_3 and preserves the deterministic Overall_Risk_Score, Risk_Level, and findings.
6. IF both Analyst_Synthesis and Pass_3 fail within the concurrent execution, THEN THE Pipeline_Orchestrator SHALL produce the final report from the deterministic Base_Report and omit the exploit-narrative fields.
