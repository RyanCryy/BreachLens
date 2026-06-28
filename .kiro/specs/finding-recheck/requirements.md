# Requirements Document

## Introduction

This feature lets a user re-verify whether a single, previously reported finding (for example a missing SPF, DMARC, or CAA record, a missing security header, an expired TLS certificate, or an exposed file) has been fixed — without re-running the full BreachLens scan. A user can trigger a re-check two ways:

1. By clicking a **Re-check** button on an individual finding card in the results view.
2. By asking in natural language in the existing chat (for example "did my SPF get fixed?" or "re-check DMARC").

A re-check runs only the specific passive check(s) relevant to that one finding, then reports whether the issue is now **resolved**, **still present**, or **indeterminate** (could not be confirmed). The results view updates the corresponding finding card to reflect the outcome. Because some findings are derived from non-deterministic context (narrative or AI-only items), the feature explicitly distinguishes findings that can be re-checked from those that cannot.

This is a hackathon project, so scope is kept pragmatic: re-checks reuse the existing passive check primitives in `lib/checks.js`, remain client-state-only (no server-side persistence), and introduce a single new backend endpoint plus a controlled new capability in the chat path.

## Glossary

- **Recheck_Service**: The backend Netlify Function that accepts a request to re-verify one finding and returns its current resolution status. Exposed at `POST /api/recheck`.
- **Recheck_Router**: The backend component that maps a finding identifier to the specific passive check function(s) required to re-verify it and to the predicate that decides resolution.
- **Recheckable_Finding**: A finding whose identifier maps to one or more passive checks in `lib/checks.js` and to a deterministic resolution predicate.
- **Non_Recheckable_Finding**: A finding that has no deterministic passive check mapping (for example AI-narrative-only items or any finding identifier the Recheck_Router does not recognize).
- **Finding_Id**: The stable identifier carried by each finding (for example `spf-missing`, `dmarc-missing`, `caa-missing`, `hdr-hsts`, `ssl-expired`, `cookie-secure`, `mixed-content`, `robots-sensitive`, dynamic `subdomain-{name}`, dynamic `exposed-file-{path}`).
- **Recheck_Status**: The outcome of a re-check, one of exactly three values: `resolved`, `unresolved`, `indeterminate`.
  - **resolved**: The condition that originally produced the finding is no longer present.
  - **unresolved**: The condition that originally produced the finding is still present.
  - **indeterminate**: The relevant check could not produce a confident answer (for example a network timeout, an unreachable host, or a resolver failure).
- **Finding_Card**: The UI element in the results view that renders one finding, including its severity badge, title, explanation, recommendation, and optional fix snippet.
- **Chat_Service**: The backend Netlify Function at `POST /api/chat` that answers follow-up questions about the report.
- **Recheck_Intent**: A user chat message whose meaning is a request to re-verify a specific existing finding.
- **Frontend_App**: The client-side application in `public/app.js` that renders results and the chat.

## Requirements

### Requirement 1: Re-check a single finding without re-running the full scan

**User Story:** As a domain owner, I want to re-check one specific finding, so that I can confirm a fix without waiting for a complete re-scan.

#### Acceptance Criteria

1. WHEN the Recheck_Service receives a valid request, where a valid request contains a non-empty domain and a Finding_Id that maps to a Recheckable_Finding, THE Recheck_Service SHALL execute only the passive check(s) mapped to that Finding_Id and SHALL NOT execute the full scan pipeline.
2. WHEN the Recheck_Service completes a re-check, THE Recheck_Service SHALL return a Recheck_Status of exactly one of `resolved`, `unresolved`, or `indeterminate`.
3. THE Recheck_Service SHALL return the Finding_Id that was re-checked together with the Recheck_Status.
4. WHEN the Recheck_Service returns a result, THE Recheck_Service SHALL include a human-readable message, not exceeding 500 characters, describing the outcome.
5. THE Recheck_Service SHALL accept requests only via HTTP POST.
6. WHEN the Recheck_Service receives a request using any HTTP method other than POST or OPTIONS, THE Recheck_Service SHALL return HTTP status 405.
7. IF the Recheck_Service receives a request containing a Finding_Id that maps to a Non_Recheckable_Finding, THEN THE Recheck_Service SHALL return HTTP status 200 with a Recheck_Status of `indeterminate` and a message indicating that the finding cannot be automatically re-checked, and SHALL NOT execute any passive check.
8. IF a re-check exceeds 30 seconds of total execution time, THEN THE Recheck_Service SHALL terminate the re-check and return a Recheck_Status of `indeterminate` with a message indicating that the re-check timed out.

### Requirement 2: Validate re-check requests

**User Story:** As a developer, I want re-check requests validated, so that malformed input fails clearly instead of producing misleading results.

#### Acceptance Criteria

1. IF a re-check request body is not valid JSON, THEN THE Recheck_Service SHALL return HTTP status 400 with an error message indicating the request body could not be parsed as JSON, AND SHALL NOT execute any passive check.
2. IF a re-check request omits the domain, supplies a domain that is not a non-empty string, or supplies a domain that fails the existing domain validation rules (isValidDomain) after normalization, THEN THE Recheck_Service SHALL return HTTP status 400 with an error message indicating the domain is missing or invalid, AND SHALL NOT execute any passive check.
3. IF a re-check request omits the Finding_Id, supplies a Finding_Id that is not a non-empty string, or supplies a Finding_Id longer than 256 characters, THEN THE Recheck_Service SHALL return HTTP status 400 with an error message indicating the Finding_Id is missing, empty, or exceeds the 256-character limit, AND SHALL NOT execute any passive check.
4. WHEN the Recheck_Service receives a domain value, THE Recheck_Service SHALL normalize the domain (normalizeDomain) using the same normalization rules as the scan endpoint before applying domain validation (isValidDomain) and before running any check.
5. WHEN the Recheck_Service processes a re-check request, THE Recheck_Service SHALL parse the request body, then validate the domain, then validate the Finding_Id, returning on the first validation failure encountered.
6. IF a re-check request supplies a Finding_Id that the Recheck_Router does not recognize as a Recheckable_Finding, THEN THE Recheck_Service SHALL return HTTP status 200 with a Recheck_Status of `indeterminate` and a message stating the finding cannot be automatically re-checked.

### Requirement 3: Map findings to their relevant checks

**User Story:** As a developer, I want each finding mapped to the correct passive check, so that a re-check verifies the right condition.

#### Acceptance Criteria

1. WHERE the Finding_Id is `spf-missing`, THE Recheck_Router SHALL re-verify the SPF condition using the DNS check, and SHALL report `resolved` when an SPF record is present and `unresolved` when no SPF record is present.
2. WHERE the Finding_Id is `dmarc-missing`, THE Recheck_Router SHALL re-verify the DMARC condition using the DNS check, and SHALL report `resolved` when a DMARC record is present and `unresolved` when no DMARC record is present.
3. WHERE the Finding_Id is `caa-missing`, THE Recheck_Router SHALL re-verify the CAA condition using the DNS check, and SHALL report `resolved` when CAA status is `present`, `unresolved` when CAA status is `missing`, and `indeterminate` when CAA status is `unknown`.
4. WHERE the Finding_Id is one of `hdr-hsts`, `hdr-csp`, `hdr-xfo`, or `hdr-xcto`, THE Recheck_Router SHALL re-verify the corresponding security header using the headers check, and SHALL report `resolved` when the header is present and `unresolved` when the header is absent.
5. WHERE the Finding_Id begins with `ssl-`, THE Recheck_Router SHALL re-verify the TLS certificate using the SSL check, and SHALL report `resolved` when a certificate is readable and expires in more than 30 days, `unresolved` when a certificate is readable but expired or expiring within 30 days, and `indeterminate` when the certificate cannot be read.
6. WHERE the Finding_Id is one of `cookie-secure`, `cookie-httponly`, or `cookie-samesite`, THE Recheck_Router SHALL re-verify cookie attributes using the headers check followed by cookie analysis, and SHALL report `resolved` when no cookie is missing the corresponding attribute and `unresolved` when at least one cookie is missing the corresponding attribute.
7. WHERE the Finding_Id is `mixed-content`, THE Recheck_Router SHALL re-verify mixed content using the headers check followed by mixed-content analysis, and SHALL report `resolved` when zero insecure references are found on an HTTPS page and `unresolved` when at least one insecure reference is found.
8. WHERE the Finding_Id is `robots-sensitive`, THE Recheck_Router SHALL re-verify sensitive robots.txt disclosures using the robots/sitemap check, and SHALL report `resolved` when no sensitive disallow entries are present and `unresolved` when at least one sensitive disallow entry is present.
9. WHERE the Finding_Id begins with `exposed-file-`, THE Recheck_Router SHALL re-verify only the single file path encoded in the Finding_Id using a status-only request, and SHALL report `resolved` when the path no longer returns HTTP 200 and `unresolved` when the path still returns HTTP 200.
10. WHERE the Finding_Id begins with `subdomain-`, THE Recheck_Router SHALL treat the finding as a Non_Recheckable_Finding and SHALL report `indeterminate` with a message explaining that subdomain exposure cannot be confirmed resolved by a single passive re-check.
11. WHEN the Recheck_Router re-verifies an exposed-file finding, THE Recheck_Router SHALL inspect only the HTTP status code and SHALL NOT read, store, or return the response body.
12. IF the Finding_Id does not match any of the mapping rules in criteria 1 through 10, THEN THE Recheck_Router SHALL treat the finding as a Non_Recheckable_Finding, SHALL report `indeterminate`, and SHALL NOT invoke any check.
13. IF a network error, connection failure, or request timeout exceeding 10 seconds occurs during a DNS, SSL, headers, robots/sitemap, or status-only request, THEN THE Recheck_Router SHALL report `indeterminate` and SHALL NOT report `resolved` or `unresolved` for that finding.
14. WHEN the Recheck_Router issues any DNS, SSL, headers, robots/sitemap, or status-only request, THE Recheck_Router SHALL enforce a per-request timeout of 10 seconds.

### Requirement 4: Handle indeterminate outcomes and check failures

**User Story:** As a domain owner, I want honest results when a re-check cannot be confirmed, so that I am not told a problem is fixed when it is unknown.

#### Acceptance Criteria

1. IF the passive check mapped to a Finding_Id fails or cannot reach the target, THEN THE Recheck_Service SHALL return a Recheck_Status of `indeterminate`.
2. IF the passive check mapped to a Finding_Id does not complete within its per-check timeout (DNS 6 seconds, SSL 8 seconds, subdomain enumeration 8 seconds, HTTP header retrieval 9 seconds, files/robots retrieval 6 seconds), THEN THE Recheck_Service SHALL abort that check and return a Recheck_Status of `indeterminate`.
3. WHEN the Recheck_Service returns a Recheck_Status of `indeterminate`, THE Recheck_Service SHALL include a message indicating that the result could not be confirmed and that the user may retry the re-check.
4. WHEN the Recheck_Service returns a Recheck_Status of `indeterminate`, THE Recheck_Service SHALL retain the Finding's previously recorded state without marking it `resolved` or `unresolved`.
5. IF an unexpected error occurs while processing a re-check, THEN THE Recheck_Service SHALL return a Recheck_Status of `indeterminate` and SHALL NOT propagate an unhandled error to the caller.

### Requirement 5: Re-check button on each finding card

**User Story:** As a domain owner, I want a Re-check button on each finding, so that I can verify a specific fix directly from the results.

#### Acceptance Criteria

1. WHERE a finding is a Recheckable_Finding, THE Frontend_App SHALL render a Re-check control on that Finding_Card.
2. WHERE a finding is a Non_Recheckable_Finding, THE Frontend_App SHALL render that finding's Re-check control in a state that is not activatable and SHALL NOT send a re-check request when that control is interacted with.
3. WHEN a user activates the Re-check control on a Finding_Card, THE Frontend_App SHALL send exactly one re-check request to the Recheck_Service containing the current domain and that finding's Finding_Id.
4. IF a user activates the Re-check control on a Finding_Card while no current domain exists in client state, THEN THE Frontend_App SHALL NOT send a re-check request and SHALL indicate on that Finding_Card that the re-check is unavailable.
5. WHILE a re-check request for a Finding_Card is in progress, THE Frontend_App SHALL display a visually distinct pending state on that Finding_Card that differs from the resolved, unresolved, and indeterminate states, and SHALL disable that card's Re-check control.
6. WHILE a re-check request for one Finding_Card is in progress, THE Frontend_App SHALL keep the Re-check controls on all other Finding_Cards independently activatable.
7. WHEN a user activates the Re-check control, THE Frontend_App SHALL re-check only that one finding and SHALL NOT re-run the full scan.

### Requirement 6: Reflect re-check results in the finding card

**User Story:** As a domain owner, I want each finding card to show its latest re-check outcome, so that I can see at a glance what is fixed.

#### Acceptance Criteria

1. WHEN the Frontend_App receives a `resolved` Recheck_Status for a Finding_Card, THE Frontend_App SHALL mark that Finding_Card as resolved using a visual state that is distinguishable from the unresolved, indeterminate, re-check-failed, and not-yet-re-checked states of a Finding_Card.
2. WHEN the Frontend_App receives an `unresolved` Recheck_Status for a Finding_Card, THE Frontend_App SHALL display on that Finding_Card an indication that the issue is still present, using a visual state distinguishable from the resolved, indeterminate, re-check-failed, and not-yet-re-checked states.
3. WHEN the Frontend_App receives an `indeterminate` Recheck_Status for a Finding_Card, THE Frontend_App SHALL display on that Finding_Card an indication that the result could not be confirmed, using a visual state distinguishable from the resolved, unresolved, re-check-failed, and not-yet-re-checked states.
4. WHILE a re-check request initiated from a Finding_Card is in progress, THE Frontend_App SHALL disable that card's Re-check control and display an in-progress indicator on that Finding_Card.
5. IF a re-check request from a Finding_Card fails at the network or transport level, or does not receive a response within 30 seconds, THEN THE Frontend_App SHALL display on that Finding_Card an indication that the re-check could not be completed and SHALL re-enable that card's Re-check control.
6. IF the Recheck_Service returns a non-success error response for a re-check request from a Finding_Card, THEN THE Frontend_App SHALL display on that Finding_Card an indication that the re-check could not be completed and SHALL re-enable that card's Re-check control.
7. WHEN the Frontend_App displays any Recheck_Status on a Finding_Card, THE Frontend_App SHALL also display the date and time at which the re-check was performed.
8. WHEN a user activates the Re-check control again on the same Finding_Card, THE Frontend_App SHALL replace the previous Recheck_Status display for that Finding_Card with the new outcome.

### Requirement 7: Recognize a re-check request in chat

**User Story:** As a domain owner, I want to ask the chat to re-check a finding in plain language, so that I can verify fixes conversationally.

#### Acceptance Criteria

1. WHEN a chat message expresses a Recheck_Intent that resolves to exactly one existing Recheckable_Finding in the current report, THE Chat_Service SHALL trigger a re-check of that finding through the same Recheck_Router used by the Recheck_Service.
2. WHEN a chat message expresses a Recheck_Intent, THE Chat_Service SHALL resolve the message to the Finding_Id of an existing finding in the current report before invoking the Recheck_Router.
3. IF a chat message expresses a Recheck_Intent but no existing finding in the current report matches the request, THEN THE Chat_Service SHALL reply with a message indicating that no matching finding exists to re-check, and SHALL NOT invoke the Recheck_Router or run a passive check.
4. IF a chat message expresses a Recheck_Intent that resolves to a Non_Recheckable_Finding, THEN THE Chat_Service SHALL reply with a message indicating that the finding cannot be automatically re-checked, SHALL NOT invoke the Recheck_Router or run a passive check, and SHALL NOT report a fabricated Recheck_Status.
5. IF a chat message expresses a Recheck_Intent that resolves to more than one existing finding in the current report, THEN THE Chat_Service SHALL reply with a message listing the matching findings by Finding_Id, and SHALL NOT invoke the Recheck_Router or run a passive check until the message resolves to exactly one Finding_Id.
6. WHEN a chat message does not express a Recheck_Intent, THE Chat_Service SHALL answer using the existing read-only report-context behavior, and SHALL NOT invoke the Recheck_Router or run a passive check.

### Requirement 8: Report chat-triggered re-check results

**User Story:** As a domain owner, I want the chat to tell me the outcome of a re-check it ran, so that I get a clear answer in the conversation.

#### Acceptance Criteria

1. WHEN the Chat_Service completes a re-check triggered by a Recheck_Intent, THE Chat_Service SHALL include in its reply a status statement that reads "resolved" when the Recheck_Status is `resolved`, "still present" when the Recheck_Status is `unresolved`, and "could not be confirmed" when the Recheck_Status is `indeterminate`.
2. WHEN the Chat_Service reports a re-check outcome, THE Chat_Service SHALL identify the re-checked finding in its reply by both its Finding_Id and its human-readable finding description.
3. WHEN the Chat_Service reports a re-check outcome, THE Chat_Service SHALL base the resolved or still-present statement only on the Recheck_Status returned by the Recheck_Router and SHALL NOT infer resolution from the prior report context.
4. IF a chat-triggered re-check returns a Recheck_Status of `indeterminate`, THEN THE Chat_Service SHALL state in its reply that the result could not be confirmed and SHALL include an explicit prompt inviting the user to request the re-check again.
5. IF the Recheck_Router returns no Recheck_Status for a chat-triggered re-check (including timeout or Recheck_Router unavailability), THEN THE Chat_Service SHALL reply with a message indicating the re-check could not be completed, SHALL invite the user to request the re-check again, and SHALL leave the stored status of the finding unchanged.
6. WHEN the Recheck_Router returns a Recheck_Status for a chat-triggered re-check, THE Chat_Service SHALL post its outcome reply within 5 seconds of receiving that Recheck_Status.

### Requirement 9: Consistency between button and chat re-check paths

**User Story:** As a domain owner, I want the same answer whether I click the button or ask in chat, so that the two paths are trustworthy.

#### Acceptance Criteria

1. WHEN the same Finding_Id for the same domain is re-checked through the Re-check button and through chat using identical input target conditions (the same observable target state for that Finding_Id with no change to that state between the two evaluations), THE Recheck_Router SHALL return an identical Recheck_Status value, drawn from the set {resolved, unresolved, indeterminate}, for both paths.
2. THE Recheck_Service and the Chat_Service SHALL determine a Finding_Id's Recheck_Status exclusively through a single shared Recheck_Router implementation, supplying identical input parameters for a given Finding_Id and domain so that the path of invocation does not alter the result.
3. THE Recheck_Router SHALL compute Recheck_Status as a deterministic function of its input target conditions, such that two evaluations with identical inputs always yield the same Recheck_Status regardless of which path invokes it or when it is invoked.
4. IF the Recheck_Router cannot resolve a definitive Recheck_Status for a Finding_Id (for example, the target data is unavailable or the evaluation fails), THEN THE Recheck_Router SHALL return the indeterminate Recheck_Status for both the Re-check button path and the chat path, leaving the stored Finding_Id state unchanged.
