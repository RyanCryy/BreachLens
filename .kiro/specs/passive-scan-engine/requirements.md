# Requirements Document

## Introduction

The Passive Scan Engine performs all raw, no-authentication security checks against a target domain. The engine observes only publicly available information and never performs intrusive testing. It runs every check concurrently, tolerates partial failures from any individual check, streams real-time progress as checks resolve, and returns a structured result within a bounded time regardless of slow or unresponsive third-party data sources.

This document defines the functional and quality requirements for the engine using EARS patterns. Scope is limited to passive observation; authenticated scanning, active exploitation, and paid third-party data sources are explicitly out of scope.

## Glossary

- **Scan_Engine**: The component that orchestrates and executes all passive security checks against a target domain and aggregates their outcomes.
- **Check**: A single passive security inspection (e.g., DNS/SPF/DMARC, CAA, TLS certificate, subdomains, HTTP headers, cookies, mixed content, technology stack, robots.txt/sitemap.xml, exposed files, provider inference).
- **Target_Domain**: The domain name submitted by the user as the subject of the scan.
- **Scan_Result**: The single structured object returned by the Scan_Engine containing the outcome of every Check.
- **Check_Outcome**: The portion of the Scan_Result describing one Check, including its status and any findings.
- **Check_Timeout**: The maximum duration, configured per Check between 6 and 8 seconds inclusive, that a single Check is allowed to run before being treated as unavailable.
- **Progress_Event**: A streamed event emitted by the Scan_Engine reporting the resolution of a single Check.
- **Unavailable_Status**: A Check_Outcome status indicating the Check could not run or complete (failure or timeout), as distinct from a Check that ran and found nothing.
- **Empty_Status**: A Check_Outcome status indicating the Check ran successfully and found no findings.
- **Success_Status**: A Check_Outcome status indicating the Check ran successfully and produced one or more findings.
- **Resolution_Failure**: The condition where DNS resolution for the Target_Domain produces no usable address.
- **User**: The person who submits a Target_Domain and receives the Scan_Result.

## Requirements

### Requirement 1: Run all passive checks concurrently

**User Story:** As a User, I want to enter a domain and receive results from all passive checks, so that I get a complete picture of my public security exposure.

#### Acceptance Criteria

1. WHEN a valid Target_Domain is submitted, THE Scan_Engine SHALL start every defined Check concurrently.
2. WHEN every Check has resolved, THE Scan_Engine SHALL return a single Scan_Result containing one Check_Outcome for every defined Check.
3. THE Scan_Engine SHALL include in the Scan_Result a Check_Outcome for each of the following Checks: DNS/SPF/DMARC, CAA, TLS certificate, subdomains, HTTP headers, cookies, mixed content, technology stack, robots.txt/sitemap.xml, exposed files, and provider inference.

### Requirement 2: Tolerate slow or failing individual checks

**User Story:** As a User, I want my scan to complete even if one data source is slow or rate-limited, so that a single flaky dependency never breaks my report.

#### Acceptance Criteria

1. IF a Check exceeds its Check_Timeout, THEN THE Scan_Engine SHALL set that Check_Outcome status to Unavailable_Status and continue the remaining Checks.
2. IF a Check raises an error, THEN THE Scan_Engine SHALL set that Check_Outcome status to Unavailable_Status and continue the remaining Checks.
3. WHEN any single Check fails or times out, THE Scan_Engine SHALL return the Scan_Result for all remaining Checks.
4. WHEN a Check completes successfully with one or more findings, THE Scan_Engine SHALL set that Check_Outcome status to Success_Status.
5. WHEN a Check completes successfully with no findings, THE Scan_Engine SHALL set that Check_Outcome status to Empty_Status.
6. THE Scan_Engine SHALL complete and return the Scan_Result within the largest configured Check_Timeout plus an aggregation allowance of 2 seconds.

### Requirement 3: Passive observation only

**User Story:** As a User, I want assurance that scanning my domain never performs anything beyond passive observation, so that running a scan carries no risk to my infrastructure.

#### Acceptance Criteria

1. WHEN checking for exposed sensitive files, THE Scan_Engine SHALL read only the HTTP status code of each requested path.
2. WHEN checking for exposed sensitive files, THE Scan_Engine SHALL discard each HTTP response body without storing it in the Scan_Result.
3. WHEN performing any Check, THE Scan_Engine SHALL issue only read-only requests against the Target_Domain.
4. WHEN performing any Check, THE Scan_Engine SHALL omit any authentication credentials from requests to the Target_Domain.
5. WHERE a Check requires a TLS inspection, THE Scan_Engine SHALL limit network activity to a TLS handshake on port 443.

### Requirement 4: Real-time progress visibility

**User Story:** As a User, I want to see which checks are actively running and which have completed, so that I understand the scan is making real progress rather than appearing frozen.

#### Acceptance Criteria

1. WHEN a Check resolves with success, failure, or timeout, THE Scan_Engine SHALL emit a Progress_Event identifying that Check and its status.
2. WHEN the Scan_Engine streams Progress_Events, THE Scan_Engine SHALL emit each Progress_Event in the actual order in which Checks resolve.
3. THE Scan_Engine SHALL emit exactly one Progress_Event per defined Check during a scan.

### Requirement 5: Handle unresolvable or invalid domains

**User Story:** As a User, I want a clear, friendly error if I enter a domain that doesn't resolve, so that I understand the problem isn't with the scanner itself.

#### Acceptance Criteria

1. IF the Target_Domain produces a Resolution_Failure, THEN THE Scan_Engine SHALL return a distinct error state instead of a Scan_Result.
2. WHEN the Scan_Engine returns the error state for a Resolution_Failure, THE Scan_Engine SHALL include a human-readable message describing the resolution problem.
3. WHEN the Scan_Engine returns the error state for a Resolution_Failure, THE Scan_Engine SHALL exclude raw stack traces and internal error details from the message.

### Requirement 6: Exclude out-of-scope sources

**User Story:** As a User, I want assurance that paid or out-of-scope data sources are never silently substituted, so that I can trust the accuracy of the report.

#### Acceptance Criteria

1. WHERE a Check depends on a paid third-party data source requiring an API key AND no valid API key is configured, THE Scan_Engine SHALL report that Check_Outcome with Unavailable_Status.
2. WHERE a Check depends on a paid third-party data source requiring an API key AND a valid API key is configured, THE Scan_Engine SHALL run that Check and report its Check_Outcome from real observation.
3. WHEN reporting an out-of-scope data source, THE Scan_Engine SHALL provide the Check_Outcome from real observation rather than simulated findings.
