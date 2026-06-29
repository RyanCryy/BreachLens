# Implementation Plan: Passive Scan Engine

## Overview

This plan extracts the scan orchestration currently inlined in `netlify/functions/scan.js` into a new dependency-injected module, `netlify/functions/lib/scan-engine.js`, that composes the existing passive primitives in `netlify/functions/lib/checks.js`. The build proceeds bottom-up: constants → outcome normalizer → check registry → concurrent execution with per-check timeouts, a global watchdog, and progress emission → DNS resolution gate → paid-source gating → handler refactor. Each implementation step is immediately followed by the property-based and unit tests defined in the design's Testing Strategy, so correctness is validated incrementally and the engine is fully wired into `scan.js` by the end.

All code is JavaScript (ES modules, Node `>=18`), matching the existing codebase. Tests use `fast-check` (`^4.8.0`) under `vitest` (`^4.1.9`), following the established `recheck.propertyN.test.js` layout with injected `deps` and `vi.useFakeTimers()` for hang/timeout cases. Minimum 100 runs per property.

## Tasks

- [x] 1. Create scan-engine module skeleton and constants
  - [x] 1.1 Define core constants in `netlify/functions/lib/scan-engine.js`
    - Create the module and export `CHECK_STATUS` (`success`/`empty`/`unavailable`), `RESULT_TYPE` (`scan`/`resolution_failure`), `CHECK_IDS` (the 11 defined checks), and `CHECK_TIMEOUTS` mapping each id to a per-check budget within the inclusive 6000–8000 ms range
    - Export an empty `runScan(domain, deps = defaultDeps, emit = () => {})` stub and a `defaultDeps` object wiring the real primitives from `lib/checks.js`
    - _Requirements: 1.3, 2.6_

  - [x]* 1.2 Write unit test for the check id list
    - Assert `CHECK_IDS` equals exactly the 11 named checks (DNS/SPF/DMARC, CAA, TLS, subdomains, headers, cookies, mixed content, tech, robots/sitemap, exposed files, provider)
    - Assert every `CHECK_TIMEOUTS` value is within `[6000, 8000]`
    - File: `netlify/functions/lib/scan-engine.unit.test.js`
    - _Requirements: 1.3, 2.6_

- [x] 2. Implement the outcome normalizer and internal sentinels
  - [x] 2.1 Implement sentinels and `normalizeOutcome` in `scan-engine.js`
    - Define `TIMEOUT_SENTINEL` and `ERROR_SENTINEL(msg)` internal markers
    - Implement pure `normalizeOutcome(id, settled)`: sentinel/error → `{ id, status: UNAVAILABLE, findings: [], error }`; ran with ≥1 finding → `SUCCESS`; ran with 0 findings → `EMPTY` with `error: null`
    - _Requirements: 2.4, 2.5_

  - [x]* 2.2 Write property test for status trichotomy
    - **Property 3: Status trichotomy** — for any raw result/behavior, the normalizer assigns exactly one status (Unavailable on error/timeout, Success on ≥1 finding, Empty on 0 findings)
    - **Validates: Requirements 2.4, 2.5**
    - Use a `findings` arbitrary (arrays of arbitrary length) to drive the Success/Empty boundary; min 100 runs
    - File: `netlify/functions/lib/scan-engine.property3.test.js`

  - [x]* 2.3 Write unit tests for normalizer edge cases
    - Empty findings → `Empty`; one finding → `Success`; sentinel → `Unavailable`
    - Add to `netlify/functions/lib/scan-engine.unit.test.js`
    - _Requirements: 2.4, 2.5_

- [x] 3. Build the check registry
  - [x] 3.1 Implement the check registry in `scan-engine.js`
    - Map each `checkId` to `{ run(domain, deps), toFindings(raw), timeout }`, composing `checkDns`, `lookupCaa`, `checkSsl`, `checkSubdomains`, `checkHeaders`, `checkRobotsSitemap`, `checkSensitiveFiles`, `inferProvider` from `lib/checks.js`
    - Model `cookies`, `mixed-content`, and `tech` as dependent checks that await the shared `headers` fetch and reuse `analyzeCookies`/`analyzeMixedContent`/`fingerprintTech` (no new requests — preserve single passive fetch)
    - Implement `toFindings(raw)` per the design's findings-bearing table; for `exposed-files`, derive only status-shaped fields (path, status, exposed) and never retain response bodies
    - _Requirements: 1.3, 3.1, 3.2_

  - [x]* 3.2 Write property test for no response bodies retained
    - **Property 6: No response bodies retained** — for any Scan_Result, no Check_Outcome retains an HTTP response body; exposed-file outcomes carry only status-derived fields
    - **Validates: Requirements 3.1, 3.2**
    - Min 100 runs
    - File: `netlify/functions/lib/scan-engine.property6.test.js`

- [x] 4. Implement concurrent execution, bounded completion, and progress emission
  - [x] 4.1 Launch all checks concurrently with per-check timeouts in `runScan`
    - Build all check wrappers synchronously in a single loop before any `await`, each wrapped with `withTimeout(checkPromise, CHECK_TIMEOUTS[id], TIMEOUT_SENTINEL)` and a `.catch` → `ERROR_SENTINEL`
    - _Requirements: 1.1, 2.1, 2.2_

  - [x]* 4.2 Write property test for concurrent start
    - **Property 1: All checks start concurrently** — every defined check has started before any check resolves
    - **Validates: Requirements 1.1**
    - Min 100 runs; use injected deps that record start order vs resolution order
    - File: `netlify/functions/lib/scan-engine.property1.test.js`

  - [x] 4.3 Implement the resolve phase with a global watchdog and failure isolation
    - `await` the failure-tolerant wrappers (never raw check promises); wrap the whole resolve phase in a global watchdog of `max(CHECK_TIMEOUTS) + 2000 ms` that resolves outstanding checks as `Unavailable`
    - Add an outer try/catch so an orchestrator error still yields a complete result with affected checks `Unavailable`
    - _Requirements: 2.1, 2.2, 2.6_

  - [x]* 4.4 Write property test for bounded completion time
    - **Property 5: Bounded completion time** — for any behaviors including never-resolving checks, `runScan` settles within `max(Check_Timeout) + 2000 ms`
    - **Validates: Requirements 2.6**
    - Use `vi.useFakeTimers()` + `vi.runAllTimersAsync()`; min 100 runs
    - File: `netlify/functions/lib/scan-engine.property5.test.js`

  - [x]* 4.5 Write property test for partial-failure isolation
    - **Property 4: Partial-failure isolation** — for any subset of checks that throw/reject/hang/time out, the scan still resolves to a complete Scan_Result where failing checks are `Unavailable` and others keep their implied status
    - **Validates: Requirements 2.1, 2.2, 2.3**
    - Use a per-check `behavior` arbitrary (`success-with-findings`, `success-empty`, `throw`, `reject`, `hang`, `timeout`); min 100 runs
    - File: `netlify/functions/lib/scan-engine.property4.test.js`

  - [x] 4.6 Implement progress emission in `runScan`
    - Call `emit({ type: "progress", check, status, seq })` exactly once per check at the moment its wrapper settles, assigning a monotonic `seq` in emission (resolution) order
    - _Requirements: 4.1, 4.2, 4.3_

  - [x]* 4.7 Write property test for progress-event invariants
    - **Property 7: Progress-event invariants** — exactly one event per defined check; each event's check ∈ CHECK_IDS with status matching its final outcome; events emitted in resolution order with strictly increasing `seq`
    - **Validates: Requirements 4.1, 4.2, 4.3**
    - Use a `resolutionOrder` arbitrary (permutation of `CHECK_IDS`) to drive fake-dep settle order; min 100 runs
    - File: `netlify/functions/lib/scan-engine.property7.test.js`

  - [x] 4.8 Aggregate outcomes into a Scan_Result
    - Assemble `{ type: "scan", domain, scannedAt, outcomes }` with exactly one `Check_Outcome` per `CHECK_IDS` entry (no omissions, no duplicates)
    - _Requirements: 1.2, 2.3_

  - [x]* 4.9 Write property test for result completeness
    - **Property 2: Result completeness** — for any assignment of check behaviors, the set of outcome ids equals `CHECK_IDS` exactly
    - **Validates: Requirements 1.2, 2.3**
    - Min 100 runs
    - File: `netlify/functions/lib/scan-engine.property2.test.js`

- [x] 5. Checkpoint - core engine
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement the DNS resolution gate
  - [x] 6.1 Add the resolution gate and `ResolutionFailure` state in `runScan`
    - Evaluate DNS resolution before aggregation; if the domain yields no usable address, return `{ type: RESOLUTION_FAILURE, domain, message }` instead of a Scan_Result
    - Draw the message from a fixed friendly string parameterized only by domain; never interpolate `Error`/`error.stack`/internals
    - _Requirements: 5.1, 5.2, 5.3_

  - [x]* 6.2 Write property test for the resolution-failure error state
    - **Property 8: Resolution-failure error state** — for any dep config where DNS yields no usable address, `runScan` returns a distinct `Resolution_Failure` with a non-empty message containing no stack traces/internals, even when the DNS dep throws an Error with a populated stack
    - **Validates: Requirements 5.1, 5.2, 5.3**
    - Min 100 runs
    - File: `netlify/functions/lib/scan-engine.property8.test.js`

  - [x]* 6.3 Write unit test for the resolution-failure message text
    - Concrete unreachable-domain case asserting the friendly message text and the absence of stack markers
    - Add to `netlify/functions/lib/scan-engine.unit.test.js`
    - _Requirements: 5.2, 5.3_

- [x] 7. Implement paid / out-of-scope source gating
  - [x] 7.1 Add key-gated registry closures reading from `deps.env`
    - For each key-gated check, return the `Unavailable` sentinel before invoking the paid primitive when no valid API key is present in `deps.env`; otherwise invoke the real primitive and derive the outcome from its observation
    - Never substitute engine-fabricated findings for a missing key
    - _Requirements: 6.1, 6.2, 6.3_

  - [x]* 7.2 Write property test for paid-source key gating
    - **Property 9: Paid-source key gating** — with no key in `deps.env`, the outcome is `Unavailable` and the paid primitive is never invoked; with a valid key, the real primitive is invoked and drives the outcome
    - **Validates: Requirements 6.1, 6.2, 6.3**
    - Use an `env` arbitrary toggling key presence/absence and a spy primitive; min 100 runs
    - File: `netlify/functions/lib/scan-engine.property9.test.js`

- [x] 8. Refactor the streaming handler to delegate to the engine
  - [x] 8.1 Refactor `netlify/functions/scan.js` to call `runScan`
    - Keep `normalizeDomain`/`isValidDomain` validation and the downstream AI passes in the handler; build an `emit` that NDJSON-encodes events to `controller.enqueue`, call `runScan(domain, defaultDeps, emit)`, emit `{ type: "error", message }` on `RESOLUTION_FAILURE` else `{ type: "result", scan }`
    - _Requirements: 4.1, 4.2, 4.3, 5.1_

  - [x]* 8.2 Write handler integration test
    - Assert `runScan` wired into the NDJSON stream emits `progress` lines followed by a single `result` (or `error`) line
    - File: `netlify/functions/lib/scan-engine.unit.test.js` (or a dedicated handler test)
    - _Requirements: 4.1, 4.2, 4.3, 5.1_

- [x] 9. Add passive-only smoke tests
  - [x]* 9.1 Write smoke tests for passive-only request constraints
    - 3.3 read-only verbs (GET / TLS handshake, no mutating verbs); 3.4 no auth/credential headers attached (only existing User-Agent); 3.5 TLS check connects to port 443 and performs only a handshake
    - File: `netlify/functions/lib/scan-engine.smoke.test.js`
    - _Requirements: 3.3, 3.4, 3.5_

- [x] 10. Final checkpoint - full suite
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional test sub-tasks and can be skipped for a faster MVP; core implementation tasks are never optional.
- Each of the 9 correctness properties is implemented as a single property-based test in its own file, mirroring the existing `recheck.propertyN.test.js` layout, and is annotated with its property number and the requirements clause it validates.
- Property tests inject all check primitives via `deps` and use fake timers for hang/timeout cases, so 100+ iterations stay fast and never touch the real network.
- Requirements 3.3–3.5 are verified by smoke tests/review rather than property tests because their behavior does not vary with input.
- Checkpoints provide incremental validation between the core engine, the gating logic, and the handler wiring.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.1"] },
    { "id": 3, "tasks": ["3.2", "4.1"] },
    { "id": 4, "tasks": ["4.2", "4.3"] },
    { "id": 5, "tasks": ["4.4", "4.5", "4.6"] },
    { "id": 6, "tasks": ["4.7", "4.8"] },
    { "id": 7, "tasks": ["4.9", "6.1"] },
    { "id": 8, "tasks": ["6.2", "6.3", "7.1"] },
    { "id": 9, "tasks": ["7.2", "8.1"] },
    { "id": 10, "tasks": ["8.2", "9.1"] }
  ]
}
```
