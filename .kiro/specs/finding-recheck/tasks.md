# Implementation Plan: Finding Re-check

## Overview

This plan implements the finding-recheck feature for BreachLens (Netlify Functions v2 on Deno + vanilla JS frontend). It is built around a single shared `Recheck_Router` module (`lib/recheck.js`) whose pure decision logic is the property-based-testing target, with thin HTTP/chat wrappers and isolated per-card frontend state.

The work proceeds bottom-up and test-driven: first stand up the test runner and `fast-check`, then build the status-only check primitive, then the pure router classifier and predicates (validated with property tests), then the async orchestrator with dependency injection and timeouts, then the HTTP endpoint, then the chat integration, then the frontend, wiring each layer into the previous one.

Convention note: the codebase is ESM JavaScript (`"type": "module"`), functions reuse a shared `CORS` const and `json` helper (see `scan.js`/`chat.js`), and checks live in `lib/checks.js`. Tasks follow these conventions.

## Tasks

- [ ] 1. Set up test runner and property-based testing dependency
  - Add `vitest` and `fast-check` as devDependencies (Vitest runs the ESM modules in-process; functions still deploy to Deno unchanged)
  - Add a `test` script (e.g. `"test": "vitest run"`) to `package.json` and configure jsdom environment availability for frontend DOM tests
  - Create a minimal `vitest.config.js` (ESM, node environment by default, jsdom opt-in per file)
  - Add a smoke test that imports `lib/checks.js` to confirm ESM test wiring works
  - _Requirements: supports all testing tasks below_

- [ ] 2. Add the status-only file probe primitive
  - [ ] 2.1 Implement `checkFileStatus(domain, path)` in `netlify/functions/lib/checks.js`
    - Issue a `GET` with `redirect: "manual"`, the existing BreachLens User-Agent, and a 6s `AbortSignal.timeout`
    - Return `{ reachable, status, exposed }`; inspect only `res.status`, never call `res.text()` or read `res.body`
    - On any throw/timeout return `{ reachable: false, status: null, exposed: false }`
    - _Requirements: 3.9, 3.11, 3.14_

  - [ ]* 2.2 Write unit test for `checkFileStatus`
    - Assert it returns `exposed: true` only on status 200 and never accesses the response body (use a fetch double whose body accessors throw/record)
    - _Requirements: 3.9, 3.11_

- [ ] 3. Implement the pure router classifier (`routeFor` / `isRecheckable`)
  - [ ] 3.1 Create `netlify/functions/lib/recheck.js` with the `STATUS` enum and the family mapping table
    - Define `STATUS = { RESOLVED, UNRESOLVED, INDETERMINATE }`
    - Implement `routeFor(findingId)` returning `{ family, check, decide, describe, path? }` or `null`, covering exact ids (`spf-missing`, `dmarc-missing`, `caa-missing`, `hdr-hsts`/`hdr-csp`/`hdr-xfo`/`hdr-xcto`, `cookie-secure`/`cookie-httponly`/`cookie-samesite`, `mixed-content`, `robots-sensitive`) and prefixes (`ssl-`, `exposed-file-`); `subdomain-*` and all unrecognized ids return `null`
    - For `exposed-file-{path}`, decode the path as `findingId.slice("exposed-file-".length)` and carry it on the route
    - Implement `isRecheckable(findingId)` as `routeFor(findingId) !== null`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.12_

  - [ ] 3.2 Implement the pure per-family `decide(observation)` predicates
    - Implement total functions mapping a normalized observation (or `{ ok: false }` sentinel) to a `STATUS` per the design truth table for every family
    - Ensure the failure sentinel / `reachable: false` always maps to `INDETERMINATE`; CAA `unknown` maps to `INDETERMINATE`; SSL boundary at `expiresInDays > 30`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.1_

  - [ ]* 3.3 Write property test for the result contract
    - **Property 1: Re-check result always satisfies the result contract** (status ∈ enum, echoes `findingId`, non-empty message ≤ 500 chars)
    - **Validates: Requirements 1.2, 1.3, 1.4**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 1: ...`

  - [ ]* 3.4 Write property test for non-recheckable / unrecognized ids
    - **Property 2: Non-recheckable and unrecognized ids yield indeterminate without running any check** (every `subdomain-*` and arbitrary unrecognized string → `indeterminate`, no dependency invoked)
    - **Validates: Requirements 1.7, 2.6, 3.10, 3.12**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 2: ...`; assert injected check spies are never called

  - [ ]* 3.5 Write property test for the family-to-predicate truth table
    - **Property 3: Each recheckable family maps to the correct check and resolution predicate** (per-family generated successful observations yield the documented status; SSL `expiresInDays` ∈ {…,-1,0,30,31,…}; cookie/mixed/robots counts incl. 0)
    - **Validates: Requirements 1.1, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 3: ...`

- [ ] 4. Implement the async orchestrator `recheckFinding` with timeouts and DI
  - [ ] 4.1 Implement `recheckFinding({ domain, findingId }, deps = defaultDeps)` and `withTimeout`
    - `defaultDeps` wires the real `lib/checks.js` primitives (`checkDns`, `checkSsl`, `checkHeaders`, `checkRobotsSitemap`, `analyzeCookies`, `analyzeMixedContent`, `checkFileStatus`)
    - Flow: `routeFor` → null short-circuits to `indeterminate` with no check; else run mapped check(s) under per-check `withTimeout` (DNS 6s, SSL 8s, headers 9s, robots 6s, file 6s), normalize to observation or `{ ok: false }` on throw/timeout, then `decide`, then `describe`
    - Wrap the whole call in an overall 30s `withTimeout` and a try/catch that collapses any unexpected error to `indeterminate`; ensure the timed-out message and indeterminate messages invite a retry and stay ≤ 500 chars
    - Add the robots reachability guard so a swallowed network error becomes `{ ok: false }` rather than a false `resolved`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.7, 1.8, 2.6, 3.13, 3.14, 4.1, 4.2, 4.3, 4.5, 9.2, 9.3_

  - [ ]* 4.2 Write property test for failure/unreachability → indeterminate
    - **Property 4: Any check failure, unreachability, or error yields indeterminate** (injected deps that throw, time out, or report unreachable never produce `resolved`/`unresolved`)
    - **Validates: Requirements 3.13, 4.1, 4.5, 9.4**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 4: ...`

  - [ ]* 4.3 Write property test for exposed-file status-only inspection
    - **Property 5: Exposed-file re-checks inspect only the HTTP status code and never the body** (response double whose body accessors record/reject access)
    - **Validates: Requirements 3.11**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 5: ...`

  - [ ]* 4.4 Write property test for path-independent determinism
    - **Property 8: Status is a deterministic, path-independent function of the inputs** (two evaluations with identical fixed observation/deps — one per simulated path — yield identical status)
    - **Validates: Requirements 9.1, 9.2, 9.3**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 8: ...`

  - [ ]* 4.5 Write unit tests for orchestrator timeouts and messaging
    - With fake timers, a never-resolving injected check yields `indeterminate` at its per-check budget and at the 30s overall cap; assert "could not confirm / retry" wording
    - _Requirements: 1.8, 3.14, 4.2, 4.3_

- [ ] 5. Checkpoint - Ensure all router tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement the `POST /api/recheck` endpoint
  - [ ] 6.1 Create `netlify/functions/recheck.js`
    - Mirror `scan.js`/`chat.js` structure (shared `CORS` const, `json` helper); `OPTIONS` → 204, non-POST/OPTIONS → 405
    - Strict validation order (parse body → domain → findingId, return on first failure): unparseable body → 400; missing/invalid domain after `normalizeDomain` + `isValidDomain` → 400; missing/empty/>256-char findingId → 400
    - On valid request call `recheckFinding({ domain, findingId })` and return `200 { findingId, status, message }`; non-recheckable/unrecognized id returns `200` + `indeterminate` (not 400); wrap handler in try/catch so any error becomes `200` + `indeterminate`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 4.5_

  - [ ] 6.2 Add the `/api/recheck` redirect to `netlify.toml`
    - Add the redirect to `/.netlify/functions/recheck` before the `/*` SPA fallback
    - _Requirements: 1.1, 1.5_

  - [ ]* 6.3 Write endpoint contract unit tests for `recheck.js`
    - Method handling (405/204), JSON parse failure (400), domain + findingId validation incl. 256-char boundary (255/256/257) and normalization, validation ordering, and 200+indeterminate for unrecognized id
    - _Requirements: 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [ ] 7. Integrate the recheck-intent stage into chat
  - [ ] 7.1 Add intent + finding resolution to `netlify/functions/chat.js`
    - Before the existing read-only answer path, resolve `domain = report.domain || scan.domain` and run a single structured `callLLMJson` over the user message + existing findings (`id` + `title`) returning `{ recheck, findingIds }`; intersect returned ids with ids actually present in `report.findings`; add a deterministic keyword fallback (`re-check`, `recheck`, `is … fixed`, `did … get fixed`, `check … again`, `verify …`) when the LLM call fails
    - Preserve the existing read-only behavior entirely when `recheck === false`
    - _Requirements: 7.1, 7.2, 7.6_

  - [ ] 7.2 Implement chat branch resolution and deterministic outcome templating
    - Branch on the resolved set: 0 matches → "no matching finding"; >1 → list candidates by `Finding_Id`; exactly 1 non-recheckable (`isRecheckable(id) === false`) → "can't be automatically re-checked" with no router/check/fabricated status; exactly 1 recheckable → call `recheckFinding({ domain, findingId })`
    - Template the outcome deterministically from the returned status ("resolved" / "still present" / "could not be confirmed"), naming the finding by both `Finding_Id` and human-readable title; on router unavailable/throw/no status → "couldn't complete that re-check, try again" with no status statement and stored state unchanged
    - _Requirements: 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 9.2_

  - [ ]* 7.3 Write property test for chat intent resolution subset guarantee
    - **Property 6: Chat intent resolution never targets a fabricated finding** (resolved id set ⊆ ids present in the report; invented ids discarded)
    - **Validates: Requirements 7.2**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 6: ...`

  - [ ]* 7.4 Write property test for chat outcome templating
    - **Property 7: Chat outcome replies are templated faithfully from the router status** (reply contains mandated wording for the status plus both `Finding_Id` and title)
    - **Validates: Requirements 8.1, 8.2**
    - Min 100 iterations; tag `Feature: finding-recheck, Property 7: ...`

  - [ ]* 7.5 Write chat orchestration branch unit tests
    - With the intent step stubbed, verify each branch — non-recheck (router not called), zero match, multiple match, non-recheckable single match, recheckable single match (router called) — plus router-unavailable and "router status overrides stale context"
    - _Requirements: 7.1, 7.3, 7.4, 7.5, 7.6, 8.3, 8.4, 8.5, 8.6, 9.2_

- [ ] 8. Checkpoint - Ensure all backend tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Add the per-card Re-check control to the frontend
  - [ ] 9.1 Add client-side recheckability and per-card state to `public/app.js`
    - Add a local `isRecheckable(id)` mirroring the router family rules and a `recheckState` `Map<FindingId, { phase, message, checkedAt }>`
    - In `renderFindings`, add a footer row per card: recheckable → activatable `Re-check` button + status slot; non-recheckable → disabled, non-activatable control that never sends a request
    - _Requirements: 5.1, 5.2_

  - [ ] 9.2 Implement the activation handler with isolated state and 30s timeout
    - No `state.domain` → show "Re-check unavailable", send nothing; else set that card to pending and disable only that card's button while keeping others activatable
    - Send exactly one `POST /api/recheck` with `{ domain, findingId }` using a 30s `AbortController`; on success render the returned status with a distinct visual state and a timestamp; on network/transport failure, 30s timeout, or non-2xx render a distinct failed state and re-enable; re-activation replaces the prior status display
    - _Requirements: 5.3, 5.4, 5.5, 5.6, 5.7, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

  - [ ] 9.3 Add re-check status styles to `public/styles.css`
    - Add visually distinct `.recheck-status` classes for pending, resolved, unresolved, indeterminate, and failed states
    - _Requirements: 5.5, 6.1, 6.2, 6.3_

  - [ ]* 9.4 Write jsdom DOM tests for the frontend re-check control
    - Recheckable vs non-recheckable rendering; single request with correct body on activation; no-domain unavailable path; pending/disabled state and independence across cards; resolved/unresolved/indeterminate/failed states each distinct; timestamp rendered; re-activation replaces prior status; request hits `/api/recheck` not `/api/scan`
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

- [ ] 10. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional test sub-tasks and can be skipped for a faster MVP, but they validate the correctness properties and HTTP/DOM contracts and are recommended.
- Each task references specific requirements (granular clauses) for traceability.
- Property-based tests use `fast-check` with a minimum of 100 iterations, dependency injection on the orchestrator, and the tag format `Feature: finding-recheck, Property {number}: {property_text}`.
- Properties 1–8 from the design are each implemented by exactly one property-based test, placed close to the code they validate (router predicates in task 3, orchestrator in task 4, chat in task 7).
- Checkpoints provide incremental validation between the router, backend, and frontend layers.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "3.2", "3.3", "3.4"] },
    { "id": 3, "tasks": ["3.5", "4.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "4.4", "4.5", "6.1", "6.2"] },
    { "id": 5, "tasks": ["6.3", "7.1"] },
    { "id": 6, "tasks": ["7.2"] },
    { "id": 7, "tasks": ["7.3", "7.4", "7.5", "9.1"] },
    { "id": 8, "tasks": ["9.2", "9.3"] },
    { "id": 9, "tasks": ["9.4"] }
  ]
}
```
