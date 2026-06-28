# Design Document

## Overview

The finding-recheck feature lets a user re-verify a single previously reported BreachLens
finding — without re-running the whole scan — from two entry points: a **Re-check** button on
each finding card, and a natural-language request in the existing chat. Both paths must produce
the same answer for the same observable target state (Requirement 9), so the design is built
around a **single shared `Recheck_Router`** module that is the only place a `Recheck_Status` is
ever computed.

The core idea is a clean split between **pure decision logic** and **impure I/O**:

- A `Finding_Id` is mapped to a *route* — which passive check(s) to run plus a **pure predicate**
  that turns the observed target state into a `Recheck_Status` (`resolved` / `unresolved` /
  `indeterminate`).
- The router's orchestrator performs the I/O (reusing the existing primitives in
  `lib/checks.js`), enforces per-request and overall timeouts, and forces `indeterminate` on any
  failure, timeout, or unrecognized id.

This separation keeps the feature honest (we never claim "fixed" when we actually couldn't tell),
keeps it small (re-uses existing checks), keeps it consistent (one router for both paths), and
makes the decision logic an excellent property-based-testing target because the predicates are
pure, total, deterministic functions.

Scope is kept pragmatic for a hackathon:

- One new backend module (`lib/recheck.js`) and one new endpoint (`recheck.js`).
- A controlled new capability in `chat.js` that delegates status computation to the same router
  and otherwise preserves the existing strict read-only behavior.
- Client state stays entirely in the browser (no server-side persistence), consistent with the
  rest of BreachLens.

### Requirements coverage map

| Area | Requirements |
| --- | --- |
| `POST /api/recheck` endpoint, method/timeout handling | 1, 2 |
| Finding-to-check mapping + resolution predicates | 3 |
| Indeterminate / failure honesty | 4 |
| Re-check control on each card | 5 |
| Card result rendering + timestamp | 6 |
| Chat recheck-intent recognition | 7 |
| Chat recheck reporting | 8 |
| Button/chat consistency via shared router | 9 |

## Architecture

```mermaid
flowchart TD
  subgraph Client[public/app.js]
    Card[Finding card + Re-check control]
    Chat[Chat input]
  end

  subgraph Edge[Netlify Functions v2]
    RecheckFn[recheck.js\nPOST /api/recheck]
    ChatFn[chat.js\nPOST /api/chat]
  end

  subgraph Shared[lib/recheck.js — Recheck_Router]
    Route[routeFor(findingId)\npure classifier]
    Decide[decide(observation)\npure predicates]
    Orchestrate[recheckFinding()\nI/O + timeouts + error→indeterminate]
  end

  Checks[lib/checks.js\ncheckDns / checkSsl / checkHeaders /\ncheckRobotsSitemap / analyzeCookies /\nanalyzeMixedContent / checkFileStatus]

  Card -->|"{domain, findingId}"| RecheckFn
  Chat -->|message + report| ChatFn
  RecheckFn --> Orchestrate
  ChatFn -->|intent resolves to 1 findingId| Orchestrate
  Orchestrate --> Route
  Orchestrate --> Decide
  Orchestrate --> Checks
  Orchestrate -->|"{findingId, status, message}"| RecheckFn
  Orchestrate -->|"{findingId, status, message}"| ChatFn
```

Both server entry points are thin wrappers. They are responsible only for transport concerns
(HTTP method, JSON parsing, validation, response shaping, and — for chat — intent resolution).
Neither computes a `Recheck_Status`; both call `recheckFinding()` (Requirement 9.2).

### Why a shared module rather than calling the endpoint from chat

`chat.js` could HTTP-call `/api/recheck`, but importing the same in-process module is simpler,
faster (helps the 5-second budget in Requirement 8.6), avoids a second cold start, and makes the
"single shared implementation" guarantee structural rather than conventional.

## Components and Interfaces

### 1. `netlify/functions/lib/recheck.js` (Recheck_Router — new)

The single source of truth. Exposes pure helpers (used by tests and the chat path) and the async
orchestrator (used by both server paths).

```js
// Status enum — the only three values a recheck can yield.
export const STATUS = { RESOLVED: "resolved", UNRESOLVED: "unresolved", INDETERMINATE: "indeterminate" };

// Pure: classify a Finding_Id into a route, or null if Non_Recheckable.
// No I/O. Used by the orchestrator AND mirrored (separately) on the client for affordance.
export function routeFor(findingId) { /* returns { family, check, decide, describe, path? } | null */ }

// Pure: is this id recheckable at all? (routeFor(id) !== null)
export function isRecheckable(findingId) { ... }

// Async orchestrator — the ONLY place status is computed end to end.
// `deps` allows injecting check implementations for tests; defaults to lib/checks.js.
export async function recheckFinding({ domain, findingId }, deps = defaultDeps) {
  // -> { findingId, status, message }   (message <= 500 chars)
}
```

Internal structure — a **mapping table** keyed by id family. Each entry has:

- `match(findingId)` — exact string or prefix test.
- `run(domain, deps)` — async; performs the mapped check(s) under a per-request timeout and
  returns a **normalized observation** with an explicit `reachable`/`ok` flag, or a failure
  sentinel `{ ok: false }`.
- `decide(observation)` — **pure, total** function returning a `STATUS` value.
- `describe(status, observation)` — builds the human-readable message (≤ 500 chars).

`recheckFinding` flow:

1. `route = routeFor(findingId)`.
2. If `route === null` → return `{ findingId, status: INDETERMINATE, message: "This finding can't be automatically re-checked." }` **without invoking any check** (Requirements 1.7, 2.6, 3.10, 3.12).
3. Otherwise run `route.run(domain, deps)` wrapped in `withTimeout(...)`; on throw/timeout the observation is the failure sentinel.
4. `status = route.decide(observation)` (sentinel → `INDETERMINATE`).
5. Wrap the whole thing so any unexpected error resolves to `INDETERMINATE` (Requirement 4.5).
6. Return `{ findingId, status, message }`.

#### Finding-to-check mapping table (Requirement 3)

| Finding_Id (family) | Check(s) used | `resolved` when | `unresolved` when | `indeterminate` when |
| --- | --- | --- | --- | --- |
| `spf-missing` | `checkDns` | `dns.spf === true` | `dns.spf === false` | DNS lookup fails/times out (3.13) |
| `dmarc-missing` | `checkDns` | `dns.dmarc === true` | `dns.dmarc === false` | DNS lookup fails/times out |
| `caa-missing` | `checkDns` | `dns.caa.status === "present"` | `dns.caa.status === "missing"` | `dns.caa.status === "unknown"` or lookup fails (3.3) |
| `hdr-hsts` / `hdr-csp` / `hdr-xfo` / `hdr-xcto` | `checkHeaders` | mapped header present (`hsts`/`csp`/`xfo`/`xcto` === true) | header absent **and** site reachable | site unreachable / header fetch fails (3.4, 3.13) |
| `ssl-*` (prefix: `ssl-error`, `ssl-expired`, `ssl-expiring`, `ssl-expiring-soon`) | `checkSsl` | cert readable **and** `expiresInDays > 30` | cert readable **and** `expiresInDays <= 30` (incl. expired) | cert cannot be read (`error` set / `expiresInDays === null`) (3.5) |
| `cookie-secure` / `cookie-httponly` / `cookie-samesite` | `checkHeaders` → `analyzeCookies` | reachable **and** corresponding `missing*` list is empty | reachable **and** ≥1 cookie missing the attribute | site unreachable / header fetch fails (3.6, 3.13) |
| `mixed-content` | `checkHeaders` → `analyzeMixedContent` | reachable **and** `count === 0` | reachable **and** `count >= 1` | site unreachable / header fetch fails (3.7, 3.13) |
| `robots-sensitive` | `checkRobotsSitemap` (+ reachability guard) | reachable **and** `sensitiveDisallows.length === 0` | reachable **and** `sensitiveDisallows.length >= 1` | host unreachable / robots fetch fails (3.8, 3.13) |
| `exposed-file-{path}` (prefix) | `checkFileStatus` (status-only) | path **does not** return HTTP 200 | path **still** returns HTTP 200 | request fails/times out (3.9, 3.13) |
| `subdomain-*` (prefix) | none | — | — | always `indeterminate`, no check run (3.10) |
| any other / unrecognized | none | — | — | always `indeterminate`, no check run (3.12) |

Notes:

- **Exposed-file (3.11):** the path is decoded from the id as `findingId.slice("exposed-file-".length)`.
  `checkFileStatus` issues a `GET` with `redirect: "manual"`, inspects **only** `res.status`, and
  **never** calls `res.text()`/`res.body` — mirroring the ethical status-only design already used by
  `checkSensitiveFiles` in `lib/checks.js`.
- **Reachability guard for robots:** `checkRobotsSitemap` swallows network errors and returns an
  empty result, which would otherwise look (falsely) like `resolved`. The router therefore treats a
  total connectivity failure as the failure sentinel so robots failures map to `indeterminate`
  rather than a false `resolved` (Requirement 3.13, 4.1). Pragmatically this is done by having
  `run` detect that the underlying fetch threw / timed out and emit `{ ok: false }`.
- **Header-family "unreachable":** `checkHeaders` already returns `reachable: false` + `error` when
  the site can't be fetched over HTTPS; the header/cookie/mixed-content predicates return
  `indeterminate` when `reachable === false`.

#### Timeouts (Requirements 1.8, 3.13, 3.14, 4.2)

- **Overall:** `recheckFinding` is wrapped in `withTimeout(promise, 30000, timeoutResult)`; on the
  30 s cap it yields `{ findingId, status: INDETERMINATE, message: "The re-check timed out — please try again." }` (Requirement 1.8).
- **Per check (re-using `withTimeout`):** DNS 6 s, SSL 8 s, headers 9 s, robots 6 s, status-only file
  probe 6 s — each ≤ the 10 s per-request cap (Requirements 3.14, 4.2). Subdomain enumeration is
  never invoked because subdomain findings are non-recheckable. Exceeding any per-check budget
  produces the failure sentinel → `indeterminate`.

### 2. `netlify/functions/recheck.js` (Recheck_Service — new)

Thin HTTP wrapper, structured exactly like `scan.js`/`chat.js` (shared `CORS` const, `json`
helper).

```
OPTIONS                      -> 204 + CORS
non-POST/OPTIONS             -> 405 (Req 1.5, 1.6)
body not JSON                -> 400 "could not parse JSON" (Req 2.1)
domain missing/invalid       -> 400 (after normalizeDomain + isValidDomain) (Req 2.2, 2.4)
findingId missing/>256 chars -> 400 (Req 2.3)
otherwise                    -> 200 { findingId, status, message } from recheckFinding()
```

Validation order is strict (Requirement 2.5): **parse body → validate domain → validate findingId
→ return on first failure**, then route. Note that a Non_Recheckable or unrecognized id is **not** a
400 — it is a valid request that returns `200` + `indeterminate` (Requirements 1.7, 2.6). The
function never throws to the caller; any unexpected error becomes `200` + `indeterminate`
(Requirement 4.5).

A redirect is added to `netlify.toml` (before the `/*` SPA fallback):

```toml
[[redirects]]
  from = "/api/recheck"
  to = "/.netlify/functions/recheck"
  status = 200
```

### 3. `netlify/functions/chat.js` (Chat_Service — modified)

The chat path gains a recheck-intent stage **before** the existing read-only answer path. The
existing behavior is fully preserved for non-recheck messages (Requirement 7.6).

Flow:

1. Parse body (`message`, `report`, `scan`, `history`) as today. Resolve `domain = report.domain || scan.domain`.
2. **Intent + finding resolution** via a single structured LLM JSON call (`callLLMJson`) that is
   given the user message plus the list of existing findings (`id` + `title` only). It returns
   `{ recheck: boolean, findingIds: string[] }`. Server-side we **intersect** the returned ids with
   the ids actually present in `report.findings`, discarding any the model invented — this enforces
   "resolve to an existing finding" (Requirement 7.2) and means the model can never fabricate a
   target. A deterministic keyword fallback (`re-check`, `recheck`, `is … fixed`, `did … get fixed`,
   `check … again`, `verify …`) is used if the LLM call fails, so chat degrades gracefully.
3. Branch on the resolved set:
   - `recheck === false` → existing read-only report-context answer (Requirement 7.6).
   - recheck, **0** matching existing findings → reply "I don't see a matching finding in this
     report to re-check." No router, no check (Requirement 7.3).
   - recheck, **>1** matching findings → reply listing the candidates by `Finding_Id`, asking the
     user to pick one. No router, no check (Requirement 7.5).
   - recheck, **exactly 1** finding that is **Non_Recheckable** (`isRecheckable(id) === false`) →
     reply "That finding can't be automatically re-checked." No router, no check, no fabricated
     status (Requirement 7.4).
   - recheck, **exactly 1** Recheckable finding → call `recheckFinding({ domain, findingId })`
     (Requirement 7.1), then compose the outcome reply **deterministically** from the returned
     status (see below). No second LLM call is needed, which guarantees the status statement is
     based only on the router result (Requirement 8.3) and is returned well within 5 s of receiving
     the status (Requirement 8.6).
4. Outcome reply templating (Requirement 8):
   - `resolved` → "…is now **resolved**."
   - `unresolved` → "…is **still present**."
   - `indeterminate` → "…**could not be confirmed**. You can ask me to re-check it again." (Requirement 8.4)
   - The reply names the finding by both `Finding_Id` and its human-readable `title` (Requirement 8.2).
   - If `recheckFinding` returns nothing / throws (router unavailable) → "I couldn't complete that
     re-check. Please ask me to try again." and the finding's stored state is left unchanged
     (Requirement 8.5). Chat is stateless server-side, so "leave stored state unchanged" simply
     means we do not emit a status statement.

Because the chat path only **reads** the report to resolve which finding to re-check and then
delegates to the shared router, it does not infer resolution from stale report context
(Requirement 8.3) and remains otherwise read-only.

### 4. `public/app.js` (Frontend_App — modified)

#### Recheckability on the client

The client mirrors the router's classifier with a small local `isRecheckable(id)` function (same
family rules as the table above). Drift is **safe**: even if the client mis-classifies an id as
recheckable, the server returns `200` + `indeterminate` with the "can't be automatically
re-checked" message, so the worst case is an honest indeterminate, never a wrong answer. The
router remains authoritative.

#### Re-check control in `renderFindings`

Each finding card gains a footer row:

- **Recheckable finding** → an activatable `Re-check` button plus a status slot.
- **Non_Recheckable finding** → a disabled, non-activatable control labeled e.g. "Can't auto
  re-check" that never sends a request (Requirements 5.1, 5.2).

Per-card state is tracked in a `Map` keyed by `Finding_Id` (`recheckState[id] = { phase, message, checkedAt }`),
so cards are fully independent (Requirements 5.6, 6.x).

Activation handler:

1. If `!state.domain` → show "Re-check unavailable" on that card, send nothing (Requirement 5.4).
2. Else set that card to **pending**, disable **only that card's** button (Requirements 5.5, 6.4),
   leaving all other cards activatable (Requirement 5.6).
3. `POST /api/recheck` with `{ domain: state.domain, findingId: id }` — exactly one request
   (Requirement 5.3) — using an `AbortController` with a **30 s** client timeout (Requirement 6.5).
4. On success → render the returned `status` (resolved / unresolved / indeterminate) with a
   visually distinct state and a **timestamp** of when the re-check ran (Requirements 6.1, 6.2,
   6.3, 6.7). Re-enable the button.
5. On network/transport failure, 30 s timeout, or non-2xx response → render a distinct **failed**
   state and re-enable the button (Requirements 6.5, 6.6).
6. Re-activating replaces the previous status display with the new outcome (Requirement 6.8).

Visual phases (each visually distinct per Requirements 6.1–6.3, plus pending and failed):
`idle` → `pending` → one of {`resolved`, `unresolved`, `indeterminate`, `failed`}. New CSS classes
(`.recheck-status.is-resolved` etc.) are added to `styles.css`; no `index.html` change is needed
because cards are built dynamically.

### 5. `netlify/functions/lib/checks.js` (modified — small addition)

Add a single status-only helper reused by the exposed-file route (kept here for consistency with
the existing `checkSensitiveFiles` ethic of never reading the body):

```js
// Status-only probe of ONE path. Never reads/stores/returns the body (Req 3.11).
export async function checkFileStatus(domain, path) {
  try {
    const res = await fetch(`https://${domain}${path}`, {
      method: "GET", redirect: "manual",
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(6000),
    });
    return { reachable: true, status: res.status, exposed: res.status === 200 };
  } catch (_) {
    return { reachable: false, status: null, exposed: false };
  }
}
```

## Data Models

### RecheckRequest (HTTP request body)

```ts
{ domain: string,     // raw user/client domain; normalized server-side
  findingId: string } // stable Finding_Id, 1..256 chars
```

### RecheckResult (HTTP 200 body / router return value)

```ts
{ findingId: string,   // echoes the requested id (Req 1.3)
  status: "resolved" | "unresolved" | "indeterminate",  // exactly one (Req 1.2)
  message: string }     // human-readable, <= 500 chars (Req 1.4)
```

### RecheckError (HTTP 400/405 body)

```ts
{ error: string }   // validation/method failures only; never used for indeterminate
```

### Normalized observation (internal to the router)

A per-family object carrying the minimal signal plus an explicit reachability flag, e.g.:

```ts
// DNS-backed families
{ ok: true, spf: boolean, dmarc: boolean, caa: { status: "present"|"missing"|"unknown" } } | { ok: false }
// header/cookie/mixed-content families
{ ok: true, reachable: boolean, hsts/csp/xfo/xcto?: boolean, cookies?: {...}, mixed?: { count: number } } | { ok: false }
// ssl family
{ ok: true, expiresInDays: number|null, error: string|null } | { ok: false }
// exposed-file family
{ ok: true, reachable: boolean, status: number|null } | { ok: false }
```

The failure sentinel `{ ok: false }` (or `reachable: false`) is what every `decide` maps to
`indeterminate`.

### Client per-card recheck state

```ts
recheckState: Map<FindingId, {
  phase: "idle" | "pending" | "resolved" | "unresolved" | "indeterminate" | "failed",
  message: string,
  checkedAt: number | null   // epoch ms, rendered as local date/time (Req 6.7)
}>
```

This state lives only in the browser, consistent with BreachLens having no server-side persistence.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a
system — essentially, a formal statement about what the system should do. Properties serve as the
bridge between human-readable specifications and machine-verifiable correctness guarantees.*

The `Recheck_Router` is the natural property-based-testing target: its decision logic (`routeFor`
and the per-family `decide` predicates) is **pure, total, and deterministic**, and the orchestrator
(`recheckFinding`) is exercised with **injected check dependencies** so I/O, timeouts, and failures
can be simulated deterministically without real network calls. The HTTP method/validation rules,
all frontend rendering behavior, and the timing/timeout configuration are covered by example and
edge-case tests in the Testing Strategy (they do not vary meaningfully across 100+ generated inputs).

### Property 1: Re-check result always satisfies the result contract

*For any* `Finding_Id` (including arbitrary, malformed, and well-formed family ids) and *any*
observation outcome, the value returned by `recheckFinding` SHALL have `status` ∈
{`resolved`, `unresolved`, `indeterminate`}, SHALL echo back the requested `findingId` unchanged,
and SHALL include a non-empty `message` whose length does not exceed 500 characters.

**Validates: Requirements 1.2, 1.3, 1.4**

### Property 2: Non-recheckable and unrecognized ids yield indeterminate without running any check

*For any* `Finding_Id` that is not a recognized recheckable family (every `subdomain-*` id and every
otherwise-unrecognized string), `recheckFinding` SHALL return `status === "indeterminate"` and SHALL
invoke none of the passive check dependencies.

**Validates: Requirements 1.7, 2.6, 3.10, 3.12**

### Property 3: Each recheckable family maps to the correct check and resolution predicate

*For any* recheckable `Finding_Id` family and *any* generated successful observation for that family,
`recheckFinding` SHALL invoke exactly the mapped check(s) for that family and SHALL return the
`Recheck_Status` dictated by that family's documented truth table — specifically: SPF/DMARC resolve
when the record is present and are unresolved when absent; CAA resolves on `present`, is unresolved
on `missing`, and is indeterminate on `unknown`; each `hdr-*` resolves when its header is present and
is unresolved when absent; `ssl-*` resolves when the certificate is readable and expires in more
than 30 days and is unresolved when readable but expiring within 30 days or expired; each `cookie-*`
resolves when no cookie is missing the corresponding attribute and is unresolved otherwise;
`mixed-content` resolves when zero insecure references are present and is unresolved otherwise;
`robots-sensitive` resolves when no sensitive disallow entry is present and is unresolved otherwise;
`exposed-file-{path}` resolves when the path no longer returns HTTP 200 and is unresolved when it
still returns HTTP 200.

**Validates: Requirements 1.1, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9**

### Property 4: Any check failure, unreachability, or error yields indeterminate

*For any* recheckable `Finding_Id`, when the mapped check dependency fails, is unreachable, times
out, or throws an arbitrary error, `recheckFinding` SHALL return `status === "indeterminate"` and
SHALL NOT return `resolved` or `unresolved`.

**Validates: Requirements 3.13, 4.1, 4.5, 9.4**

### Property 5: Exposed-file re-checks inspect only the HTTP status code and never the body

*For any* `exposed-file-{path}` `Finding_Id`, the exposed-file route SHALL read only the HTTP status
code of the probe response and SHALL NOT read, store, or return the response body (verified with a
response double whose body accessors record or reject any access).

**Validates: Requirements 3.11**

### Property 6: Chat intent resolution never targets a fabricated finding

*For any* set of candidate `Finding_Id`s produced by the intent-resolution step and *any* current
report, the set of ids the chat path resolves to SHALL be a subset of the `Finding_Id`s actually
present in that report (ids not present in the report are discarded before the router is invoked).

**Validates: Requirements 7.2**

### Property 7: Chat outcome replies are templated faithfully from the router status

*For any* re-checked finding (its `Finding_Id` and human-readable title) and *any* `Recheck_Status`
returned by the router, the chat outcome reply SHALL contain the status wording mandated for that
value ("resolved" for `resolved`, "still present" for `unresolved`, "could not be confirmed" for
`indeterminate`) and SHALL contain both the finding's `Finding_Id` and its human-readable title.

**Validates: Requirements 8.1, 8.2**

### Property 8: Status is a deterministic, path-independent function of the inputs

*For any* `Finding_Id` and *any* fixed observation/injected dependencies, two evaluations of the
router — including one simulating the Re-check-button path and one simulating the chat path — SHALL
produce identical `Recheck_Status` values, regardless of invocation order or which path invoked it.

**Validates: Requirements 9.1, 9.2, 9.3**

## Error Handling

The guiding principle (Requirement 4) is **honesty over optimism**: when the system cannot
confidently confirm a fix, it reports `indeterminate` rather than guessing.

### Backend — `recheck.js`

- **Method errors:** non-POST/OPTIONS → `405`; `OPTIONS` → `204` with CORS (Requirements 1.5, 1.6).
- **Parse errors:** unparseable body → `400 { error }`, no check run (Requirement 2.1).
- **Validation errors:** missing/invalid domain → `400`; missing/empty/over-256-char `findingId` →
  `400`; evaluated strictly in order body → domain → findingId, returning on first failure
  (Requirements 2.2–2.5).
- **Non-recheckable / unrecognized id:** this is **not** an error — it returns `200` with
  `indeterminate` (Requirements 1.7, 2.6).
- **Unexpected errors:** the entire handler body runs inside a try/catch that converts any thrown
  error into `200 { findingId, status: "indeterminate", message }` so no unhandled error reaches the
  caller (Requirement 4.5).

### Backend — `lib/recheck.js`

- Each mapped check runs under `withTimeout` at its per-check budget (DNS 6 s, SSL 8 s, headers 9 s,
  robots 6 s, status-only 6 s), all within the 10 s per-request cap (Requirements 3.14, 4.2).
- The whole `recheckFinding` call runs under an overall 30 s `withTimeout`; exceeding it yields
  `indeterminate` with a timed-out message (Requirement 1.8).
- Any check that throws, times out, or signals unreachability collapses to the `{ ok: false }`
  failure sentinel, which every `decide` maps to `indeterminate` (Requirements 3.13, 4.1).
- Indeterminate messages explicitly say the result could not be confirmed and invite a retry
  (Requirement 4.3). The router is stateless, so an indeterminate result simply returns
  `indeterminate` and changes nothing (Requirement 4.4 on the server side).

### Backend — `chat.js`

- If intent resolution (LLM) fails, fall back to deterministic keyword matching so chat still works.
- Router unavailable / throws / returns nothing → "couldn't complete that re-check, please ask again"
  and no status statement is emitted; stored finding state is left unchanged (Requirement 8.5).
- Zero / multiple / non-recheckable matches are handled as conversational replies, never as errors,
  and never invoke the router or a check (Requirements 7.3, 7.4, 7.5).

### Frontend — `app.js`

- No current domain → no request, card shows "Re-check unavailable" (Requirement 5.4).
- Network/transport failure or 30 s client timeout (`AbortController`) → card shows a distinct
  **failed** state and re-enables its button (Requirement 6.5).
- Non-2xx HTTP response → same **failed** state and re-enable (Requirement 6.6).
- Per-card state is isolated, so one card's failure or pending state never affects another
  (Requirements 5.6, 6.x).

## Testing Strategy

A dual approach is used: **property-based tests** for the pure/deterministic router logic, and
**example/edge unit tests** for HTTP contracts, timing/timeout configuration, chat orchestration
branching, and DOM rendering.

### Property-based tests (router logic)

- **Library:** `fast-check` with the existing test runner (Vitest/Jest-style). PBT is **not**
  implemented from scratch.
- **Iterations:** each property test runs a minimum of **100** generated cases.
- **Tagging:** each property test references its design property using the format
  `Feature: finding-recheck, Property {number}: {property_text}`.
- **Mapping:** Properties 1–8 above are each implemented by a **single** property-based test.
  Generators include: arbitrary strings + constructed valid family ids (P1, P2); per-family
  observation generators with boundary values such as SSL `expiresInDays` ∈ {…, -1, 0, 30, 31, …}
  and cookie/mixed-content/robots counts including 0 (P3); throwing/timing-out/unreachable dependency
  doubles (P4); generated `exposed-file-{path}` ids with a body-access-tracking response double
  (P5); arbitrary candidate-id lists crossed with generated report finding sets (P6); arbitrary
  `(findingId, title, status)` triples (P7); arbitrary `(findingId, observation)` pairs evaluated via
  both simulated paths (P8).
- **Dependency injection:** the orchestrator accepts injected check implementations (`deps`) so all
  property tests run fully in-memory with no real network access, keeping 100+ iterations cheap.

### Example and edge-case unit tests

- **Endpoint contract (`recheck.js`):** method handling (405/204), JSON parse failure (400),
  domain/findingId validation including the 256-char boundary (255/256/257) and domain normalization,
  and validation ordering (Requirements 1.5, 1.6, 2.1–2.5).
- **Timeouts:** with fake timers, a never-resolving injected check yields `indeterminate` at the
  per-check budget and at the 30 s overall cap (Requirements 1.8, 3.14, 4.2).
- **Indeterminate messaging:** message content asserts the "could not confirm / retry" wording
  (Requirement 4.3).
- **Chat orchestration (`chat.js`):** with the intent step stubbed, verify each branch — non-recheck
  (read-only path, router not called), zero match, multiple match, non-recheckable single match, and
  recheckable single match (router called) — plus router-unavailable and the "status overrides stale
  context" case (Requirements 7.1, 7.3–7.6, 8.3, 8.4, 8.5, 8.6, 9.2).
- **Frontend (`app.js`) DOM tests** (jsdom): recheckable vs non-recheckable control rendering; single
  request on activation with correct body; no-domain unavailable path; pending/disabled state and
  independence of other cards; resolved/unresolved/indeterminate/failed visual states each distinct;
  timestamp rendered; re-activation replaces prior status; recheck hits `/api/recheck` not
  `/api/scan` (Requirements 5.1–5.7, 6.1–6.8).
