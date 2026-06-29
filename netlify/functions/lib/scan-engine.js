// Passive Scan Engine — orchestrates every no-authentication, observation-only
// security check against a Target_Domain and aggregates each Check's outcome into
// a single structured Scan_Result.
//
// This module owns the orchestration contract (concurrency, per-check timeouts,
// status derivation, progress ordering, bounded completion, and the DNS-resolution
// gate). It composes the passive network primitives in `lib/checks.js` via an
// injected `deps` object so the orchestration logic stays pure-ish and testable
// without touching the real network.

import {
  checkDns,
  lookupCaa,
  checkSsl,
  checkSubdomains,
  checkHeaders,
  checkRobotsSitemap,
  checkSensitiveFiles,
  inferProvider,
  analyzeCookies,
  analyzeMixedContent,
  fingerprintTech,
  withTimeout,
} from "./checks.js";

// Status enum — the only three values a Check_Outcome can carry.
export const CHECK_STATUS = {
  SUCCESS: "success", // ran successfully, >= 1 finding
  EMPTY: "empty", // ran successfully, 0 findings
  UNAVAILABLE: "unavailable", // could not run / complete (error or timeout)
};

// Distinct top-level result discriminator.
export const RESULT_TYPE = {
  SCAN: "scan", // a full Scan_Result
  RESOLUTION_FAILURE: "resolution_failure", // DNS could not resolve the domain
};

// The canonical list of defined checks (Requirement 1.3).
export const CHECK_IDS = [
  "dns",
  "caa",
  "tls",
  "subdomains",
  "headers",
  "cookies",
  "mixed-content",
  "tech",
  "robots",
  "exposed-files",
  "provider",
];

// Per-check timeout budgets (ms). Each value is constrained to the inclusive
// Check_Timeout range [6000, 8000] (Requirement 2.6).
export const CHECK_TIMEOUTS = {
  dns: 7000,
  caa: 7000,
  tls: 7000,
  subdomains: 6000,
  headers: 8000,
  cookies: 8000,
  "mixed-content": 8000,
  tech: 8000,
  robots: 6000,
  "exposed-files": 6000,
  provider: 6000,
};

// Default dependency wiring — the real passive primitives from `lib/checks.js`.
// Tests inject their own `deps` to simulate success/empty/error/hang/timeout
// behaviors entirely in-memory without touching the network.
export const defaultDeps = {
  checkDns,
  lookupCaa,
  checkSsl,
  checkSubdomains,
  checkHeaders,
  checkRobotsSitemap,
  checkSensitiveFiles,
  inferProvider,
  analyzeCookies,
  analyzeMixedContent,
  fingerprintTech,
  withTimeout,
  // API keys / configuration for key-gated paid sources are read from here so
  // tests can control configuration without touching process.env.
  env: {},
};

// ---------------------------------------------------------------------------
// Internal sentinels
// ---------------------------------------------------------------------------
// A check wrapper resolves to one of these markers instead of rejecting, so the
// orchestrator's `Promise.all` over the wrappers can never reject. Both are
// normalized to an `Unavailable` Check_Outcome by `normalizeOutcome`.

// Returned by `withTimeout` when a check exceeds its Check_Timeout.
export const TIMEOUT_SENTINEL = Object.freeze({
  __unavailable: true,
  reason: "timeout",
});

// Returned by a check wrapper's `.catch` when a check throws or rejects. The
// message is sanitized to a human-readable reason (no stack traces / internals).
export const ERROR_SENTINEL = (msg) =>
  Object.freeze({
    __unavailable: true,
    reason: typeof msg === "string" && msg.length > 0 ? msg : "error",
  });

// Returned by the launch phase when a key-gated check has no valid API key
// configured in `deps.env`. The check's paid primitive is NEVER invoked; the
// scan reports the outcome as `Unavailable` with a sanitized reason and never
// substitutes engine-fabricated findings (Requirements 6.1, 6.3).
export const MISSING_KEY_SENTINEL = Object.freeze({
  __unavailable: true,
  reason: "api key not configured",
});

// Structural guard: is `settled` one of the unavailability markers (or a raw
// Error that slipped through)? Reserved strictly for "could not run / complete".
function isUnavailable(settled) {
  return (
    settled instanceof Error ||
    (settled != null &&
      typeof settled === "object" &&
      settled.__unavailable === true)
  );
}

// Read a check's raw observation from its settled slot. A settled wrapper is
// either an unavailability marker (no observation) or a ran-result of the shape
// `{ findings, data }`, where `data` is the raw, UNSTRIPPED observation shared
// during the run. Returns the raw observation object, or `null` when the check
// did not produce one (unavailable / timed out / never settled). Used by the
// DNS-resolution gate to reuse the dns/headers observations the scan already
// gathered, rather than issuing an extra lookup.
function rawObservation(settled) {
  if (settled == null || isUnavailable(settled)) return null;
  if (typeof settled === "object" && settled.data != null && typeof settled.data === "object") {
    return settled.data;
  }
  return null;
}

// The friendly, human-readable Resolution_Failure message — parameterized ONLY
// by the domain. It deliberately carries no Error objects, stack traces, or
// internal reasons (Requirements 5.2, 5.3). Mirrors the existing handler copy.
export function resolutionFailureMessage(domain) {
  return `We couldn't find "${domain}". Double-check the spelling — it may not exist or may not be publicly resolvable.`;
}

// Extract a sanitized, human-readable reason from an unavailability marker.
function unavailableReason(settled) {
  if (settled instanceof Error) {
    return typeof settled.message === "string" && settled.message.length > 0
      ? settled.message
      : "error";
  }
  if (settled != null && typeof settled.reason === "string" && settled.reason.length > 0) {
    return settled.reason;
  }
  return "error";
}

// ---------------------------------------------------------------------------
// Response-body sanitizer
// ---------------------------------------------------------------------------
// The carried-through `data` observation must NEVER retain an HTTP response
// body anywhere in the Scan_Result (Requirements 3.1, 3.2). Several primitives
// legitimately carry a response body INTERNALLY during the run (e.g. the shared
// `headers` fetch hands its `body` to the dependent mixed-content / tech checks),
// but that body must be discarded before it is stored on a Check_Outcome.
//
// `stripResponseBodies` is PURE: it returns a deep copy of the observation with
// every body/content-like field removed at every depth, preserving all other
// (legitimately useful) fields for the report layer. Input is never mutated.

// Field names that hold a raw response payload. Matched case-insensitively.
const BODY_LIKE_KEYS = new Set([
  "body",
  "content",
  "text",
  "html",
  "responsebody",
  "raw",
]);

export function stripResponseBodies(value) {
  if (Array.isArray(value)) {
    return value.map((v) => stripResponseBodies(v));
  }
  if (value != null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value)) {
      if (BODY_LIKE_KEYS.has(key.toLowerCase())) continue; // drop body-like fields
      out[key] = stripResponseBodies(value[key]);
    }
    return out;
  }
  // Primitives (string/number/boolean/null/undefined) pass through unchanged.
  return value;
}

// ---------------------------------------------------------------------------
// Outcome Normalizer
// ---------------------------------------------------------------------------
// Pure. Maps a settled check (or the timeout/error sentinel) to a Check_Outcome.
//   - sentinel / error               -> { id, status: UNAVAILABLE, findings: [], error }
//   - ran, findings.length > 0       -> { id, status: SUCCESS,     findings, error: null }
//   - ran, findings.length === 0     -> { id, status: EMPTY,       findings: [], error: null }
//
// `settled` is either an unavailability marker (TIMEOUT_SENTINEL / ERROR_SENTINEL /
// raw Error) or a "ran" result of the shape `{ findings: Finding[], data?: object }`
// produced by the resolve phase after applying a check's `toFindings(raw)`.
// An optional `data` field on a ran result is carried through for the report layer.
//
// Requirements: 2.4, 2.5
export function normalizeOutcome(id, settled) {
  // Could not run / complete — error or timeout.
  if (isUnavailable(settled)) {
    return {
      id,
      status: CHECK_STATUS.UNAVAILABLE,
      findings: [],
      error: unavailableReason(settled),
    };
  }

  // Ran successfully — derive Success vs Empty from the findings count.
  const findings = Array.isArray(settled?.findings) ? settled.findings : [];
  const outcome = {
    id,
    status: findings.length > 0 ? CHECK_STATUS.SUCCESS : CHECK_STATUS.EMPTY,
    findings: findings.length > 0 ? findings : [],
    error: null,
  };

  // Carry through optional normalized observation for the report layer, with
  // every HTTP response body / content field stripped at every depth so no body
  // is ever stored in the Scan_Result (Requirements 3.1, 3.2). The full, unstripped
  // observation is still shared INTERNALLY during the run via the scan context;
  // only this FINAL stored copy is body-free.
  if (settled != null && typeof settled === "object" && settled.data !== undefined) {
    outcome.data = stripResponseBodies(settled.data);
  }

  return outcome;
}

// ---------------------------------------------------------------------------
// Shared per-scan context
// ---------------------------------------------------------------------------
// Several checks are derived from a single underlying primitive call rather than
// issuing their own request:
//   - `headers` is fetched ONCE; `cookies`, `mixed-content`, and `tech` reuse the
//     already-fetched headers/body/cookies (preserving the single passive fetch).
//   - `provider` is inferred from the `dns` result's nameservers, so it reuses the
//     same `dns` call rather than re-resolving.
//
// `createScanContext()` returns a fresh per-scan cache. The resolve phase (later
// task) creates one context and threads it through every `run(domain, deps, ctx)`
// call, so each shared primitive is invoked exactly once and its promise reused.
// When a check's `run` is called standalone without a context, a private one-off
// context is created, so the check still works in isolation (e.g. in unit tests).
export function createScanContext() {
  return Object.create(null);
}

// Memoize a shared primitive promise on the context under `key`. The factory is
// invoked at most once per context; subsequent callers await the same promise.
function shared(ctx, key, factory) {
  if (ctx[key] === undefined) {
    ctx[key] = Promise.resolve().then(factory);
  }
  return ctx[key];
}

// ---------------------------------------------------------------------------
// Check Registry
// ---------------------------------------------------------------------------
// Maps each `checkId` to:
//   - run(domain, deps, ctx?) — invokes the underlying passive primitive(s) from
//     `lib/checks.js`, returning that check's raw observation. Dependent checks
//     (cookies/mixed-content/tech, provider) await a shared primitive via `ctx`
//     instead of issuing a new request.
//   - toFindings(raw)         — PURE: derives the findings array used to classify
//     the outcome as Success (>=1) vs Empty (0), per the design's findings table.
//   - timeout                 — the per-check Check_Timeout in ms (from CHECK_TIMEOUTS).
//
// `toFindings` never retains HTTP response bodies. For `exposed-files` it derives
// strictly status-shaped fields (path, status, exposed) — Requirements 3.1, 3.2.
export const CHECK_REGISTRY = {
  // --- DNS / SPF / DMARC --------------------------------------------------
  // Shared with `provider`, which reads this result's nameservers.
  dns: {
    timeout: CHECK_TIMEOUTS.dns,
    run: (domain, deps, ctx = createScanContext()) =>
      shared(ctx, "dns", () => deps.checkDns(domain)),
    // Finding-bearing: SPF present, DMARC present, or notable mail records.
    // Empty: the domain resolves but carries nothing notable.
    toFindings: (raw) => {
      if (!raw || typeof raw !== "object") return [];
      const findings = [];
      if (raw.spf) findings.push({ type: "spf", present: true });
      if (raw.dmarc) findings.push({ type: "dmarc", present: true });
      if (Array.isArray(raw.mx) && raw.mx.length > 0) {
        findings.push({ type: "mx", count: raw.mx.length });
      }
      return findings;
    },
  },

  // --- CAA ----------------------------------------------------------------
  caa: {
    timeout: CHECK_TIMEOUTS.caa,
    run: (domain, deps) => deps.lookupCaa(domain),
    // Finding-bearing: a CAA record is present. Empty: missing (or unknown).
    toFindings: (raw) =>
      raw && raw.status === "present"
        ? [{ type: "caa", records: Array.isArray(raw.records) ? raw.records : [] }]
        : [],
  },

  // --- TLS certificate ----------------------------------------------------
  tls: {
    timeout: CHECK_TIMEOUTS.tls,
    run: (domain, deps) => deps.checkSsl(domain),
    // Finding-bearing: a certificate was successfully read (has a validTo).
    toFindings: (raw) =>
      raw && raw.validTo
        ? [
            {
              type: "tls",
              issuer: raw.issuer ?? null,
              subject: raw.subject ?? null,
              validFrom: raw.validFrom ?? null,
              validTo: raw.validTo,
              expiresInDays: raw.expiresInDays ?? null,
              valid: !!raw.valid,
            },
          ]
        : [],
  },

  // --- Subdomains ---------------------------------------------------------
  subdomains: {
    timeout: CHECK_TIMEOUTS.subdomains,
    run: (domain, deps) => deps.checkSubdomains(domain),
    // Finding-bearing: >=1 discovered subdomain.
    toFindings: (raw) => {
      const subs = raw && Array.isArray(raw.subdomains) ? raw.subdomains : [];
      return subs.map((name) => ({ type: "subdomain", name }));
    },
  },

  // --- HTTP security headers ----------------------------------------------
  // Shared with cookies / mixed-content / tech via the single passive fetch.
  headers: {
    timeout: CHECK_TIMEOUTS.headers,
    run: (domain, deps, ctx = createScanContext()) =>
      shared(ctx, "headers", () => deps.checkHeaders(domain)),
    // Finding-bearing: any security header is present.
    toFindings: (raw) => {
      if (!raw || typeof raw !== "object") return [];
      const SECURITY_HEADERS = [
        "hsts",
        "csp",
        "xfo",
        "xcto",
        "referrerPolicy",
        "permissionsPolicy",
      ];
      return SECURITY_HEADERS.filter((k) => raw[k]).map((header) => ({
        type: "header",
        header,
      }));
    },
  },

  // --- Cookies (dependent: reuses the shared headers fetch) ---------------
  cookies: {
    timeout: CHECK_TIMEOUTS.cookies,
    run: async (domain, deps, ctx = createScanContext()) => {
      const headers = await shared(ctx, "headers", () => deps.checkHeaders(domain));
      const setCookies = headers && Array.isArray(headers.setCookies) ? headers.setCookies : [];
      return deps.analyzeCookies(setCookies);
    },
    // Finding-bearing: any cookie missing a security flag.
    toFindings: (raw) => {
      if (!raw || typeof raw !== "object") return [];
      const findings = [];
      for (const name of raw.missingSecure || []) {
        findings.push({ type: "cookie", name, missing: "secure" });
      }
      for (const name of raw.missingHttpOnly || []) {
        findings.push({ type: "cookie", name, missing: "httponly" });
      }
      for (const name of raw.missingSameSite || []) {
        findings.push({ type: "cookie", name, missing: "samesite" });
      }
      return findings;
    },
  },

  // --- Mixed content (dependent: reuses the shared headers fetch) ---------
  "mixed-content": {
    timeout: CHECK_TIMEOUTS["mixed-content"],
    run: async (domain, deps, ctx = createScanContext()) => {
      const headers = await shared(ctx, "headers", () => deps.checkHeaders(domain));
      const body = headers && typeof headers.body === "string" ? headers.body : "";
      const servedHttps = headers ? !!headers.servedHttps : true;
      return deps.analyzeMixedContent(body, servedHttps);
    },
    // Finding-bearing: >=1 insecure (http://) reference on an HTTPS page.
    toFindings: (raw) =>
      raw && raw.applicable && raw.count > 0
        ? [
            {
              type: "mixed-content",
              count: raw.count,
              samples: Array.isArray(raw.samples) ? raw.samples : [],
            },
          ]
        : [],
  },

  // --- Technology fingerprint (dependent: reuses the shared headers fetch) -
  tech: {
    timeout: CHECK_TIMEOUTS.tech,
    run: async (domain, deps, ctx = createScanContext()) => {
      const headers = await shared(ctx, "headers", () => deps.checkHeaders(domain));
      const server = headers ? headers.server : null;
      const poweredBy = headers ? headers.poweredBy : null;
      const body = headers && typeof headers.body === "string" ? headers.body : "";
      return deps.fingerprintTech(server, poweredBy, body);
    },
    // Finding-bearing: >=1 detected technology.
    toFindings: (raw) => {
      const detected = raw && Array.isArray(raw.detected) ? raw.detected : [];
      return detected.map((name) => ({ type: "tech", name }));
    },
  },

  // --- robots.txt / sitemap.xml -------------------------------------------
  robots: {
    timeout: CHECK_TIMEOUTS.robots,
    run: (domain, deps) => deps.checkRobotsSitemap(domain),
    // Finding-bearing: sensitive Disallow entries, or a sitemap is present.
    toFindings: (raw) => {
      if (!raw || typeof raw !== "object") return [];
      const findings = [];
      for (const path of raw.sensitiveDisallows || []) {
        findings.push({ type: "robots-disallow", path });
      }
      if (raw.sitemapPresent) {
        findings.push({ type: "sitemap", urlCount: raw.sitemapUrlCount ?? null });
      }
      return findings;
    },
  },

  // --- Exposed sensitive files --------------------------------------------
  // IMPORTANT: status-only. toFindings derives ONLY (path, status, exposed) and
  // NEVER retains any response body — Requirements 3.1, 3.2. The underlying
  // checkSensitiveFiles primitive already returns only these fields.
  "exposed-files": {
    timeout: CHECK_TIMEOUTS["exposed-files"],
    run: (domain, deps) => deps.checkSensitiveFiles(domain),
    // Finding-bearing: >=1 path returning HTTP 200 (exposed).
    toFindings: (raw) => {
      const probes = Array.isArray(raw) ? raw : [];
      return probes
        .filter((p) => p && p.exposed)
        .map((p) => ({ path: p.path, status: p.status, exposed: true }));
    },
  },

  // --- Provider inference (dependent: reuses the shared dns result) --------
  provider: {
    timeout: CHECK_TIMEOUTS.provider,
    run: async (domain, deps, ctx = createScanContext()) => {
      const dnsRaw = await shared(ctx, "dns", () => deps.checkDns(domain));
      const nameservers = dnsRaw && Array.isArray(dnsRaw.nameservers) ? dnsRaw.nameservers : [];
      return deps.inferProvider(nameservers);
    },
    // Finding-bearing: a provider was identified (inferProvider returns a name).
    toFindings: (raw) =>
      typeof raw === "string" && raw.length > 0 ? [{ type: "provider", name: raw }] : [],
  },
};

// ---------------------------------------------------------------------------
// Paid / Out-of-Scope Source Gating (Requirements 6.1, 6.2, 6.3)
// ---------------------------------------------------------------------------
// A general, registry-driven mechanism for checks backed by a paid third-party
// source that requires an API key (e.g. domain-level breach data / HIBP, which
// the legacy handler treats as `hibp.available = false`).
//
// A registry entry opts into gating by declaring `requiresKey: "<ENV_KEY_NAME>"`.
// The launch phase consults `keyGateSentinel(entry, deps)` BEFORE calling the
// entry's `run`. When the named key is absent or invalid in the INJECTED
// `deps.env` (never `process.env`, so tests fully control configuration), the
// check is short-circuited to `MISSING_KEY_SENTINEL` — its paid primitive is
// NEVER invoked (Req 6.1) and no findings are fabricated (Req 6.3). When a valid
// key IS present, `keyGateSentinel` returns `null`, so the real primitive runs
// and the outcome is derived from its observation exactly like any other check
// (Req 6.2).
//
// The mechanism is general: none of the current 11 CHECK_IDS declares
// `requiresKey`, so default behavior is unchanged (and result-completeness is
// preserved — no new id is added to CHECK_IDS). A key-gated check is wired by
// (a) declaring `requiresKey` on its registry entry and (b) reading the key from
// `deps.env`. Tests exercise the gate by injecting a `deps.registry` whose entry
// for some check id declares `requiresKey` and a spy `run` primitive.
//
// A key is considered "valid/configured" when `deps.env[requiresKey]` is a
// non-empty string (after trimming). Anything else — missing, undefined, empty,
// or whitespace — is treated as "no valid key" and gates the check.

// PURE. Returns `MISSING_KEY_SENTINEL` when `entry` is key-gated and no valid key
// is configured in `deps.env`; otherwise returns `null` (the check may run).
export function keyGateSentinel(entry, deps) {
  const requiresKey =
    entry && typeof entry.requiresKey === "string" && entry.requiresKey.length > 0
      ? entry.requiresKey
      : null;
  if (!requiresKey) return null; // not a key-gated check — always runs

  const env = deps && deps.env && typeof deps.env === "object" ? deps.env : {};
  const value = env[requiresKey];
  const hasValidKey = typeof value === "string" && value.trim().length > 0;
  return hasValidKey ? null : MISSING_KEY_SENTINEL;
}

// ---------------------------------------------------------------------------
// Launch phase
// ---------------------------------------------------------------------------
// Build one failure-tolerant wrapper per defined check. Every wrapper is created
// synchronously in a single loop BEFORE any `await`, so each check's underlying
// network operation is kicked off immediately and all checks overlap in flight
// (concurrency — Requirement 1.1). A single shared scan context is threaded into
// every `run(domain, deps, ctx)` so the shared `headers`/`dns` primitives fire
// exactly once and dependent checks reuse them.
//
// Each wrapper is guaranteed never to reject (failure isolation — Req 2.1, 2.2):
//   - the raw check promise has a `.catch` → ERROR_SENTINEL(message), so a throw
//     or rejection becomes an unavailability marker carrying a sanitized reason;
//   - that already-safe promise is then bounded by the check's Check_Timeout via
//     `deps.withTimeout(..., TIMEOUT_SENTINEL)`, so a slow check resolves to the
//     timeout marker instead of hanging.
//
// On settle, a wrapper either passes an unavailability marker straight through
// (to be normalized as Unavailable) or applies the registry's pure `toFindings`
// to the raw observation, producing the `{ findings, data }` shape that
// `normalizeOutcome` consumes. `data` carries the raw observation through for the
// report layer.
//
// Returns: Array<{ id, promise }> — one entry per CHECK_IDS, in CHECK_IDS order.
// The promise never rejects; it resolves to an unavailability marker or to a
// `{ findings, data }` ran-result.
function launchChecks(domain, deps, ctx) {
  // The registry may be overridden via `deps.registry` (a test/dep hook) so a
  // check can be configured as key-gated without mutating the module-level
  // CHECK_REGISTRY. Defaults to the real registry. Iteration is always over
  // CHECK_IDS, so result-completeness is preserved regardless of the override.
  const registry = (deps && deps.registry) || CHECK_REGISTRY;
  return CHECK_IDS.map((id) => {
    const entry = registry[id];
    const timeoutMs = (entry && entry.timeout) || CHECK_TIMEOUTS[id];

    // Paid-source key gate (Req 6.1, 6.2, 6.3): if this check is key-gated and no
    // valid API key is configured in `deps.env`, short-circuit to the missing-key
    // sentinel WITHOUT invoking the paid primitive and without fabricating any
    // findings. Otherwise start the check NOW (synchronously) so its underlying
    // op is already in flight before we move on to the next check. A synchronous
    // throw from `run` is normalized into a rejected promise so the shared
    // `.catch` below handles it uniformly.
    const gate = keyGateSentinel(entry, deps);
    let started;
    if (gate) {
      started = Promise.resolve(gate);
    } else {
      try {
        started = Promise.resolve(entry.run(domain, deps, ctx));
      } catch (err) {
        started = Promise.reject(err);
      }
    }

    // Failure isolation: a throw/rejection becomes an ERROR_SENTINEL carrying a
    // sanitized reason, never a rejected promise (Req 2.2).
    const caught = started.catch((err) =>
      ERROR_SENTINEL(err && typeof err.message === "string" ? err.message : "error")
    );

    // Per-check timeout: a check that overruns its Check_Timeout resolves to the
    // timeout marker instead of stalling the scan (Req 2.1).
    const bounded = deps.withTimeout(caught, timeoutMs, TIMEOUT_SENTINEL);

    // On settle: pass unavailability markers through untouched; otherwise apply
    // the pure `toFindings` to derive the findings array and carry the raw
    // observation as `data` for the report layer. A throw inside `toFindings`
    // degrades to Unavailable rather than rejecting.
    const promise = bounded
      .then((settled) => {
        if (isUnavailable(settled)) return settled;
        let findings;
        try {
          findings = entry.toFindings(settled);
        } catch (err) {
          return ERROR_SENTINEL(
            err && typeof err.message === "string" ? err.message : "error"
          );
        }
        return {
          findings: Array.isArray(findings) ? findings : [],
          data: settled,
        };
      })
      .catch((err) =>
        ERROR_SENTINEL(err && typeof err.message === "string" ? err.message : "error")
      );

    return { id, promise };
  });
}

// Main orchestrator.
//   domain: normalized Target_Domain (string)
//   deps:   injected check primitives (defaults to the real lib/checks.js fns)
//   emit:   (Progress_Event) => void   progress callback (defaults to a no-op)
// Returns: Promise<Scan_Result | ResolutionFailure>
//
// LAUNCH + RESOLVE + AGGREGATE phases implemented (tasks 4.1, 4.3, 4.6, 4.8).
// The resolve phase awaits the failure-tolerant wrappers under a global watchdog
// so the whole scan is bounded (Req 2.6) and an unexpected orchestrator error
// still yields a complete result (failure isolation — Req 2.1, 2.2). Progress is
// emitted exactly once per check in resolution order (task 4.6). The aggregate
// phase assembles the final `{ type, domain, scannedAt, outcomes }` Scan_Result
// with exactly one Check_Outcome per CHECK_IDS entry, in CHECK_IDS order — no
// omissions, no duplicates (Req 1.2, 2.3). The DNS-resolution gate (task 6.1) and
// paid-source gating (task 7.1) are layered on in later tasks.
//
// The global watchdog budget is `max(CHECK_TIMEOUTS values) + 2000 ms` — the
// largest per-check Check_Timeout plus the 2-second aggregation allowance
// (Requirement 2.6). It is computed once from the configured timeouts so the
// bound automatically tracks any timeout change.
const WATCHDOG_BUDGET_MS = Math.max(...Object.values(CHECK_TIMEOUTS)) + 2000;

export async function runScan(domain, deps = defaultDeps, emit = () => {}) {
  // One shared context per scan: the shared `headers`/`dns` primitives fire once
  // and dependent checks (cookies/mixed-content/tech, provider) reuse them.
  const ctx = createScanContext();

  // Build all wrappers synchronously (no await yet) so checks overlap in flight.
  const launched = launchChecks(domain, deps, ctx);

  // Per-check settled slots, hoisted above the try so that even an unexpected
  // orchestrator error can still assemble a complete result from whatever has
  // settled so far. `recorded[i]` flips to true the instant wrapper `i` settles.
  const settledSlots = new Array(launched.length).fill(undefined);
  const recorded = new Array(launched.length).fill(false);

  // ---- Progress emission (Req 4.1, 4.2, 4.3) ----------------------------
  // Exactly one Progress_Event is emitted per defined check, in the actual order
  // in which checks resolve. `seq` is a monotonically increasing counter assigned
  // at emission time, so emission order equals resolution order (Req 4.2). The
  // `emittedFor` guard ensures a check that both settles and is later swept by the
  // watchdog (or vice versa) is reported exactly once (Req 4.3).
  let seq = 0;
  const emittedFor = new Array(launched.length).fill(false);

  // A throwing `emit` callback must never break the scan, so every invocation is
  // wrapped — a faulty consumer can't propagate an exception into the orchestrator.
  const safeEmit = (event) => {
    try {
      emit(event);
    } catch {
      // Swallow consumer errors: progress emission is best-effort observability
      // and must not affect scan completion or failure isolation.
    }
  };

  // Emit the single Progress_Event for wrapper `i` from its settled value (or the
  // timeout sentinel when swept while still outstanding). No-op if already emitted.
  const emitProgress = (i, settled) => {
    if (emittedFor[i]) return;
    emittedFor[i] = true;
    const status = normalizeOutcome(launched[i].id, settled).status;
    safeEmit({ type: "progress", check: launched[i].id, status, seq: seq++ });
  };

  try {
    // Attach a per-wrapper settle hook. We await the failure-tolerant wrappers
    // (never the raw check promises), so none of these can reject and the
    // `Promise.all` below can never reject. This `.then` is the single point where
    // per-check progress is emitted: the moment a wrapper settles (in resolution
    // order) we record its value and emit exactly one Progress_Event for it.
    const tracked = launched.map((c, i) =>
      c.promise.then((settled) => {
        settledSlots[i] = settled;
        recorded[i] = true;
        emitProgress(i, settled);
        return settled;
      })
    );

    // Global watchdog: bound the ENTIRE resolve phase to the bounded-completion
    // budget. Even a pathological check that ignores its own Check_Timeout (e.g.
    // one that never resolves) cannot stall the scan past the budget — when the
    // watchdog fires, `withTimeout` resolves to the timeout sentinel and we fall
    // through to aggregation, treating any still-outstanding check as Unavailable.
    await deps.withTimeout(
      Promise.all(tracked),
      WATCHDOG_BUDGET_MS,
      TIMEOUT_SENTINEL
    );
  } catch (err) {
    // Defensive: the wrappers never reject and the watchdog-bounded Promise.all
    // cannot reject, so reaching here means an unexpected orchestrator error.
    // We swallow it and aggregate below — any check that did not record a settled
    // value becomes Unavailable, so the scan still returns a complete result and
    // never throws (Req 2.1, 2.2).
    void err;
  }

  // Watchdog sweep: any check still outstanding when the watchdog fired (or when
  // an unexpected error short-circuited the resolve phase) never settled, so its
  // settle hook never emitted. Emit its single Progress_Event now from the timeout
  // sentinel (Unavailable), preserving exactly-one-event-per-check (Req 4.3). The
  // `emittedFor` guard makes this a no-op for checks that already settled, and any
  // check that settles after this sweep is likewise skipped — never double-emitted.
  for (let i = 0; i < launched.length; i++) {
    if (!emittedFor[i]) {
      emitProgress(i, recorded[i] ? settledSlots[i] : TIMEOUT_SENTINEL);
    }
  }

  // ---- DNS-resolution gate (task 6.1, Req 5.1, 5.2, 5.3) ----------------
  // Evaluated AFTER all checks settle but BEFORE assembling the Scan_Result.
  // The gate reuses the dns/headers observations the scan ALREADY gathered (no
  // extra DNS lookup): it reads `resolves` from the dns check's raw observation
  // and `reachable` from the headers check's raw observation. This mirrors the
  // original handler intent (`!dnsRes.resolves && !hdrRes.reachable`): the domain
  // is a genuine Resolution_Failure only when DNS positively determined it does
  // NOT resolve to a usable address AND the site was unreachable.
  //
  // The real `checkDns` always returns a `resolves` boolean (true when it found
  // A/MX records, false otherwise), so a genuine non-resolving domain surfaces
  // here as `resolves === false`. A dns check that simply could not RUN (errored,
  // timed out, or never settled) yields no observation and is treated as an
  // Unavailable check — not a resolution failure — so the scan still produces a
  // complete Scan_Result rather than masquerading a flaky dependency as a
  // non-existent domain. This keeps the gate firing only on genuine resolution
  // failure.
  const dnsIndex = launched.findIndex((c) => c.id === "dns");
  const headersIndex = launched.findIndex((c) => c.id === "headers");
  const dnsObs = dnsIndex >= 0 ? rawObservation(settledSlots[dnsIndex]) : null;
  const headersObs = headersIndex >= 0 ? rawObservation(settledSlots[headersIndex]) : null;

  // DNS positively reported no usable address (ran, but `resolves === false`).
  const dnsUnresolved = !!(dnsObs && dnsObs.resolves === false);
  // The site responded to the passive homepage fetch (so it IS reachable).
  const siteReachable = !!(headersObs && headersObs.reachable === true);

  // Genuine Resolution_Failure: DNS resolved to nothing AND the site is
  // unreachable. Return the distinct error state instead of a Scan_Result (Req
  // 5.1). The message is the fixed friendly string parameterized only by the
  // domain — no stack traces / internals (Req 5.2, 5.3).
  if (dnsUnresolved && !siteReachable) {
    return {
      type: RESULT_TYPE.RESOLUTION_FAILURE,
      domain,
      message: resolutionFailureMessage(domain),
    };
  }

  // Aggregation (task 4.8): normalize each wrapper's settled value into a
  // Check_Outcome and assemble the final Scan_Result. Any check still outstanding
  // when the watchdog fired (or when an unexpected error short-circuited the
  // resolve phase) is treated as Unavailable via the timeout sentinel. Iterating
  // `launched` (built once per CHECK_IDS, in CHECK_IDS order) guarantees exactly
  // one Check_Outcome per defined check — no omissions, no duplicates, and in
  // CHECK_IDS order (Req 1.2, 2.3). Task 6.1 adds the DNS-resolution gate before
  // this point, and task 7.1 layers in paid-source gating.
  const outcomes = launched.map((c, i) =>
    normalizeOutcome(c.id, recorded[i] ? settledSlots[i] : TIMEOUT_SENTINEL)
  );

  return {
    type: RESULT_TYPE.SCAN,
    domain,
    scannedAt: new Date().toISOString(),
    outcomes,
  };
}
