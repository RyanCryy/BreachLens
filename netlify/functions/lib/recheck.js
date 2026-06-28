// Recheck_Router — the single source of truth for re-verifying ONE finding.
//
// This module is deliberately split into pure decision logic and impure I/O:
//   - `routeFor(findingId)` is a pure, total classifier: it maps a Finding_Id to
//     the route describing which passive check to run plus the pure predicate that
//     turns the observed target state into a Recheck_Status — or `null` when the
//     finding can't be automatically re-checked (Non_Recheckable_Finding).
//   - `recheckFinding()` (task 4.1) is the async orchestrator that performs the I/O,
//     enforces timeouts, and forces `indeterminate` on any failure.
//
// Keeping the classifier pure makes it a clean property-based-testing target and lets
// the client mirror the same family rules for re-check affordance without any I/O.

import {
  checkDns,
  checkSsl,
  checkHeaders,
  checkRobotsSitemap,
  analyzeCookies,
  analyzeMixedContent,
  checkFileStatus,
  withTimeout,
} from "./checks.js";

// Status enum — the only three values a recheck can ever yield.
export const STATUS = {
  RESOLVED: "resolved",
  UNRESOLVED: "unresolved",
  INDETERMINATE: "indeterminate",
};

// Finding_Id prefixes whose suffix is dynamic.
const SSL_PREFIX = "ssl-";
const EXPOSED_FILE_PREFIX = "exposed-file-";
const SUBDOMAIN_PREFIX = "subdomain-";

// Exact security-header ids → the boolean key on the headers observation.
const HEADER_KEYS = {
  "hdr-hsts": "hsts",
  "hdr-csp": "csp",
  "hdr-xfo": "xfo",
  "hdr-xcto": "xcto",
};

// Exact cookie ids → the cookie attribute and the analyzeCookies list that tracks it.
const COOKIE_ATTRS = {
  "cookie-secure": { attr: "secure", missingKey: "missingSecure" },
  "cookie-httponly": { attr: "httponly", missingKey: "missingHttpOnly" },
  "cookie-samesite": { attr: "samesite", missingKey: "missingSameSite" },
};

// ------------------------------------------------------------------
//  Pure decision predicates (per family)
//
//  Each `decide` maps a normalized observation (or the `{ ok: false }` failure
//  sentinel) to a STATUS value. The actual truth-table bodies are implemented in
//  task 3.2 — for now every predicate defaults to INDETERMINATE so the module is
//  importable and total, and `describe` returns a placeholder message. The route
//  table below is structured so 3.2 only has to fill in these function bodies:
//  the discriminating parameters (which header key / which cookie list) are bound
//  into the per-route closures here, so each `decide` still has the pure
//  `decide(observation)` signature.
// ------------------------------------------------------------------

// Hard cap on every outcome message (Requirement 1.4). Any builder output is run
// through `clampMessage` so the contract holds even if a future edit grows a string.
const MAX_MESSAGE_LENGTH = 500;
// Standard invitation appended to every indeterminate message (Requirement 4.3).
const RETRY_HINT = "You can run the re-check again in a moment.";

// Defensive guard shared by every predicate: the failure sentinel `{ ok: false }`,
// a missing observation, or any object that didn't explicitly report `ok === true`
// is treated as "couldn't observe" → INDETERMINATE (Requirements 4.1, 4.5).
function isObserved(observation) {
  return Boolean(observation) && typeof observation === "object" && observation.ok === true;
}

// Families whose check talks to the live site (headers/cookies/mixed-content/robots/
// exposed-file) carry an explicit `reachable` flag. When the site couldn't be reached
// we must NOT guess "fixed" — we report INDETERMINATE (Requirements 3.13, 4.1).
function isReachable(observation) {
  return observation.reachable === true;
}

// SPF (Requirement 3.1): record present → resolved, absent → unresolved, lookup failed → indeterminate.
function decideSpf(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (observation.spf === true) return STATUS.RESOLVED;
  if (observation.spf === false) return STATUS.UNRESOLVED;
  return STATUS.INDETERMINATE;
}

// DMARC (Requirement 3.2): record present → resolved, absent → unresolved, lookup failed → indeterminate.
function decideDmarc(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (observation.dmarc === true) return STATUS.RESOLVED;
  if (observation.dmarc === false) return STATUS.UNRESOLVED;
  return STATUS.INDETERMINATE;
}

// CAA (Requirement 3.3): present → resolved, missing → unresolved, unknown/failed → indeterminate.
function decideCaa(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  const status = observation.caa && observation.caa.status;
  if (status === "present") return STATUS.RESOLVED;
  if (status === "missing") return STATUS.UNRESOLVED;
  // "unknown" and any unexpected value → we couldn't tell.
  return STATUS.INDETERMINATE;
}

// Security header (Requirement 3.4): header present → resolved; absent while the site is
// reachable → unresolved; site unreachable / fetch failed → indeterminate.
// `headerKey` is one of hsts/csp/xfo/xcto; the predicate reads observation[headerKey].
function makeDecideHeader(headerKey) {
  return function decideHeader(observation) {
    if (!isObserved(observation)) return STATUS.INDETERMINATE;
    if (!isReachable(observation)) return STATUS.INDETERMINATE;
    return observation[headerKey] === true ? STATUS.RESOLVED : STATUS.UNRESOLVED;
  };
}

// Cookie attribute (Requirement 3.6): no cookie missing the attribute → resolved; ≥1 cookie
// missing it → unresolved; site unreachable / fetch failed → indeterminate.
// `missingKey` selects the analyzeCookies list (missingSecure/missingHttpOnly/missingSameSite).
function makeDecideCookie(missingKey) {
  return function decideCookie(observation) {
    if (!isObserved(observation)) return STATUS.INDETERMINATE;
    if (!isReachable(observation)) return STATUS.INDETERMINATE;
    const missing = observation.cookies && observation.cookies[missingKey];
    if (!Array.isArray(missing)) return STATUS.INDETERMINATE;
    return missing.length === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED;
  };
}

// Mixed content (Requirement 3.7): zero insecure references → resolved; ≥1 → unresolved;
// site unreachable / fetch failed → indeterminate.
function decideMixedContent(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (!isReachable(observation)) return STATUS.INDETERMINATE;
  const count = observation.mixed && observation.mixed.count;
  if (typeof count !== "number" || Number.isNaN(count)) return STATUS.INDETERMINATE;
  return count === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED;
}

// Sensitive robots.txt disclosures (Requirement 3.8): no sensitive disallow entries → resolved;
// ≥1 → unresolved; host unreachable / fetch failed → indeterminate.
function decideRobots(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (!isReachable(observation)) return STATUS.INDETERMINATE;
  const disallows = observation.sensitiveDisallows;
  if (!Array.isArray(disallows)) return STATUS.INDETERMINATE;
  return disallows.length === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED;
}

// TLS certificate (Requirement 3.5): cert readable & expiresInDays > 30 → resolved;
// readable but expiring within 30 days (incl. 0/expired/negative) → unresolved;
// cert can't be read (error set / expiresInDays === null) → indeterminate. Boundary is strictly > 30.
function decideSsl(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (observation.error) return STATUS.INDETERMINATE;
  const days = observation.expiresInDays;
  if (typeof days !== "number" || Number.isNaN(days)) return STATUS.INDETERMINATE;
  return days > 30 ? STATUS.RESOLVED : STATUS.UNRESOLVED;
}

// Exposed file (Requirement 3.9): path no longer returns HTTP 200 → resolved; still 200 → unresolved;
// request failed / unreachable → indeterminate. Status-only — the observation never carries a body.
function decideExposedFile(observation) {
  if (!isObserved(observation)) return STATUS.INDETERMINATE;
  if (!isReachable(observation)) return STATUS.INDETERMINATE;
  if (observation.status === 200) return STATUS.UNRESOLVED;
  if (typeof observation.status === "number") return STATUS.RESOLVED;
  return STATUS.INDETERMINATE;
}

// ------------------------------------------------------------------
//  Pure message builders (per family)
//
//  Every builder is pure and total, returns a non-empty human-readable string, and is
//  clamped to <= 500 chars (Requirement 1.4). Indeterminate messages are honest about
//  the uncertainty and invite a retry (Requirement 4.3).
// ------------------------------------------------------------------

// Trim any message to the contract length, preserving a non-empty result.
function clampMessage(message) {
  const text = typeof message === "string" && message.length > 0 ? message : "Re-check complete.";
  return text.length > MAX_MESSAGE_LENGTH ? text.slice(0, MAX_MESSAGE_LENGTH) : text;
}

// Shared shape: resolved / unresolved / indeterminate wording for a named condition.
// `resolved` / `unresolved` are full sentences; `indeterminate` gets the retry hint appended.
function describeWith({ resolved, unresolved, indeterminate }) {
  return function describe(status) {
    if (status === STATUS.RESOLVED) return clampMessage(resolved);
    if (status === STATUS.UNRESOLVED) return clampMessage(unresolved);
    return clampMessage(`${indeterminate} ${RETRY_HINT}`);
  };
}

const describeSpf = describeWith({
  resolved: "An SPF record is now published for this domain — the missing-SPF finding looks resolved.",
  unresolved: "Still no SPF record found. Publish a \"v=spf1\" TXT record to authorize your senders and resolve this finding.",
  indeterminate: "The SPF DNS lookup didn't return a clear answer, so this couldn't be confirmed.",
});

const describeDmarc = describeWith({
  resolved: "A DMARC record is now published for this domain — the missing-DMARC finding looks resolved.",
  unresolved: "Still no DMARC record found. Publish a \"v=DMARC1\" TXT record at _dmarc to resolve this finding.",
  indeterminate: "The DMARC DNS lookup didn't return a clear answer, so this couldn't be confirmed.",
});

const describeCaa = describeWith({
  resolved: "A CAA record is now present for this domain — the missing-CAA finding looks resolved.",
  unresolved: "No CAA record is present. Add a CAA record to restrict which CAs may issue certificates and resolve this finding.",
  indeterminate: "The CAA lookup was inconclusive (the resolver couldn't confirm whether a record exists).",
});

// Friendly labels for the security-header families.
const HEADER_LABELS = {
  hsts: "Strict-Transport-Security (HSTS)",
  csp: "Content-Security-Policy",
  xfo: "X-Frame-Options",
  xcto: "X-Content-Type-Options",
};

function makeDescribeHeader(headerKey) {
  const label = HEADER_LABELS[headerKey] || "security header";
  return describeWith({
    resolved: `The ${label} header is now present on the site — this finding looks resolved.`,
    unresolved: `The ${label} header is still missing from the site's HTTPS response. Add it to resolve this finding.`,
    indeterminate: `The site couldn't be reached over HTTPS, so the ${label} header couldn't be confirmed.`,
  });
}

// Friendly labels for the cookie-attribute families.
const COOKIE_LABELS = {
  secure: "Secure",
  httponly: "HttpOnly",
  samesite: "SameSite",
};

function makeDescribeCookie(attr) {
  const label = COOKIE_LABELS[attr] || "the expected";
  return describeWith({
    resolved: `Every cookie now sets the ${label} attribute — this finding looks resolved.`,
    unresolved: `At least one cookie is still missing the ${label} attribute. Add it to all cookies to resolve this finding.`,
    indeterminate: `The site couldn't be reached over HTTPS, so the cookie ${label} attribute couldn't be confirmed.`,
  });
}

const describeMixedContent = describeWith({
  resolved: "No insecure (HTTP) references were found on the HTTPS page — the mixed-content finding looks resolved.",
  unresolved: "Insecure (HTTP) references are still present on the HTTPS page. Switch them to HTTPS to resolve this finding.",
  indeterminate: "The site couldn't be reached over HTTPS, so mixed content couldn't be confirmed.",
});

const describeRobots = describeWith({
  resolved: "No sensitive paths are disclosed in robots.txt — this finding looks resolved.",
  unresolved: "robots.txt still discloses sensitive-looking paths. Remove them (and secure the paths directly) to resolve this finding.",
  indeterminate: "robots.txt couldn't be retrieved, so sensitive disclosures couldn't be confirmed.",
});

const describeSsl = describeWith({
  resolved: "The TLS certificate is readable and valid for more than 30 days — this finding looks resolved.",
  unresolved: "The TLS certificate is expired or expiring within 30 days. Renew it to resolve this finding.",
  indeterminate: "The TLS certificate couldn't be read, so its expiry couldn't be confirmed.",
});

function makeDescribeExposedFile(path) {
  const safePath = typeof path === "string" && path.length > 0 ? path : "the file";
  return describeWith({
    resolved: `"${safePath}" no longer returns HTTP 200 — it appears to no longer be publicly exposed.`,
    unresolved: `"${safePath}" still returns HTTP 200 and appears publicly accessible. Block or remove it to resolve this finding.`,
    indeterminate: `The request for "${safePath}" failed, so its exposure couldn't be confirmed.`,
  });
}

// ------------------------------------------------------------------
//  Pure classifier
// ------------------------------------------------------------------

// Classify a Finding_Id into a route, or return null for a Non_Recheckable_Finding.
//
// A route carries:
//   - family:   the finding family this id belongs to
//   - check:    which passive check primitive to run ("dns" | "ssl" | "headers" | "robots" | "file")
//   - analyze?: secondary pure analysis step run on the headers result ("cookies" | "mixedContent")
//   - decide:   pure (observation) -> STATUS predicate
//   - describe: pure (status, observation) -> message builder
//   - path?:    for exposed-file-{path}, the decoded file path to probe
//   - headerKey?/attr?/missingKey?: discriminators carried for the orchestrator's I/O step
//
// No I/O happens here. `subdomain-*` ids and every unrecognized id return null.
export function routeFor(findingId) {
  if (typeof findingId !== "string" || findingId.length === 0) return null;

  // --- DNS-backed families (exact ids) ---
  if (findingId === "spf-missing") {
    return { family: "spf", check: "dns", decide: decideSpf, describe: describeSpf };
  }
  if (findingId === "dmarc-missing") {
    return { family: "dmarc", check: "dns", decide: decideDmarc, describe: describeDmarc };
  }
  if (findingId === "caa-missing") {
    return { family: "caa", check: "dns", decide: decideCaa, describe: describeCaa };
  }

  // --- Security headers (exact ids) ---
  if (Object.prototype.hasOwnProperty.call(HEADER_KEYS, findingId)) {
    const headerKey = HEADER_KEYS[findingId];
    return {
      family: "header",
      check: "headers",
      headerKey,
      decide: makeDecideHeader(headerKey),
      describe: makeDescribeHeader(headerKey),
    };
  }

  // --- Cookie attributes (exact ids) — headers fetch followed by cookie analysis ---
  if (Object.prototype.hasOwnProperty.call(COOKIE_ATTRS, findingId)) {
    const { attr, missingKey } = COOKIE_ATTRS[findingId];
    return {
      family: "cookie",
      check: "headers",
      analyze: "cookies",
      attr,
      missingKey,
      decide: makeDecideCookie(missingKey),
      describe: makeDescribeCookie(attr),
    };
  }

  // --- Mixed content (exact id) — headers fetch followed by mixed-content analysis ---
  if (findingId === "mixed-content") {
    return {
      family: "mixed-content",
      check: "headers",
      analyze: "mixedContent",
      decide: decideMixedContent,
      describe: describeMixedContent,
    };
  }

  // --- Sensitive robots.txt disclosures (exact id) ---
  if (findingId === "robots-sensitive") {
    return { family: "robots", check: "robots", decide: decideRobots, describe: describeRobots };
  }

  // --- TLS certificate (prefix: ssl-error, ssl-expired, ssl-expiring, ssl-expiring-soon, ...) ---
  if (findingId.startsWith(SSL_PREFIX)) {
    return { family: "ssl", check: "ssl", decide: decideSsl, describe: describeSsl };
  }

  // --- Exposed file (prefix: exposed-file-{path}) — status-only probe of the single path ---
  if (findingId.startsWith(EXPOSED_FILE_PREFIX)) {
    const path = findingId.slice(EXPOSED_FILE_PREFIX.length);
    return {
      family: "exposed-file",
      check: "file",
      path,
      decide: decideExposedFile,
      describe: makeDescribeExposedFile(path),
    };
  }

  // --- Subdomain exposure is explicitly Non_Recheckable (no single passive re-check) ---
  if (findingId.startsWith(SUBDOMAIN_PREFIX)) return null;

  // Anything else is unrecognized → Non_Recheckable.
  return null;
}

// Is this Finding_Id recheckable at all? (routeFor(id) !== null)
export function isRecheckable(findingId) {
  return routeFor(findingId) !== null;
}

// ==================================================================
//  Async orchestrator — `recheckFinding` (the ONLY place a status is
//  computed end to end). Both server entry points (the /api/recheck
//  endpoint and the chat path) call this, guaranteeing one shared
//  implementation and a path-independent result (Requirements 9.2, 9.3).
// ==================================================================

// Default dependency wiring — the real passive-check primitives from lib/checks.js.
// Injectable so tests can simulate successes, failures, timeouts, and unreachability
// fully in-memory with no real network access.
export const defaultDeps = {
  checkDns,
  checkSsl,
  checkHeaders,
  checkRobotsSitemap,
  analyzeCookies,
  analyzeMixedContent,
  checkFileStatus,
};

// The failure sentinel every `decide` maps to INDETERMINATE (Requirements 3.13, 4.1).
const FAILURE = Object.freeze({ ok: false });

// Per-check timeout budgets (Requirements 3.14, 4.2). Each is <= the 10s per-request
// cap. Subdomain enumeration is never invoked because subdomain ids are non-recheckable.
const CHECK_TIMEOUTS = {
  dns: 6000, // DNS 6s
  ssl: 8000, // SSL 8s
  headers: 9000, // HTTP header retrieval 9s
  robots: 6000, // robots/sitemap retrieval 6s
  file: 6000, // status-only file probe 6s
};

// Overall cap on the whole re-check (Requirement 1.8).
const OVERALL_TIMEOUT_MS = 30000;

const TIMEOUT_MESSAGE = `The re-check timed out before it could finish. ${RETRY_HINT}`;
const UNRECHECKABLE_MESSAGE = "This finding can't be automatically re-checked.";
const UNEXPECTED_MESSAGE = `The re-check couldn't be completed. ${RETRY_HINT}`;

// Run the mapped check(s) for a route and normalize the raw check result into the
// family's observation shape. Any thrown error becomes the failure sentinel. Each
// observation explicitly carries the signal the family's pure `decide` predicate reads.
async function runRoute(route, domain, deps) {
  switch (route.check) {
    case "dns": {
      // SPF / DMARC / CAA all read a single DNS check.
      const dns = await deps.checkDns(domain);
      if (!dns || typeof dns !== "object") return FAILURE;
      return { ok: true, spf: dns.spf, dmarc: dns.dmarc, caa: dns.caa };
    }

    case "ssl": {
      const ssl = await deps.checkSsl(domain);
      if (!ssl || typeof ssl !== "object") return FAILURE;
      return { ok: true, expiresInDays: ssl.expiresInDays, error: ssl.error };
    }

    case "headers": {
      const headers = await deps.checkHeaders(domain);
      if (!headers || typeof headers !== "object") return FAILURE;
      const reachable = headers.reachable === true;

      // Cookie families: headers fetch followed by cookie analysis.
      if (route.analyze === "cookies") {
        const cookies = deps.analyzeCookies(headers.setCookies || []);
        return { ok: true, reachable, cookies };
      }

      // Mixed-content: headers fetch followed by mixed-content analysis on body + protocol.
      if (route.analyze === "mixedContent") {
        const mixed = deps.analyzeMixedContent(headers.body || "", headers.servedHttps);
        return { ok: true, reachable, mixed: { count: mixed ? mixed.count : 0 } };
      }

      // Plain security-header family: carry just the mapped boolean + reachability.
      return { ok: true, reachable, [route.headerKey]: headers[route.headerKey] === true };
    }

    case "robots": {
      // Reachability guard (Requirements 3.13, 4.1): checkRobotsSitemap swallows network
      // errors and returns empty arrays, which would look (falsely) like "resolved". We
      // first probe the host with a status-only request to /robots.txt; if that fetch
      // fails entirely the host is unreachable, so we emit the failure sentinel rather
      // than a false `resolved`.
      const probe = await deps.checkFileStatus(domain, "/robots.txt");
      if (!probe || probe.reachable !== true) return FAILURE;
      const robots = await deps.checkRobotsSitemap(domain);
      if (!robots || typeof robots !== "object") return FAILURE;
      return {
        ok: true,
        reachable: true,
        sensitiveDisallows: Array.isArray(robots.sensitiveDisallows) ? robots.sensitiveDisallows : [],
      };
    }

    case "file": {
      // Exposed-file: status-only probe of the single decoded path (Requirement 3.11).
      const probe = await deps.checkFileStatus(domain, route.path);
      if (!probe || typeof probe !== "object") return FAILURE;
      return { ok: true, reachable: probe.reachable === true, status: probe.status };
    }

    default:
      return FAILURE;
  }
}

// Run a route under its per-check timeout budget. On timeout or any throw, resolve to
// the failure sentinel so the family `decide` collapses to INDETERMINATE.
async function observe(route, domain, deps) {
  const budget = CHECK_TIMEOUTS[route.check] || 9000;
  try {
    const observation = await withTimeout(runRoute(route, domain, deps), budget, FAILURE);
    return observation || FAILURE;
  } catch (_) {
    return FAILURE;
  }
}

function isValidStatus(value) {
  return value === STATUS.RESOLVED || value === STATUS.UNRESOLVED || value === STATUS.INDETERMINATE;
}

// Final safety net on the result contract (Requirements 1.2, 1.3, 1.4): the returned
// object always has the requested findingId, a status in the enum, and a non-empty
// message clamped to 500 characters.
function normalizeResult(result, findingId) {
  const status = result && isValidStatus(result.status) ? result.status : STATUS.INDETERMINATE;
  let message =
    result && typeof result.message === "string" && result.message.length > 0
      ? result.message
      : UNEXPECTED_MESSAGE;
  if (message.length > MAX_MESSAGE_LENGTH) message = message.slice(0, MAX_MESSAGE_LENGTH);
  return { findingId, status, message };
}

// The core flow (runs inside the overall timeout + a try/catch in recheckFinding):
//   1. Classify the id. A null route short-circuits to INDETERMINATE with NO check run
//      (Requirements 1.7, 2.6, 3.10, 3.12).
//   2. Otherwise run the mapped check(s) under their per-check timeout and normalize.
//   3. status = route.decide(observation); message = route.describe(status, observation).
async function runRecheck({ domain, findingId }, deps) {
  const route = routeFor(findingId);
  if (route === null) {
    return { findingId, status: STATUS.INDETERMINATE, message: UNRECHECKABLE_MESSAGE };
  }
  const observation = await observe(route, domain, deps);
  const status = route.decide(observation);
  const message = route.describe(status, observation);
  return { findingId, status, message };
}

// Async orchestrator. Re-verifies ONE finding and returns { findingId, status, message }.
//
// Honesty over optimism: any failure, timeout, unreachability, unrecognized id, or
// unexpected error collapses to INDETERMINATE — we never claim "fixed" when we couldn't
// actually tell (Requirement 4). The whole call is wrapped in an overall 30s timeout
// (Requirement 1.8) and a try/catch that converts any unexpected error to INDETERMINATE
// (Requirement 4.5), so the caller never sees an unhandled rejection.
export async function recheckFinding({ domain, findingId } = {}, deps = defaultDeps) {
  let result;
  try {
    result = await withTimeout(runRecheck({ domain, findingId }, deps), OVERALL_TIMEOUT_MS, {
      findingId,
      status: STATUS.INDETERMINATE,
      message: TIMEOUT_MESSAGE,
    });
  } catch (_) {
    result = { findingId, status: STATUS.INDETERMINATE, message: UNEXPECTED_MESSAGE };
  }
  return normalizeResult(result, findingId);
}
