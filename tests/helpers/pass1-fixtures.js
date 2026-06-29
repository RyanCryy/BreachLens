// tests/helpers/pass1-fixtures.js
//
// Shared fast-check generators + the expected-value oracle for the Pass 1
// verification suite.
// =============================================================================
//
// WHY THIS FILE EXISTS
// --------------------
// The Pass 1 property tests (Properties 1–9) need a large, structured input
// space that mirrors the REAL shapes `deriveFindings` emits, so that the frozen
// production functions (`runPass1` / `classifyOne`) and the real deterministic
// oracle (`fallbackClassify` / `defaultFixSnippet`) both handle the generated
// findings exactly as they would handle production data.
//
// This module authors NO production change. It only imports the real, frozen
// `findings.js` exports and RE-EXPORTS them as the oracle — the suite always
// compares production output against the genuine deterministic functions, never
// against a reimplementation. (If the rule tables in findings.js ever change,
// the oracle changes with them automatically.)
//
// The generators are grounded in the exact id/type/path/snippet facts of
// netlify/functions/lib/findings.js:
//   - email-auth : spf-missing, dmarc-missing            (carry suggestedSnippet)
//   - tls        : ssl-error, ssl-expired, ssl-expiring, ssl-expiring-soon
//   - header     : hdr-hsts, hdr-csp, hdr-xfo, hdr-xcto
//   - dns        : caa-missing                            (carries suggestedSnippet)
//   - cookie     : cookie-secure, cookie-httponly, cookie-samesite
//   - mixed-content : mixed-content
//   - info-leak  : robots-sensitive
//   - subdomain  : subdomain-surface (fixed) + subdomain-<name> (dynamic)
//   - exposure   : exposed-file-<path> (dynamic, carries `path`)
//
// SEVERITY_MAP / EXPOSED_FILE_INFO keys are reproduced ONLY as generator inputs
// (to produce both "known" and "unknown" dynamic findings); they are never used
// as the assertion oracle — fallbackClassify is.
//
// =============================================================================

import fc from "fast-check";

// --- The expected-value ORACLE: the real, frozen deterministic functions. ---
// Re-exported so every property test imports the genuine implementation.
export { fallbackClassify, defaultFixSnippet } from "../../netlify/functions/lib/findings.js";

// =============================================================================
//  Ground-truth catalogs (mirrors of findings.js — used as GENERATOR INPUT only)
// =============================================================================

// Exposed-file paths that findings.js classifies with a specific severity.
export const KNOWN_EXPOSED_PATHS = [
  "/.git/config",
  "/.git/HEAD",
  "/.env",
  "/wp-config.php.bak",
  "/.DS_Store",
];

// Exposed-file paths NOT in EXPOSED_FILE_INFO → fall to the default ("high").
export const UNKNOWN_EXPOSED_PATHS = [
  "/backup.zip",
  "/config.yml",
  "/admin.php",
  "/.svn/entries",
  "/server-status",
  "/db.sql",
];

// Subdomain leaf labels findings.js treats as "notable".
export const NOTABLE_SUBDOMAINS = [
  "dev",
  "staging",
  "test",
  "qa",
  "uat",
  "admin",
  "internal",
  "vpn",
  "jenkins",
  "gitlab",
  "phpmyadmin",
  "backup",
  "legacy",
  "beta",
  "sandbox",
  "demo",
];

// Every category Pass 1 can see (the design's Finding `type` union).
export const ALL_TYPES = [
  "email-auth",
  "tls",
  "header",
  "subdomain",
  "dns",
  "cookie",
  "mixed-content",
  "info-leak",
  "exposure",
];

// Realistic, paste-ready record values for snippet-carrying findings.
const SPF_VALUES = ["v=spf1 include:_spf.google.com -all", "v=spf1 mx -all", "v=spf1 -all"];
const DOMAINS = ["example.com", "acme.co", "mysite.org", "shop.io", "blog.dev"];

// =============================================================================
//  Per-finding SENTINEL injector (for cross-finding leakage assertions)
// =============================================================================
//
// Each finding in a list gets a UNIQUE, position-derived marker embedded in its
// label, detail, and (when present) suggestedSnippet. Property 1's isolation
// check can then assert that the LLM call for finding i contains finding i's
// sentinel and NO OTHER finding's sentinel. The marker is deterministic (no
// randomness) so fast-check shrinking stays reproducible, and is bracketed so
// no sentinel is a substring of another (e.g. ⟦S1⟧ is not inside ⟦S11⟧).

/** The unique sentinel token for the finding at position `index`. */
export function sentinelFor(index) {
  return `⟦S${index}⟧`;
}

/**
 * Return a copy of `findings` where each finding embeds its unique sentinel in
 * label/detail/suggestedSnippet and exposes it on a non-production `_sentinel`
 * field for convenient assertion. Original objects are not mutated.
 */
export function injectSentinels(findings) {
  return findings.map((f, i) => {
    const s = sentinelFor(i);
    const out = { ...f, _sentinel: s };
    out.label = `${f.label} ${s}-L`;
    out.detail = `${f.detail} ${s}-D`;
    if (typeof f.suggestedSnippet === "string") {
      out.suggestedSnippet = `${f.suggestedSnippet} ${s}-S`;
    }
    return out;
  });
}

// =============================================================================
//  fixSnippet arbitraries (what an LLM might return in json.fixSnippet)
// =============================================================================

// A usable, paste-ready literal token (trimmed, non-empty, not "null").
export const usableSnippetArb = fc.constantFrom(
  "v=spf1 include:_spf.example.com ~all",
  "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
  '0 issue "letsencrypt.org"',
  "Strict-Transport-Security: max-age=31536000",
  "X-Content-Type-Options: nosniff"
);

// A usable token wrapped in surrounding whitespace (Req 6.5: trimmed value kept).
export const whitespacePaddedSnippetArb = usableSnippetArb.map(
  (v) => `   ${v}\t\n `
);

// Strings that MUST normalize to null (Req 6.4): empty, whitespace-only,
// and the literal "null" in assorted casings/padding.
export const nullishSnippetStringArb = fc.constantFrom(
  "",
  "   ",
  "\t",
  "\n  \n",
  "null",
  "NULL",
  "Null",
  "  null  ",
  "\tNULL\n"
);

// Any fixSnippet STRING the LLM might emit (the task's required string space).
export const fixSnippetStringArb = fc.oneof(
  { weight: 3, arbitrary: usableSnippetArb },
  { weight: 2, arbitrary: whitespacePaddedSnippetArb },
  { weight: 3, arbitrary: nullishSnippetStringArb },
  // free-form usable-ish strings (guarded to stay non-"null", non-blank)
  {
    weight: 1,
    arbitrary: fc
      .string({ minLength: 1, maxLength: 40 })
      .filter((s) => s.trim() !== "" && s.trim().toLowerCase() !== "null"),
  }
);

// The FULL value space for json.fixSnippet, including non-string / absent forms
// (Req 6.4 covers "absent" and "non-string" too). Supports Property 6.
export const llmFixSnippetValueArb = fc.oneof(
  { weight: 6, arbitrary: fixSnippetStringArb },
  { weight: 1, arbitrary: fc.constant(undefined) },
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 1, arbitrary: fc.integer() },
  { weight: 1, arbitrary: fc.boolean() }
);

// =============================================================================
//  LLM-result arbitrary ({ title, explanation, recommendation, fixSnippet })
// =============================================================================

// Each prose field is independently present-and-nonempty, present-but-empty,
// or absent — exercising the backfill rules (Property 5).
function proseFieldArb(sample) {
  return fc.oneof(
    { weight: 3, arbitrary: fc.constantFrom(...sample) },
    { weight: 1, arbitrary: fc.constant("") },
    { weight: 1, arbitrary: fc.constant(undefined) }
  );
}

export const llmJsonArb = fc.record(
  {
    title: proseFieldArb(["Fix this issue", "Security finding", "Action required"]),
    explanation: proseFieldArb(["This matters because of X.", "An attacker could abuse Y."]),
    recommendation: proseFieldArb(["Do A then B.", "Configure the header."]),
    fixSnippet: llmFixSnippetValueArb,
  },
  { requiredKeys: [] } // any subset of keys may be present
);

// =============================================================================
//  provider arbitrary  (null, or a confidently-matched name w/ unique sentinel)
// =============================================================================

/** The provider sentinel marker so isolation tests can detect leakage. */
export const PROVIDER_SENTINEL = "⟦PROV⟧";

// Non-null provider names always carry the sentinel substring so a test can
// assert the name reached (or did not reach) a given prompt.
export const nonNullProviderArb = fc
  .constantFrom("Cloudflare", "AWS Route 53", "Google Cloud DNS", "GoDaddy", "Namecheap")
  .map((name) => `${name} ${PROVIDER_SENTINEL}`);

export const providerArb = fc.oneof(
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 2, arbitrary: nonNullProviderArb }
);

// =============================================================================
//  tech arbitrary  (non-empty detected / empty / missing-detected / absent)
// =============================================================================

/** The tech sentinel marker for prompt-injection / leakage assertions. */
export const TECH_SENTINEL = "⟦TECH⟧";

const techNameArb = fc
  .constantFrom("nginx", "WordPress", "React", "Express", "Apache", "PHP", "Cloudflare")
  .map((t) => `${t}${TECH_SENTINEL}`);

// { server, poweredBy, detected: [>=1] }  → produces the optional tech line.
export const techWithDetectedArb = fc.record({
  server: fc.option(fc.string(), { nil: null }),
  poweredBy: fc.option(fc.string(), { nil: null }),
  detected: fc.array(techNameArb, { minLength: 1, maxLength: 4 }),
});

// detected present but EMPTY  → no tech line.
export const techEmptyDetectedArb = fc.record({
  server: fc.option(fc.string(), { nil: null }),
  poweredBy: fc.option(fc.string(), { nil: null }),
  detected: fc.constant([]),
});

// detected key MISSING entirely → no tech line.
export const techMissingDetectedArb = fc.record({
  server: fc.option(fc.string(), { nil: null }),
  poweredBy: fc.option(fc.string(), { nil: null }),
});

// tech ABSENT (undefined argument) → no tech line.
export const techAbsentArb = fc.constant(undefined);

// The full tech space across all four forms.
export const techArb = fc.oneof(
  { weight: 3, arbitrary: techWithDetectedArb },
  { weight: 1, arbitrary: techEmptyDetectedArb },
  { weight: 1, arbitrary: techMissingDetectedArb },
  { weight: 1, arbitrary: techAbsentArb }
);

// =============================================================================
//  Finding arbitraries (one per category, mirroring deriveFindings shapes)
// =============================================================================

// Whether a snippet-eligible finding actually carries its suggestedSnippet.
const carriesSnippetArb = fc.boolean();

// --- email-auth ---
const spfFindingArb = fc.record({ snippet: fc.constantFrom(...SPF_VALUES), carry: carriesSnippetArb }).map(
  ({ snippet, carry }) => {
    const f = {
      id: "spf-missing",
      type: "email-auth",
      label: "Missing SPF record",
      detail: `No SPF TXT record was found. A correct, safe SPF record would be: ${snippet}`,
    };
    if (carry) f.suggestedSnippet = snippet;
    return f;
  }
);

const dmarcFindingArb = fc.record({ domain: fc.constantFrom(...DOMAINS), carry: carriesSnippetArb }).map(
  ({ domain, carry }) => {
    const snippet = `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; ruf=mailto:dmarc@${domain}; fo=1`;
    const f = {
      id: "dmarc-missing",
      type: "email-auth",
      label: "Missing DMARC record",
      detail: `No DMARC policy record was found at _dmarc.${domain}. A correct starter DMARC record would be: ${snippet}`,
    };
    if (carry) f.suggestedSnippet = snippet;
    return f;
  }
);

export const emailAuthFindingArb = fc.oneof(spfFindingArb, dmarcFindingArb);

// --- tls ---
export const tlsFindingArb = fc.constantFrom(
  { id: "ssl-error", type: "tls", label: "TLS/SSL could not be verified", detail: "Connecting over HTTPS failed or the certificate could not be read (handshake error)." },
  { id: "ssl-expired", type: "tls", label: "Expired TLS certificate", detail: "The TLS certificate appears to have expired (-3 days)." },
  { id: "ssl-expiring", type: "tls", label: "TLS certificate expiring very soon", detail: "The TLS certificate expires in 7 days (issuer: Let's Encrypt)." },
  { id: "ssl-expiring-soon", type: "tls", label: "TLS certificate expiring within a month", detail: "The TLS certificate expires in 25 days (issuer: Let's Encrypt)." }
);

// --- header ---
export const headerFindingArb = fc.constantFrom(
  { id: "hdr-hsts", type: "header", label: "Missing HTTP Strict-Transport-Security header", detail: "The HSTS header is absent, so browsers aren't forced to use HTTPS." },
  { id: "hdr-csp", type: "header", label: "Missing Content-Security-Policy header", detail: "No Content-Security-Policy header was returned, increasing XSS/injection risk." },
  { id: "hdr-xfo", type: "header", label: "Missing X-Frame-Options header", detail: "No X-Frame-Options header was returned, allowing potential clickjacking via framing." },
  { id: "hdr-xcto", type: "header", label: "Missing X-Content-Type-Options header", detail: "No X-Content-Type-Options: nosniff header was returned, allowing MIME-type sniffing." }
);

// --- dns (caa) ---
export const dnsFindingArb = carriesSnippetArb.map((carry) => {
  const snippet = '0 issue "letsencrypt.org"';
  const f = {
    id: "caa-missing",
    type: "dns",
    label: "No CAA record set",
    detail: `The domain has no CAA DNS record, so any CA may issue certificates for it. A starter CAA record would be: ${snippet}`,
  };
  if (carry) f.suggestedSnippet = snippet;
  return f;
});

// --- cookie ---
export const cookieFindingArb = fc
  .record({
    pick: fc.constantFrom(
      { id: "cookie-secure", flag: "Secure", verb: "transmitted over unencrypted HTTP" },
      { id: "cookie-httponly", flag: "HttpOnly", verb: "readable by client-side JavaScript" },
      { id: "cookie-samesite", flag: "SameSite", verb: "sent on cross-site requests" }
    ),
    n: fc.integer({ min: 1, max: 5 }),
  })
  .map(({ pick, n }) => ({
    id: pick.id,
    type: "cookie",
    label: `${n} cookie${n === 1 ? "" : "s"} missing the ${pick.flag} flag`,
    detail: `These cookies can be ${pick.verb}: session, csrftoken.`,
  }));

// --- mixed-content ---
export const mixedContentFindingArb = fc.integer({ min: 1, max: 9 }).map((count) => ({
  id: "mixed-content",
  type: "mixed-content",
  label: `Mixed content: ${count} insecure resource reference${count === 1 ? "" : "s"}`,
  detail: `The HTTPS homepage references resources over plain http:// (e.g. cdn.example.net).`,
}));

// --- info-leak (robots) ---
export const infoLeakFindingArb = fc.constant({
  id: "robots-sensitive",
  type: "info-leak",
  label: "robots.txt discloses sensitive-looking paths",
  detail: "robots.txt lists Disallow entries pointing to sensitive areas: /admin, /backup. robots.txt is public.",
});

// --- subdomain (fixed surface finding + dynamic per-name finding) ---
export const subdomainSurfaceFindingArb = fc.integer({ min: 26, max: 200 }).map((n) => ({
  id: "subdomain-surface",
  type: "subdomain",
  label: "Large public subdomain footprint",
  detail: `${n} subdomains are publicly discoverable via certificate transparency, expanding the attack surface.`,
}));

export const dynamicSubdomainFindingArb = fc
  .record({ leaf: fc.constantFrom(...NOTABLE_SUBDOMAINS), domain: fc.constantFrom(...DOMAINS) })
  .map(({ leaf, domain }) => {
    const sub = `${leaf}.${domain}`;
    return {
      id: `subdomain-${sub}`,
      type: "subdomain",
      label: `Sensitive-looking subdomain exposed: ${sub}`,
      detail: `The subdomain "${sub}" is publicly discoverable via certificate transparency and looks non-production.`,
    };
  });

export const subdomainFindingArb = fc.oneof(
  { weight: 3, arbitrary: dynamicSubdomainFindingArb },
  { weight: 1, arbitrary: subdomainSurfaceFindingArb }
);

// --- exposure (dynamic id + path; known + unknown paths) ---
export const exposureFindingArb = fc
  .oneof(
    { weight: 3, arbitrary: fc.constantFrom(...KNOWN_EXPOSED_PATHS) },
    { weight: 2, arbitrary: fc.constantFrom(...UNKNOWN_EXPOSED_PATHS) }
  )
  .map((path) => ({
    id: `exposed-file-${path}`,
    type: "exposure",
    path,
    label: `Publicly accessible file: ${path}`,
    detail: `A request to ${path} returned HTTP 200, indicating the file is publicly served.`,
  }));

// =============================================================================
//  Composite finding arbitraries
// =============================================================================

// One finding from ANY category (weighted so every type appears across runs).
export const findingArb = fc.oneof(
  emailAuthFindingArb,
  tlsFindingArb,
  headerFindingArb,
  dnsFindingArb,
  cookieFindingArb,
  mixedContentFindingArb,
  infoLeakFindingArb,
  subdomainFindingArb,
  exposureFindingArb
);

// A per-category lookup, handy for targeted tests.
export const findingArbByType = {
  "email-auth": emailAuthFindingArb,
  tls: tlsFindingArb,
  header: headerFindingArb,
  dns: dnsFindingArb,
  cookie: cookieFindingArb,
  "mixed-content": mixedContentFindingArb,
  "info-leak": infoLeakFindingArb,
  subdomain: subdomainFindingArb,
  exposure: exposureFindingArb,
};

/**
 * A NON-EMPTY list of findings (default 1–6) spanning arbitrary categories,
 * with unique per-finding sentinels already injected. Use this as the primary
 * driver for Properties 1–9.
 */
export function findingListArb({ minLength = 1, maxLength = 6 } = {}) {
  return fc.array(findingArb, { minLength, maxLength }).map(injectSentinels);
}

/**
 * A list guaranteed to include AT LEAST ONE finding of every category, in a
 * shuffled order, with sentinels injected. Useful when a test must observe the
 * full type space in a single run.
 */
export const allTypesFindingListArb = fc
  .tuple(...ALL_TYPES.map((t) => findingArbByType[t]))
  .chain((one) => fc.shuffledSubarray(one, { minLength: one.length, maxLength: one.length }))
  .map(injectSentinels);

/** Findings that are guaranteed to carry a suggestedSnippet (Property 8). */
export const snippetCarryingFindingArb = fc
  .oneof(
    spfFindingArb.map((f) => ({ ...f, suggestedSnippet: f.suggestedSnippet ?? "v=spf1 -all" })),
    dmarcFindingArb.map((f) => ({
      ...f,
      suggestedSnippet: f.suggestedSnippet ?? "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    })),
    dnsFindingArb.map((f) => ({ ...f, suggestedSnippet: f.suggestedSnippet ?? '0 issue "letsencrypt.org"' }))
  )
  // ensure the snippet is present even when the base arb omitted it
  .map((f) => (typeof f.suggestedSnippet === "string" ? f : { ...f, suggestedSnippet: "v=spf1 -all" }));
