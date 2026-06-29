// tests/helpers/pass2-fixtures.js
//
// Shared fast-check generators + expected-value oracles for the Pass 2
// (Analyst Synthesis) verification suite.
// =============================================================================
//
// WHY THIS FILE EXISTS
// --------------------
// The Pass 2 property tests (design Properties 1-13) drive the frozen production
// `runPass2` (netlify/functions/lib/analysis.js) over a large, structured input
// space and compare its output against deterministic oracles. This module:
//
//   1. Generates Classified_Finding inputs whose `severity` deliberately spans
//      the entire space production might encounter — the four scored levels
//      (critical/high/medium/low), `info`, MIXED-CASE variants, `null`, and
//      arbitrary strings — so the scoring and sorting paths are exercised on
//      their 0-weight / rank-0 branches as well as the happy path.
//   2. Generates the Pass 2 LLM response space (`summary`/`topPriority` present-
//      nonempty / present-empty / non-string / absent, plus extra score-like
//      fields that production MUST ignore).
//   3. Provides oracles (`expectedScore`, `expectedLevel`, `expectedSorted`)
//      that reimplement the deterministic scoring/banding/sort EXACTLY as the
//      (non-exported) production helpers do, so tests have a ground truth.
//   4. Re-exports the real, exported production helper used as ground truth
//      (`buildFallbackReport`) and the controllable LLM double seam from
//      tests/helpers/llm-double.js.
//
// The oracles below mirror the logic in analysis.js (verified against that file):
//
//   computeFallbackScore: weights critical=40, high=22, medium=10, low=3;
//                         score = Math.min(100, Σ weights[normalizeSeverity(severity)]);
//                         lookup is `weights[severity.toLowerCase()] || 0`.
//   scoreToLevel:         score>=70 Critical, >=45 High, >=20 Medium, else Low.
//   sortFindings:         stable sort by SEVERITY_RANK desc
//                         (critical=4, high=3, medium=2, low=1, else 0),
//                         lookup is `RANK[severity.toLowerCase()] || 0`.
//
// CASE-INSENSITIVE SEVERITY MATCHING: production normalizes each severity string
// with `.toLowerCase()` before the weight/rank lookup, so `Critical`, `HIGH`,
// `critical` all resolve to the same weight/rank. Only non-severity values —
// `info`, `null`, or an arbitrary non-matching string — fall to the `|| 0`
// branch (weight 0 AND rank 0). The oracles below replicate this exactly, which
// is why the generated severity space includes mixed-case/null/arbitrary values:
// mixed-case now contributes its intended weight, while info/null/arbitrary
// probe the 0-weight and rank-0 code paths.
//
// =============================================================================

import fc from "fast-check";

// --- Real, exported production helper, re-exported as ground truth. ---
// (computeFallbackScore / scoreToLevel / sortFindings / synthFallbackSummary are
//  NOT exported from analysis.js — that is precisely why the oracles below exist.)
export { buildFallbackReport, runPass2 } from "../../netlify/functions/lib/analysis.js";

// --- The single controllable LLM double seam, re-exported for convenience. ---
export {
  createLLMDouble,
  attachDouble,
  behaviors,
  ParseError,
} from "./llm-double.js";

// =============================================================================
//  Deterministic constants — EXACT mirrors of analysis.js (used by the oracles)
// =============================================================================

/** Weighted-sum weights — must match `computeFallbackScore` in analysis.js. */
export const WEIGHTS = { critical: 40, high: 22, medium: 10, low: 3 };

/** Severity ranks — must match `SEVERITY_RANK` in analysis.js. */
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/** Band boundaries — must match `scoreToLevel` in analysis.js. */
export const LEVEL_BANDS = { Critical: 70, High: 45, Medium: 20 };

/** Normalize a severity for lookup exactly as production does (toLowerCase). */
function normSeverity(severity) {
  return typeof severity === "string" ? severity.toLowerCase() : severity;
}

// =============================================================================
//  ORACLES
// =============================================================================

/**
 * Recompute the deterministic overall risk score for a list of classified
 * findings: `Math.min(100, Σ weights[normalizeSeverity(severity)])`, where
 * unknown / null / non-scored severities contribute 0. Mirrors production
 * exactly, including the case-insensitive `weights[severity.toLowerCase()] || 0`
 * lookup.
 *
 * @param {Array<{severity?: unknown}>} findings
 * @returns {number} integer score in [0, 100]
 */
export function expectedScore(findings) {
  let score = 0;
  for (const f of findings) score += WEIGHTS[normSeverity(f && f.severity)] || 0;
  return Math.min(100, score);
}

/**
 * Recompute the risk-level band from a score. Total over all numbers; mirrors
 * `scoreToLevel` exactly (boundaries 70 / 45 / 20).
 *
 * @param {number} score
 * @returns {"Critical"|"High"|"Medium"|"Low"}
 */
export function expectedLevel(score) {
  if (score >= LEVEL_BANDS.Critical) return "Critical";
  if (score >= LEVEL_BANDS.High) return "High";
  if (score >= LEVEL_BANDS.Medium) return "Medium";
  return "Low";
}

/**
 * Produce the expected severity-descending, STABLE ordering of findings.
 *
 * Production uses `[...findings].sort((a,b) => (RANK[b.sev]||0)-(RANK[a.sev]||0))`,
 * which is a stable sort: equal-rank elements keep their original relative order.
 * To verify that stability robustly (independent of the host engine's sort
 * implementation), this oracle breaks ties using each element's `_index` tag
 * (assigned by `classifiedListArb`). When the input is in original index order
 * the result is identical to production's stable sort; the explicit tiebreak
 * lets a test feed a shuffled array and still derive the canonical expected
 * order for equal-rank items.
 *
 * @param {Array<{severity?: unknown, _index?: number}>} findings
 * @returns {Array} a new, sorted array (input not mutated)
 */
export function expectedSorted(findings) {
  return [...findings].sort((a, b) => {
    const rankDelta =
      (SEVERITY_RANK[normSeverity(b && b.severity)] || 0) -
      (SEVERITY_RANK[normSeverity(a && a.severity)] || 0);
    if (rankDelta !== 0) return rankDelta;
    // Stable tiebreak by original index (see doc comment).
    const ai = typeof a._index === "number" ? a._index : 0;
    const bi = typeof b._index === "number" ? b._index : 0;
    return ai - bi;
  });
}

// =============================================================================
//  Severity arbitrary — spans the FULL space production may meet
// =============================================================================

/** The four scored, lowercase severities production assigns weight/rank to. */
export const SCORED_SEVERITIES = ["critical", "high", "medium", "low"];

/** Mixed-case spellings that production now normalizes to their scored value. */
export const MIXED_CASE_SEVERITIES = [
  "Critical",
  "HIGH",
  "Medium",
  "LOW",
  "High",
  "CRITICAL",
  "cRiTiCaL",
  "Low",
];

/** Non-scored but plausible severity strings (also 0 weight / rank 0). */
export const OTHER_SEVERITIES = ["info", "informational", "none", "unknown", ""];

// Object.prototype property names must be excluded from the arbitrary-string
// generator: production looks severities up on a plain object literal AFTER
// lowercasing, so a value whose lowercased form is an inherited key (e.g.
// "constructor", "valueOf", or "Constructor"/"VALUEOF") would resolve to an
// inherited function rather than 0. Those values never occur in real production
// (severities come from the fixed rule table), so excluding them — comparing
// case-insensitively to match production's `.toLowerCase()` lookup — keeps the
// generated space meaningful (genuinely-unknown severities → 0) and avoids
// spurious oracle/prod divergence.
const PROTO_KEYS = new Set(Object.getOwnPropertyNames(Object.prototype));

const arbitrarySeverityStringArb = fc
  .string({ maxLength: 16 })
  .filter((s) => !PROTO_KEYS.has(s.toLowerCase()));

/**
 * A `severity` arbitrary deliberately covering: the four scored lowercase
 * levels, mixed-case variants, non-scored words, `null`, and arbitrary strings.
 * Weighted so scored levels dominate (to build meaningful scores) while the
 * 0-weight / rank-0 paths are still hit frequently.
 */
export const severityArb = fc.oneof(
  { weight: 6, arbitrary: fc.constantFrom(...SCORED_SEVERITIES) },
  { weight: 2, arbitrary: fc.constantFrom(...MIXED_CASE_SEVERITIES) },
  { weight: 1, arbitrary: fc.constantFrom(...OTHER_SEVERITIES) },
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 1, arbitrary: arbitrarySeverityStringArb }
);

// =============================================================================
//  Classified_Finding arbitrary
// =============================================================================

// Non-empty prose so `recommendation` is always usable as a topPriority fallback
// (production does `sorted[0].recommendation`). Mixes realistic phrases with
// free-form text to widen coverage.
const idArb = fc.integer({ min: 0, max: 9_999_999 }).map((n) => `finding-${n}`);

const titleArb = fc.oneof(
  fc.constantFrom(
    "Missing SPF record",
    "Expired TLS certificate",
    "Missing Content-Security-Policy header",
    "Publicly accessible file",
    "Sensitive-looking subdomain exposed"
  ),
  fc.string({ minLength: 1, maxLength: 40 }).filter((s) => s.trim().length > 0)
);

const explanationArb = fc.oneof(
  fc.constantFrom(
    "An attacker could spoof email from your domain.",
    "Visitors may see browser security warnings.",
    "This file exposes internal configuration."
  ),
  fc.string({ minLength: 1, maxLength: 80 }).filter((s) => s.trim().length > 0)
);

const recommendationArb = fc.oneof(
  fc.constantFrom(
    "Add the SPF TXT record: v=spf1 -all",
    "Renew the TLS certificate before it expires.",
    "Remove the publicly accessible file or restrict access.",
    "Add the Content-Security-Policy response header."
  ),
  fc.string({ minLength: 1, maxLength: 80 }).filter((s) => s.trim().length > 0)
);

const TYPE_POOL = [
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

/**
 * A Classified_Finding arbitrary, shaped like the output of Pass 1's
 * `classifyOne` and consumed by `runPass2`: `{ id, type, title, severity,
 * explanation, recommendation, fixSnippet }`. `severity` spans the full space
 * (see `severityArb`).
 */
export const classifiedFindingArb = fc.record({
  id: idArb,
  type: fc.constantFrom(...TYPE_POOL),
  title: titleArb,
  severity: severityArb,
  explanation: explanationArb,
  recommendation: recommendationArb,
  fixSnippet: fc.option(fc.string({ minLength: 1, maxLength: 30 }), { nil: null }),
});

/**
 * A Classified_Finding arbitrary pinned to a specific severity — handy for
 * targeted scoring/banding tests that need to hit a known score.
 * @param {unknown} severity
 */
export function classifiedFindingArbWithSeverity(severity) {
  return classifiedFindingArb.map((f) => ({ ...f, severity }));
}

// =============================================================================
//  Classified_Finding LIST arbitrary (with original-index tags)
// =============================================================================

/**
 * Arrays of Classified_Findings. Each element is tagged with its ORIGINAL index
 * via a non-production `_index` field so the sort-stability oracle
 * (`expectedSorted`) can verify that equal-rank findings preserve their relative
 * order after production's stable sort. The `_index` field is ignored by
 * production (`runPass2` only reads severity/title/explanation/recommendation).
 *
 * @param {{minLength?: number, maxLength?: number}} [opts]
 */
export function classifiedListArb({ minLength = 0, maxLength = 8 } = {}) {
  return fc
    .array(classifiedFindingArb, { minLength, maxLength })
    .map((arr) => arr.map((f, i) => ({ ...f, _index: i })));
}

/** A NON-EMPTY classified list (min length 1) — for single-call / scoring tests. */
export function nonEmptyClassifiedListArb({ minLength = 1, maxLength = 8 } = {}) {
  return classifiedListArb({ minLength: Math.max(1, minLength), maxLength });
}

// =============================================================================
//  Domain arbitrary
// =============================================================================

const DOMAIN_LABELS = [
  "example",
  "acme",
  "mysite",
  "shop",
  "blog",
  "my-startup",
  "big-corp",
  "test-co",
  "widgets",
];
const DOMAIN_TLDS = ["com", "org", "io", "co", "dev", "net", "app"];

/**
 * A domain-string arbitrary for zero-findings and request-content properties.
 * Produces values like "acme.io" and occasionally "staging.acme.io".
 */
export const domainArb = fc.oneof(
  {
    weight: 3,
    arbitrary: fc
      .tuple(fc.constantFrom(...DOMAIN_LABELS), fc.constantFrom(...DOMAIN_TLDS))
      .map(([label, tld]) => `${label}.${tld}`),
  },
  {
    weight: 1,
    arbitrary: fc
      .tuple(
        fc.constantFrom("dev", "staging", "www", "admin"),
        fc.constantFrom(...DOMAIN_LABELS),
        fc.constantFrom(...DOMAIN_TLDS)
      )
      .map(([sub, label, tld]) => `${sub}.${label}.${tld}`),
  }
);

// =============================================================================
//  Pass 2 LLM-response arbitrary
// =============================================================================

// One prose field (summary | topPriority): independently present-and-nonempty,
// present-but-empty, non-string, or absent. `requiredKeys: []` on the record
// makes "absent" possible; here `undefined` models absence within the union and
// the record builder drops undefined-valued keys is NOT guaranteed, so absence
// is modeled at the record level below.
const presentNonEmptyProseArb = fc
  .string({ minLength: 1, maxLength: 120 })
  .filter((s) => s.trim().length > 0);

const presentEmptyProseArb = fc.constantFrom("", "   ", "\t", "\n");

const nonStringProseArb = fc.oneof(
  fc.integer(),
  fc.boolean(),
  fc.constant(null),
  fc.double({ noNaN: true }),
  fc.array(fc.string(), { maxLength: 2 })
);

/**
 * The value space for a single Pass 2 prose field. Excludes the "absent" case —
 * absence is handled by `requiredKeys` at the record level so the key is truly
 * omitted from the object rather than set to `undefined`.
 */
export const proseFieldValueArb = fc.oneof(
  { weight: 4, arbitrary: presentNonEmptyProseArb },
  { weight: 2, arbitrary: presentEmptyProseArb },
  { weight: 2, arbitrary: nonStringProseArb }
);

// Extra score-like fields production MUST ignore. Included randomly to prove the
// model's own score/level never leaks into the authoritative report.
const extraIgnoredFieldsArb = fc.record(
  {
    score: fc.integer({ min: -999, max: 999 }),
    riskLevel: fc.constantFrom("Critical", "High", "Medium", "Low", "totally-bogus"),
    overallRiskScore: fc.integer({ min: -999, max: 999 }),
  },
  { requiredKeys: [] }
);

/**
 * A Pass 2 LLM response arbitrary. `summary` and `topPriority` are each
 * INDEPENDENTLY present-and-nonempty / present-but-empty / non-string / absent
 * (absence via `requiredKeys: []`). The response may also carry extra
 * `score` / `riskLevel` / `overallRiskScore` fields to prove production ignores
 * them.
 */
export const llmResponseArb = fc
  .tuple(
    fc.record(
      { summary: proseFieldValueArb, topPriority: proseFieldValueArb },
      { requiredKeys: [] }
    ),
    extraIgnoredFieldsArb
  )
  .map(([prose, extras]) => ({ ...extras, ...prose }));

/**
 * A response whose `summary` and `topPriority` are BOTH present, non-empty
 * strings — the "valid prose used verbatim" path (Property 7).
 */
export const validLlmResponseArb = fc.record({
  summary: presentNonEmptyProseArb,
  topPriority: presentNonEmptyProseArb,
});

/**
 * A response where at least one of `summary` / `topPriority` is absent / empty /
 * non-string — the deterministic-fallback path (Property 8). Built by rejecting
 * responses where both fields happen to be valid non-empty strings.
 */
export const fallbackTriggeringLlmResponseArb = llmResponseArb.filter((r) => {
  const okSummary = typeof r.summary === "string" && r.summary.length > 0;
  const okTop = typeof r.topPriority === "string" && r.topPriority.length > 0;
  return !(okSummary && okTop);
});
