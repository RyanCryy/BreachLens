import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { runScan, RESULT_TYPE, CHECK_IDS } from "./scan-engine.js";
import { withTimeout } from "./checks.js";

// ---------------------------------------------------------------------------
// Feature: passive-scan-engine, Property 6: No response bodies retained
//
// For any Scan_Result, no Check_Outcome SHALL retain an HTTP response body — in
// particular, exposed-file outcomes SHALL carry only status-derived fields
// (path, status, exposed) and no body/content field anywhere in the result.
//
// **Validates: Requirements 3.1, 3.2**
//
// Strategy: every check primitive is injected via `deps`, so no real network is
// touched. We deliberately make the two body-bearing primitives MISBEHAVE:
//   - `checkSensitiveFiles` returns probes that include body/content-like fields
//     (`body`, `content`, `text`, `html`) alongside the legitimate
//     {path, status, exposed} — simulating a primitive that failed to discard a
//     response body (Req 3.2).
//   - `checkHeaders` returns a homepage `body` string. The headers body is
//     legitimately handed to the dependent mixed-content / tech checks INTERNALLY,
//     but it must NOT be retained anywhere in the final Scan_Result.
// We then run `runScan` and deep-walk the entire returned Scan_Result asserting
// that none of the injected body markers survive anywhere, and that every
// exposed-files finding carries strictly {path, status, exposed}.
// ---------------------------------------------------------------------------

// Unique, collision-proof sentinels prefixed onto every generated body so we can
// detect a retained body unambiguously anywhere in the serialized result.
const EXPOSED_SENTINEL = "\u0001EXPOSED_RESPONSE_BODY\u0001:";
const HEADERS_SENTINEL = "\u0001HEADERS_RESPONSE_BODY\u0001:";

// Key names that, if they appear holding a response payload, indicate a retained
// body. Used for an explicit key-name guard in addition to the value scan.
const BODY_LIKE_KEYS = ["body", "content", "text", "html", "responseBody", "raw"];

// Recursively collect every string leaf value in an arbitrary JSON-like value.
function collectStringValues(node, acc) {
  if (node == null) return acc;
  if (typeof node === "string") {
    acc.push(node);
    return acc;
  }
  if (Array.isArray(node)) {
    for (const v of node) collectStringValues(v, acc);
    return acc;
  }
  if (typeof node === "object") {
    for (const k of Object.keys(node)) collectStringValues(node[k], acc);
  }
  return acc;
}

// Recursively collect [key, value] pairs whose value is a string, for the
// body-like key-name guard.
function collectStringKeyedEntries(node, acc) {
  if (node == null || typeof node !== "object") return acc;
  if (Array.isArray(node)) {
    for (const v of node) collectStringKeyedEntries(v, acc);
    return acc;
  }
  for (const k of Object.keys(node)) {
    const v = node[k];
    if (typeof v === "string") acc.push([k, v]);
    else collectStringKeyedEntries(v, acc);
  }
  return acc;
}

// Build a fully-injected `deps` whose body-bearing primitives misbehave by
// returning response bodies, and whose other primitives return benign,
// body-free observations. The dependent analyzers (cookies / mixed-content /
// tech) are controlled here and never echo the headers body back, so any body
// that surfaces in the result came from the ENGINE retaining it, not from a
// fake analyzer leaking it.
function makeDeps({ exposedBody, headersBody, exposedProbes }) {
  return {
    checkDns: async () => ({
      nameservers: ["ns1.example.com"],
      spf: true,
      dmarc: false,
      mx: [],
    }),
    lookupCaa: async () => ({ status: "present", records: ['0 issue "ca.example"'] }),
    checkSsl: async () => ({
      validTo: "2030-01-01T00:00:00Z",
      issuer: "Example CA",
      subject: "example.com",
      valid: true,
    }),
    checkSubdomains: async () => ({ subdomains: ["api.example.com"] }),
    // MISBEHAVING: returns a homepage body. Must not be retained in the result.
    checkHeaders: async () => ({
      hsts: true,
      csp: true,
      xfo: false,
      xcto: false,
      referrerPolicy: false,
      permissionsPolicy: false,
      server: "nginx",
      poweredBy: null,
      reachable: true,
      servedHttps: true,
      setCookies: ["sid=abc"],
      body: headersBody,
      error: null,
    }),
    checkRobotsSitemap: async () => ({
      sensitiveDisallows: ["/admin"],
      sitemapPresent: true,
      sitemapUrlCount: 3,
    }),
    // MISBEHAVING: probes carry body/content-like fields alongside the legit
    // status-shaped fields. The engine must keep ONLY {path, status, exposed}.
    checkSensitiveFiles: async () =>
      exposedProbes.map((p) => ({
        path: p.path,
        status: p.status,
        exposed: p.exposed,
        body: exposedBody,
        content: exposedBody,
        text: exposedBody,
        html: exposedBody,
      })),
    inferProvider: () => "Cloudflare",
    // Dependent analyzers — controlled, body-free outputs.
    analyzeCookies: () => ({ missingSecure: ["sid"], missingHttpOnly: [], missingSameSite: [] }),
    analyzeMixedContent: () => ({ applicable: true, count: 1, samples: ["http://cdn.example/x.js"] }),
    fingerprintTech: () => ({ detected: ["nginx"] }),
    withTimeout,
    env: {},
  };
}

// Arbitrary body content. The fixed sentinel prefix guarantees detectability even
// when the generated suffix is empty; the arbitrary suffix exercises varied content.
const bodyArb = (sentinel) =>
  fc.string({ maxLength: 64 }).map((s) => sentinel + s);

// Arbitrary set of sensitive-file probes, at least one of which is exposed (200)
// so the exposed-files outcome carries findings to inspect.
const exposedProbesArb = fc
  .array(
    fc.record({
      path: fc.constantFrom("/.env", "/.git/config", "/config.json", "/backup.sql", "/.htaccess"),
      status: fc.constantFrom(200, 301, 403, 404, 500, null),
      exposed: fc.boolean(),
    }),
    { minLength: 1, maxLength: 5 }
  )
  // Ensure at least one exposed=200 probe so there is a finding to validate.
  .map((probes) => {
    const hasExposed = probes.some((p) => p.exposed && p.status === 200);
    if (hasExposed) return probes;
    return [{ path: "/.env", status: 200, exposed: true }, ...probes];
  });

describe("Feature: passive-scan-engine, Property 6: No response bodies retained", () => {
  it("never retains an HTTP response body anywhere in the Scan_Result; exposed-file findings carry only {path, status, exposed}", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 40 }).map((d) => `${d.replace(/[^a-z0-9.-]/gi, "") || "x"}.example.com`),
        bodyArb(EXPOSED_SENTINEL),
        bodyArb(HEADERS_SENTINEL),
        exposedProbesArb,
        async (domain, exposedBody, headersBody, exposedProbes) => {
          const deps = makeDeps({ exposedBody, headersBody, exposedProbes });

          const result = await runScan(domain, deps);

          // We injected resolvable DNS, so this resolves to a full Scan_Result.
          expect(result.type).toBe(RESULT_TYPE.SCAN);

          // (a) Exposed-file findings carry ONLY status-derived fields
          //     (path, status, exposed) — no body/content/etc. (Req 3.1, 3.2).
          const exposedOutcome = result.outcomes.find((o) => o.id === "exposed-files");
          expect(exposedOutcome).toBeDefined();
          for (const finding of exposedOutcome.findings) {
            expect(Object.keys(finding).sort()).toEqual(["exposed", "path", "status"]);
          }

          // (b) Deep-walk the ENTIRE Scan_Result: no injected body marker may
          //     survive anywhere — not in findings, not in any carried-through
          //     observation (Req 3.2: discard each HTTP response body without
          //     storing it in the Scan_Result).
          const allStrings = collectStringValues(result, []);
          for (const s of allStrings) {
            expect(s.includes(EXPOSED_SENTINEL)).toBe(false);
            expect(s.includes(HEADERS_SENTINEL)).toBe(false);
          }

          // (c) Explicit key-name guard: no body/content/text/html-style key may
          //     hold a retained response payload anywhere in the result.
          const keyedEntries = collectStringKeyedEntries(result, []);
          for (const [key, value] of keyedEntries) {
            if (BODY_LIKE_KEYS.includes(key.toLowerCase())) {
              expect(value.includes(EXPOSED_SENTINEL)).toBe(false);
              expect(value.includes(HEADERS_SENTINEL)).toBe(false);
            }
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
