// Netlify Function (v2, streaming): POST /api/scan
// Streams newline-delimited JSON progress events so the UI checklist reflects
// REAL concurrent progress. The passive-check ORCHESTRATION (concurrency,
// per-check timeouts, status derivation, the DNS-resolution gate, and bounded
// completion) is delegated to the pure-ish `runScan` engine in
// `lib/scan-engine.js`. This handler keeps domain validation and the downstream
// two-/three-pass AI analysis, and ADAPTS the engine's per-check progress events
// into the step-based checklist events the existing frontend consumes.
// Falls back to deterministic analysis if Claude is unavailable.

import { normalizeDomain, isValidDomain, inferProvider } from "./lib/checks.js";
import { runScan, defaultDeps, RESULT_TYPE } from "./lib/scan-engine.js";
import { deriveFindings, fallbackClassify } from "./lib/findings.js";
import {
  runPass1,
  runPass2,
  runPass3,
  attachTechStack,
  buildFallbackReport,
} from "./lib/analysis.js";

// ---------------------------------------------------------------------------
// AI-analysis budget
// ---------------------------------------------------------------------------
// The AI analysis (pass1 batched classification + pass2/pass3 run concurrently)
// gets its OWN fixed wall-clock budget, independent of how long the passive
// checks took. Earlier this was "total budget minus passive elapsed", which meant
// a slow crt.sh subdomain lookup would starve the AI and force a fallback even
// though the LLM was fine. Decoupling it guarantees the AI always gets enough time
// to finish; if the LLM itself is genuinely stuck/slow past the budget, we still
// ship the instant deterministic report so the scan never hangs.
//
// Tunable: lower for a snappier (more fallback-prone) demo; raise to give the LLM
// more room. The passive phase is separately bounded by the engine's watchdog.
const ANALYSIS_BUDGET_MS = 14000;

// Severity ordering for the deterministic fallback report (highest first).
const FALLBACK_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

// ---------------------------------------------------------------------------
// Engine-check → UI-step mapping
// ---------------------------------------------------------------------------
// The engine emits one Progress_Event per defined check ({ type, check, status,
// seq }). The frontend checklist (public/index.html) is organized into coarser
// steps. Each UI step ticks "done" only once EVERY engine check that feeds it has
// resolved, so the checklist still reflects honest progress. The grouping mirrors
// the checklist labels:
//   - dns        → "Resolving DNS, email auth & CAA"               (dns, caa, provider)
//   - ssl        → "Inspecting TLS certificate"                    (tls)
//   - subdomains → "Enumerating subdomains via cert transparency"  (subdomains)
//   - headers    → "Analyzing page security (headers, cookies, …)" (headers, cookies, mixed-content, tech)
//   - files      → "Probing robots.txt & exposed files"            (robots, exposed-files)
const STEP_GROUPS = {
  dns: ["dns", "caa", "provider"],
  ssl: ["tls"],
  subdomains: ["subdomains"],
  headers: ["headers", "cookies", "mixed-content", "tech"],
  files: ["robots", "exposed-files"],
};

// Invert STEP_GROUPS into a checkId → uiStep lookup.
const CHECK_TO_STEP = Object.create(null);
for (const [step, ids] of Object.entries(STEP_GROUPS)) {
  for (const id of ids) CHECK_TO_STEP[id] = step;
}

export default async function scan(req) {
  if (req.method === "OPTIONS") {
    return new Response("", { status: 204, headers: CORS });
  }
  if (req.method !== "POST") {
    return jsonResponse(405, { error: "Method not allowed. Use POST." });
  }

  let body;
  try {
    body = await req.json();
  } catch (_) {
    return jsonResponse(400, { error: "Invalid JSON body." });
  }

  const domain = normalizeDomain(body && body.domain);
  if (!domain || !isValidDomain(domain)) {
    return jsonResponse(400, {
      error:
        "Please enter a valid domain name, e.g. example.com (no http:// or paths).",
    });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (obj) => {
        try {
          controller.enqueue(encoder.encode(JSON.stringify(obj) + "\n"));
        } catch (_) {}
      };

      try {
        send({ type: "progress", step: "start", status: "done", domain });

        // --- Passive checks: delegate orchestration to the engine ----------
        // Capture the discovered subdomain count so the checklist can still show
        // the "N found" meta the original handler displayed. The engine emits the
        // `subdomains` progress event only AFTER this wrapped primitive resolves,
        // so the count is always populated by the time we translate that event.
        let subdomainCount = null;
        const deps = {
          ...defaultDeps,
          checkSubdomains: async (d) => {
            const r = await defaultDeps.checkSubdomains(d);
            subdomainCount = Array.isArray(r && r.subdomains) ? r.subdomains.length : 0;
            return r;
          },
        };

        // Adapter: translate engine Progress_Events into the UI's step-based
        // checklist events. A UI step is reported "done" exactly once — when the
        // last engine check feeding it resolves.
        const remaining = {};
        for (const [step, ids] of Object.entries(STEP_GROUPS)) remaining[step] = ids.length;

        const emit = (evt) => {
          if (!evt || evt.type !== "progress") return;
          const step = CHECK_TO_STEP[evt.check];
          if (!step || remaining[step] == null) return;
          remaining[step] -= 1;
          if (remaining[step] !== 0) return;
          const out = { type: "progress", step, status: "done" };
          if (step === "subdomains" && subdomainCount != null) out.count = subdomainCount;
          send(out);
        };

        const result = await runScan(domain, deps, emit);

        // DNS-resolution gate — preserve the original error contract & copy.
        if (result.type === RESULT_TYPE.RESOLUTION_FAILURE) {
          send({ type: "error", message: result.message });
          controller.close();
          return;
        }

        // Reconstruct the legacy `scanResult` shape the downstream AI passes and
        // the frontend depend on, from the engine's body-stripped Check_Outcomes.
        const scanResult = buildScanResult(domain, result);

        // --- AI analysis, capped so the report ALWAYS renders within budget --
        const { findings, provider, techStack } = deriveFindings(scanResult);

        // The instant deterministic report — the guaranteed result we ship if the
        // LLM pipeline exceeds ANALYSIS_BUDGET_MS.
        const deterministicReport = () => {
          const sorted = findings
            .map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }))
            .sort(
              (a, b) =>
                (FALLBACK_SEVERITY_RANK[b.severity] || 0) - (FALLBACK_SEVERITY_RANK[a.severity] || 0)
            );
          const r = buildFallbackReport(domain, sorted);
          r.provider = provider;
          r.domain = domain;
          attachTechStack(r, techStack);
          return r;
        };

        send({ type: "progress", step: "pass1", status: "start", total: findings.length });

        // The full LLM pipeline (pass1 → pass2 → pass3) as a single awaitable.
        let pass1Done = 0;
        const aiPipeline = (async () => {
          let classified;
          try {
            classified = await runPass1(findings, provider, techStack, () => {
              pass1Done += 1;
              send({ type: "progress", step: "pass1", status: "tick", done: pass1Done, total: findings.length });
            });
          } catch (_) {
            classified = findings.map((f) => ({ ...fallbackClassify(f), type: f.type, _source: "fallback" }));
          }
          send({ type: "progress", step: "pass1", status: "done" });

          // pass2 (executive synthesis) and pass3 (attacker narrative) are
          // INDEPENDENT: the risk score/level and findings pass3 needs are
          // computed deterministically from pass1's output, not from pass2's
          // prose. So we run them CONCURRENTLY, cutting a full LLM round-trip off
          // the critical path. pass3 runs against a deterministic base report.
          const sortedClassified = [...classified].sort(
            (a, b) =>
              (FALLBACK_SEVERITY_RANK[b.severity] || 0) - (FALLBACK_SEVERITY_RANK[a.severity] || 0)
          );
          const baseReport = buildFallbackReport(domain, sortedClassified);

          send({ type: "progress", step: "pass2", status: "start" });
          send({ type: "progress", step: "pass3", status: "start" });
          const [pass2Rep, narrative] = await Promise.all([
            runPass2(classified, domain, techStack).catch(() => null),
            runPass3(baseReport, domain).catch(() => null),
          ]);
          send({ type: "progress", step: "pass2", status: "done" });
          send({ type: "progress", step: "pass3", status: "done" });

          // pass2's report already carries the deterministic score/level/findings
          // plus the LLM summary; fall back to the deterministic base if it failed.
          const rep = pass2Rep || baseReport;
          rep.provider = provider;
          rep.domain = domain;
          attachTechStack(rep, techStack);
          if (narrative) {
            rep.attackScenario = narrative.attackScenario;
            rep.ifUnaddressed = narrative.ifUnaddressed;
          }
          return rep;
        })();

        // Give the AI analysis its OWN fixed budget, independent of how long the
        // passive phase took, so a slow crt.sh lookup can't starve it. If the LLM
        // pipeline doesn't finish in time we ship the deterministic report; the
        // frontend marks every checklist step done on the `result` event, so
        // partial AI progress is fine. (The pipeline keeps running but its later
        // sends hit a closed stream and are harmlessly ignored.)
        const analysisBudget = ANALYSIS_BUDGET_MS;
        let budgetTimer;
        const budget = new Promise((resolve) => {
          budgetTimer = setTimeout(() => resolve(null), analysisBudget);
        });
        const report =
          (await Promise.race([
            aiPipeline.then(
              (r) => {
                clearTimeout(budgetTimer);
                return r;
              },
              () => {
                clearTimeout(budgetTimer);
                return null;
              }
            ),
            budget,
          ])) || deterministicReport();

        send({ type: "result", scan: scanResult, report });
        controller.close();
      } catch (e) {
        send({ type: "error", message: "The scan failed unexpectedly. Please try again." });
        controller.close();
      }
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      ...CORS,
    },
  });
}

// ---------------------------------------------------------------------------
// Scan_Result → legacy scanResult adapter
// ---------------------------------------------------------------------------
// The engine returns `{ type, domain, scannedAt, outcomes }`, where each outcome
// is `{ id, status, findings, error, data? }` and `data` is the check's raw
// observation with every HTTP response body stripped. `deriveFindings` and the
// frontend consume the richer legacy `scanResult` shape, so we re-assemble it
// here from each check's `data`. A check that could not run carries no `data`, so
// we fall back to the same empty/neutral values the original inline handler used
// for its timeout fallbacks — no field the downstream layers rely on is dropped.
function buildScanResult(domain, result) {
  const dataOf = (id) => {
    const o = result.outcomes.find((x) => x.id === id);
    return o && o.data != null ? o.data : null;
  };

  const dns = dataOf("dns") || {};
  const tls = dataOf("tls") || {};
  const sub = dataOf("subdomains") || {};
  const hdr = dataOf("headers") || {};
  const cookies = dataOf("cookies") || {
    total: 0, missingSecure: [], missingHttpOnly: [], missingSameSite: [],
  };
  const mixedContent = dataOf("mixed-content") || { applicable: false, count: 0, samples: [] };
  const tech = dataOf("tech") || { server: null, poweredBy: null, detected: [] };
  const robots = dataOf("robots") || {};
  const files = dataOf("exposed-files") || [];
  const caa = dataOf("caa");
  const provider = dataOf("provider");

  return {
    domain,
    scannedAt: result.scannedAt || new Date().toISOString(),
    dns: {
      spf: !!dns.spf,
      dmarc: !!dns.dmarc,
      mx: dns.mx || [],
      a: dns.a || [],
      txt: dns.txt || [],
      caa: dns.caa || caa || { status: "unknown", records: [] },
    },
    ssl: {
      valid: !!tls.valid,
      expiresInDays: tls.expiresInDays ?? null,
      issuer: tls.issuer ?? null,
      subject: tls.subject ?? null,
      validTo: tls.validTo ?? null,
      error: tls.error || null,
    },
    subdomains: sub.subdomains || [],
    subdomainError: sub.error || null,
    certificates: sub.certificates || [],
    headers: {
      hsts: !!hdr.hsts,
      csp: !!hdr.csp,
      xfo: !!hdr.xfo,
      xcto: !!hdr.xcto,
      referrerPolicy: hdr.referrerPolicy || false,
      permissionsPolicy: hdr.permissionsPolicy || false,
      server: hdr.server || null,
      reachable: !!hdr.reachable,
      servedHttps: hdr.servedHttps || false,
      error: hdr.error || null,
    },
    cookies,
    mixedContent,
    tech,
    robots: {
      present: !!robots.robotsPresent,
      sensitiveDisallows: robots.sensitiveDisallows || [],
      sitemapPresent: !!robots.sitemapPresent,
      sitemapUrlCount: robots.sitemapUrlCount ?? null,
    },
    // Status-only by design — never any response body (Requirements 3.1, 3.2).
    exposedFiles: (files || []).map((f) => ({ path: f.path, status: f.status, exposed: f.exposed })),
    nameservers: dns.nameservers || [],
    provider: provider || inferProvider(dns.nameservers || []),
    hibp: {
      available: false,
      note: "Domain-level breach check requires a paid HIBP API key; not included.",
    },
  };
}

function jsonResponse(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}
