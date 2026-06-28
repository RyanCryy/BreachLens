// Netlify Function (v2, streaming): POST /api/scan
// Streams newline-delimited JSON progress events so the UI checklist reflects
// REAL concurrent progress — each passive check emits a tick the moment it
// resolves, then Pass 1 (parallel) and Pass 2 (synthesis) report progress too.
// Falls back to deterministic analysis if Claude is unavailable.

import {
  normalizeDomain,
  isValidDomain,
  checkDns,
  checkSsl,
  checkSubdomains,
  checkHeaders,
  checkRobotsSitemap,
  checkSensitiveFiles,
  analyzeCookies,
  analyzeMixedContent,
  fingerprintTech,
  inferProvider,
  withTimeout,
} from "./lib/checks.js";
import { deriveFindings, fallbackClassify } from "./lib/findings.js";
import { runPass1, runPass2, runPass3, attachTechStack } from "./lib/analysis.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

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

        // --- Passive checks, concurrent, each ticking the checklist as it lands ---
        const dnsP = withTimeout(checkDns(domain), 6000, {
          a: [], mx: [], txt: [], spf: false, dmarc: false, resolves: false, nameservers: [],
        }).then((r) => {
          send({ type: "progress", step: "dns", status: "done" });
          return r;
        });
        const sslP = withTimeout(checkSsl(domain), 8000, {
          valid: false, expiresInDays: null, issuer: null, error: "TLS check timed out",
        }).then((r) => {
          send({ type: "progress", step: "ssl", status: "done" });
          return r;
        });
        const subP = withTimeout(checkSubdomains(domain), 8000, {
          subdomains: [], error: "Subdomain lookup timed out",
        }).then((r) => {
          send({ type: "progress", step: "subdomains", status: "done", count: (r.subdomains || []).length });
          return r;
        });
        const hdrP = withTimeout(checkHeaders(domain), 9000, {
          hsts: false, csp: false, xfo: false, xcto: false, reachable: false,
          servedHttps: false, setCookies: [], body: "", server: null, poweredBy: null,
          error: "Header check timed out",
        }).then((r) => {
          send({ type: "progress", step: "headers", status: "done" });
          return r;
        });

        // robots.txt/sitemap.xml + exposed-file probe — grouped under one checklist item.
        const robotsP = withTimeout(checkRobotsSitemap(domain), 6000, {
          robotsPresent: false, sensitiveDisallows: [], sitemapPresent: false, sitemapUrlCount: null,
        });
        const filesP = withTimeout(checkSensitiveFiles(domain), 6000, []);
        const fileGroupP = Promise.all([robotsP, filesP]).then((r) => {
          send({ type: "progress", step: "files", status: "done" });
          return r;
        });

        const [dnsRes, sslRes, subRes, hdrRes, [robotsRes, filesRes]] = await Promise.all([
          dnsP, sslP, subP, hdrP, fileGroupP,
        ]);

        if (!dnsRes.resolves && !hdrRes.reachable) {
          send({
            type: "error",
            message: `We couldn't find "${domain}". Double-check the spelling — it may not exist or may not be publicly resolvable.`,
          });
          controller.close();
          return;
        }

        // Derive cookie / mixed-content / tech signals from the single homepage fetch.
        const cookies = analyzeCookies(hdrRes.setCookies || []);
        const mixedContent = analyzeMixedContent(hdrRes.body || "", hdrRes.servedHttps);
        const tech = fingerprintTech(hdrRes.server, hdrRes.poweredBy, hdrRes.body || "");

        const scanResult = {
          domain,
          scannedAt: new Date().toISOString(),
          dns: {
            spf: dnsRes.spf,
            dmarc: dnsRes.dmarc,
            mx: dnsRes.mx || [],
            a: dnsRes.a || [],
            txt: dnsRes.txt || [],
            caa: dnsRes.caa || { status: "unknown", records: [] },
          },
          ssl: {
            valid: sslRes.valid,
            expiresInDays: sslRes.expiresInDays,
            issuer: sslRes.issuer,
            subject: sslRes.subject,
            validTo: sslRes.validTo,
            error: sslRes.error || null,
          },
          subdomains: subRes.subdomains || [],
          subdomainError: subRes.error || null,
          certificates: subRes.certificates || [],
          headers: {
            hsts: hdrRes.hsts,
            csp: hdrRes.csp,
            xfo: hdrRes.xfo,
            xcto: hdrRes.xcto,
            referrerPolicy: hdrRes.referrerPolicy || false,
            permissionsPolicy: hdrRes.permissionsPolicy || false,
            server: hdrRes.server || null,
            reachable: hdrRes.reachable,
            servedHttps: hdrRes.servedHttps || false,
            error: hdrRes.error || null,
          },
          cookies,
          mixedContent,
          tech,
          robots: {
            present: robotsRes.robotsPresent,
            sensitiveDisallows: robotsRes.sensitiveDisallows || [],
            sitemapPresent: robotsRes.sitemapPresent,
            sitemapUrlCount: robotsRes.sitemapUrlCount,
          },
          // Only retain the exposed (200) entries; never any response body (status-only by design).
          exposedFiles: (filesRes || []).map((f) => ({ path: f.path, status: f.status, exposed: f.exposed })),
          nameservers: dnsRes.nameservers || [],
          provider: inferProvider(dnsRes.nameservers || []),
          hibp: {
            available: false,
            note: "Domain-level breach check requires a paid HIBP API key; not included.",
          },
        };

        // --- Two-pass AI analysis with progress + graceful fallback ---
        const { findings, provider, techStack } = deriveFindings(scanResult);

        send({ type: "progress", step: "pass1", status: "start", total: findings.length });

        let classified;
        let pass1Done = 0;
        try {
          classified = await runPass1(findings, provider, techStack, () => {
            pass1Done += 1;
            send({ type: "progress", step: "pass1", status: "tick", done: pass1Done, total: findings.length });
          });
        } catch (_) {
          classified = findings.map((f) => ({
            ...fallbackClassify(f),
            type: f.type,
            _source: "fallback",
          }));
        }
        send({ type: "progress", step: "pass1", status: "done" });

        send({ type: "progress", step: "pass2", status: "start" });
        const report = await runPass2(classified, domain, techStack);
        report.provider = provider;
        report.domain = domain;
        attachTechStack(report, techStack);
        send({ type: "progress", step: "pass2", status: "done" });

        // --- Pass 3: narrative layer (attacker scenario + risk trajectory) ---
        send({ type: "progress", step: "pass3", status: "start" });
        const narrative = await runPass3(report, domain);
        if (narrative) {
          report.attackScenario = narrative.attackScenario;
          report.ifUnaddressed = narrative.ifUnaddressed;
        }
        send({ type: "progress", step: "pass3", status: "done" });

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

function jsonResponse(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}
