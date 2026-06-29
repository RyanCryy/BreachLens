// Passive, no-auth security checks for a domain.
// Each check is defensive: it resolves with partial/empty data rather than throwing,
// so one slow or failing source never hangs or breaks the whole scan.

import dns from "node:dns/promises";
import tls from "node:tls";

// Generic timeout wrapper — resolves to `fallback` if `promise` doesn't settle in time.
export function withTimeout(promise, ms, fallback) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        resolve(fallback);
      }
    }, ms);
    Promise.resolve(promise)
      .then((val) => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve(val);
        }
      })
      .catch(() => {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve(fallback);
        }
      });
  });
}

// Normalize a user-supplied domain: strip scheme, path, port, whitespace.
export function normalizeDomain(input) {
  if (!input || typeof input !== "string") return "";
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "");
  d = d.replace(/^www\./, "");
  d = d.split("/")[0];
  d = d.split("?")[0];
  d = d.split(":")[0];
  return d.trim();
}

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
export function isValidDomain(d) {
  return DOMAIN_RE.test(d);
}

// --- DNS: A, MX, TXT (SPF + DMARC) + nameservers ---
export async function checkDns(domain) {
  const result = {
    a: [],
    mx: [],
    txt: [],
    spf: false,
    dmarc: false,
    resolves: false,
  };

  const [a, mx, txt, ns, dmarcTxt, caa] = await Promise.all([
    dns.resolve4(domain).catch(() => []),
    dns.resolveMx(domain).catch(() => []),
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveNs(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
    lookupCaa(domain),
  ]);

  result.a = Array.isArray(a) ? a : [];
  result.mx = (Array.isArray(mx) ? mx : [])
    .sort((x, y) => x.priority - y.priority)
    .map((r) => ({ exchange: r.exchange, priority: r.priority }));

  const flatTxt = (Array.isArray(txt) ? txt : []).map((parts) =>
    Array.isArray(parts) ? parts.join("") : String(parts)
  );
  result.txt = flatTxt;
  result.spf = flatTxt.some((t) => /v=spf1/i.test(t));

  const flatDmarc = (Array.isArray(dmarcTxt) ? dmarcTxt : []).map((parts) =>
    Array.isArray(parts) ? parts.join("") : String(parts)
  );
  result.dmarc = flatDmarc.some((t) => /v=DMARC1/i.test(t));

  result.nameservers = (Array.isArray(ns) ? ns : []).map((n) =>
    String(n).toLowerCase()
  );
  result.caa = caa; // { status: 'present'|'missing'|'unknown', records: [...] }
  result.resolves = result.a.length > 0 || result.mx.length > 0;

  return result;
}

// --- CAA record lookup. Distinguishes "no record" (missing) from "lookup failed/unsupported" (unknown). ---
export async function lookupCaa(domain) {
  try {
    const recs = await dns.resolveCaa(domain);
    return {
      status: recs && recs.length ? "present" : "missing",
      records: (recs || []).map((r) =>
        r.issue ? `issue ${r.issue}` : r.issuewild ? `issuewild ${r.issuewild}` : JSON.stringify(r)
      ),
    };
  } catch (e) {
    // ENODATA / ENOTFOUND -> the name has no CAA record (a real "missing").
    // Anything else (ESERVFAIL, ENOTIMP, timeouts) -> resolver couldn't tell us -> "unknown".
    if (e && (e.code === "ENODATA" || e.code === "ENOTFOUND")) {
      return { status: "missing", records: [] };
    }
    return { status: "unknown", records: [] };
  }
}

// --- SSL certificate: expiry, issuer, validity (port 443) ---
export function checkSsl(domain) {
  return new Promise((resolve) => {
    const out = {
      valid: false,
      expiresInDays: null,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      error: null,
    };

    let settled = false;
    let socket;
    const cleanup = () => {
      try {
        if (socket) {
          socket.removeAllListeners();
          socket.destroy();
        }
      } catch (_) {}
    };
    const finish = (v) => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(v);
      }
    };

    try {
      socket = tls.connect(
        {
          host: domain,
          port: 443,
          servername: domain,
          rejectUnauthorized: false, // we want to inspect even imperfect certs
          timeout: 7000,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate();
            if (cert && cert.valid_to) {
              const expiry = new Date(cert.valid_to);
              const now = new Date();
              out.expiresInDays = Math.round(
                (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
              );
              out.issuer =
                (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null;
              out.subject = (cert.subject && cert.subject.CN) || null;
              out.validFrom = cert.valid_from || null;
              out.validTo = cert.valid_to || null;
              out.valid = socket.authorized && out.expiresInDays > 0;
            } else {
              out.error = "No certificate presented";
            }
          } catch (e) {
            out.error = "Could not read certificate";
          }
          finish(out);
        }
      );

      socket.on("error", (e) => {
        if (!settled) out.error = e.code || "TLS connection failed";
        finish(out);
      });
      socket.on("timeout", () => {
        if (!settled) out.error = "TLS connection timed out";
        finish(out);
      });
    } catch (e) {
      out.error = "TLS connection failed";
      finish(out);
    }
  });
}

// --- Subdomain enumeration via crt.sh certificate transparency logs ---
export async function checkSubdomains(domain) {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(
      domain
    )}&output=json`;
    const res = await fetch(url, {
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(7500),
    });
    if (!res.ok) return { subdomains: [], error: `crt.sh HTTP ${res.status}` };

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      // crt.sh occasionally returns newline-delimited objects
      data = JSON.parse(`[${text.trim().split("\n").join(",")}]`);
    }

    const set = new Set();
    const certs = [];
    for (const row of data) {
      const names = String(row.name_value || "").split("\n");
      for (let n of names) {
        n = n.trim().toLowerCase();
        if (!n || n.startsWith("*.")) continue;
        if (n === domain) continue;
        if (n.endsWith(`.${domain}`)) set.add(n);
      }
      // Capture certificate issuance/expiry for the cert-history timeline.
      if (row.not_before && row.not_after) {
        certs.push({
          notBefore: row.not_before,
          notAfter: row.not_after,
          issuer: extractIssuerOrg(row.issuer_name),
          serial: row.serial_number || null,
        });
      }
    }
    const subdomains = Array.from(set).sort();
    const certificates = dedupeCertificates(certs);
    return { subdomains, count: subdomains.length, certificates };
  } catch (e) {
    return { subdomains: [], error: "Subdomain lookup failed" };
  }
}

// Pull the Organization (O=) out of an X.509 issuer DN string, falling back to CN.
function extractIssuerOrg(issuerName) {
  if (!issuerName) return "Unknown CA";
  const o = issuerName.match(/O\s*=\s*"?([^,"]+)"?/i);
  if (o) return o[1].trim();
  const cn = issuerName.match(/CN\s*=\s*"?([^,"]+)"?/i);
  return cn ? cn[1].trim() : "Unknown CA";
}

// Collapse certs that represent the same issuance for timeline purposes. crt.sh returns
// multiple log entries per real-world issuance — the precert + leaf (same serial), and
// often separate apex/www or ECDSA/RSA certs that share an IDENTICAL validity window and
// CA. For a coverage timeline we want ONE entry per (issuance day, expiry day, issuer),
// which also collapses entries that would otherwise render identically. Keep most recent 20.
function dedupeCertificates(certs) {
  const day = (s) => String(s || "").slice(0, 10); // ISO date portion only
  const seen = new Map();
  for (const c of certs) {
    if (!Number.isFinite(Date.parse(c.notBefore))) continue;
    const key = `${day(c.notBefore)}|${day(c.notAfter)}|${c.issuer}`;
    if (!seen.has(key)) seen.set(key, c);
  }
  const list = Array.from(seen.values());
  list.sort((a, b) => Date.parse(a.notBefore) - Date.parse(b.notBefore));
  return list.slice(-20);
}

// --- HTTP security headers (also captures cookies + body for reuse by other checks) ---
export async function checkHeaders(domain) {
  const out = {
    hsts: false,
    csp: false,
    xfo: false,
    xcto: false,
    referrerPolicy: false,
    permissionsPolicy: false,
    server: null,
    poweredBy: null,
    reachable: false,
    servedHttps: false,
    setCookies: [],
    body: "",
    error: null,
  };

  try {
    const res = await fetch(`https://${domain}`, {
      method: "GET",
      redirect: "follow",
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(8000),
    });
    out.reachable = true;
    const h = res.headers;
    out.hsts = h.has("strict-transport-security");
    out.csp = h.has("content-security-policy");
    out.xfo = h.has("x-frame-options");
    out.xcto = h.has("x-content-type-options");
    out.referrerPolicy = h.has("referrer-policy");
    out.permissionsPolicy = h.has("permissions-policy");
    out.server = h.get("server") || null;
    out.poweredBy = h.get("x-powered-by") || null;

    // Final URL protocol after redirects — used to decide if mixed-content applies.
    try {
      out.servedHttps = new URL(res.url || `https://${domain}`).protocol === "https:";
    } catch (_) {
      out.servedHttps = true;
    }

    // All Set-Cookie headers (undici exposes getSetCookie(); fall back to single header).
    if (typeof h.getSetCookie === "function") {
      out.setCookies = h.getSetCookie();
    } else if (h.get("set-cookie")) {
      out.setCookies = [h.get("set-cookie")];
    }

    // Read the HTML body ONCE so mixed-content + tech fingerprinting can reuse it.
    // Cap the scanned length to keep regex work bounded on huge pages.
    const text = await res.text().catch(() => "");
    out.body = text.length > 700000 ? text.slice(0, 700000) : text;
  } catch (e) {
    out.error = "Could not reach site over HTTPS";
  }
  return out;
}

// --- Infer hosting/DNS provider from nameservers (for tailored advice) ---
// IMPORTANT: match only against each provider's REAL authoritative nameserver
// hostname suffix, anchored to the end of the hostname. A loose substring match
// (e.g. treating "ns1.systemdns.com" as NS1 because it starts with "ns1") produces
// confidently-wrong guesses, which is exactly what we must avoid. If nothing matches
// precisely, return null so the report shows "not identified" and advice stays generic.
const PROVIDER_PATTERNS = [
  { name: "Cloudflare", re: /\.cloudflare\.com$/ },
  { name: "AWS Route 53", re: /\.awsdns-\d+\.(com|net|org|co\.uk)$/ },
  { name: "GoDaddy", re: /\.domaincontrol\.com$/ },
  { name: "Namecheap", re: /\.registrar-servers\.com$/ },
  { name: "NS1", re: /\.nsone\.net$/ },
  { name: "Google Cloud DNS", re: /\.googledomains\.com$/ },
  { name: "Azure DNS", re: /\.azure-dns\.(com|net|org|info)$/ },
  { name: "DigitalOcean", re: /\.digitalocean\.com$/ },
  { name: "DNSimple", re: /\.dnsimple\.com$/ },
  { name: "Akamai Edge DNS", re: /\.akam\.net$/ },
  { name: "DNS Made Easy", re: /\.dnsmadeeasy\.com$/ },
  { name: "Vercel", re: /\.vercel-dns\.com$/ },
];

export function inferProvider(nameservers = []) {
  const hosts = (nameservers || []).map((n) => String(n).toLowerCase().replace(/\.$/, ""));
  for (const { name, re } of PROVIDER_PATTERNS) {
    // Require a genuine suffix match on at least one nameserver hostname.
    if (hosts.some((h) => re.test(h))) return name;
  }
  return null;
}

// ============================================================
//  Additional passive checks (all free, no keys, no new deps)
// ============================================================

// --- robots.txt + sitemap.xml exposure ---
// Sensitive-sounding path fragments to look for in Disallow: rules.
const SENSITIVE_PATH_KEYWORDS = [
  "admin", "wp-admin", "backup", "backups", ".env", "config", "configuration",
  "database", "db", "sql", "private", "secret", "internal", "phpmyadmin",
  "login", "dashboard", "cpanel", "staging", "test", "old", ".git", "api/private",
  "uploads", "logs", "tmp", "temp", "user", "account", "billing", "invoice",
];

export async function checkRobotsSitemap(domain) {
  const out = {
    robotsPresent: false,
    disallowCount: 0,
    sensitiveDisallows: [],
    sitemapPresent: false,
    sitemapUrlCount: null,
  };

  // robots.txt
  try {
    const res = await fetch(`https://${domain}/robots.txt`, {
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const ct = res.headers.get("content-type") || "";
      const text = await res.text().catch(() => "");
      // Guard against soft-404s that return an HTML page with 200.
      if (!/text\/html/i.test(ct) || /disallow:/i.test(text)) {
        out.robotsPresent = true;
        const disallows = [];
        for (const line of text.split("\n")) {
          const m = line.match(/^\s*disallow:\s*(\S+)/i);
          if (m && m[1] && m[1] !== "/") disallows.push(m[1].trim());
        }
        out.disallowCount = disallows.length;
        const seen = new Set();
        for (const path of disallows) {
          const lower = path.toLowerCase();
          if (SENSITIVE_PATH_KEYWORDS.some((kw) => lower.includes(kw)) && !seen.has(lower)) {
            seen.add(lower);
            out.sensitiveDisallows.push(path);
          }
        }
        out.sensitiveDisallows = out.sensitiveDisallows.slice(0, 12);
      }
    }
  } catch (_) {
    /* absence / failure of robots.txt is not itself a finding */
  }

  // sitemap.xml — just note existence and (cheaply) count <url> entries
  try {
    const res = await fetch(`https://${domain}/sitemap.xml`, {
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const ct = res.headers.get("content-type") || "";
      const text = await res.text().catch(() => "");
      if (/xml/i.test(ct) || /<(urlset|sitemapindex)[\s>]/i.test(text)) {
        out.sitemapPresent = true;
        const matches = text.match(/<url>/gi);
        out.sitemapUrlCount = matches ? matches.length : 0;
      }
    }
  } catch (_) {
    /* absence of sitemap.xml is not a finding */
  }

  return out;
}

// --- Exposed sensitive file probe ---
// IMPORTANT (ethical/legal): we ONLY inspect the HTTP status code for these paths.
// We deliberately do NOT read, parse, log, or store ANY response body, since these
// paths may contain real secrets. Status-only is enough to flag exposure for the owner.
const SENSITIVE_FILES = ["/.git/config", "/.git/HEAD", "/.env", "/wp-config.php.bak", "/.DS_Store"];

export async function checkSensitiveFiles(domain) {
  const probes = SENSITIVE_FILES.map(async (path) => {
    try {
      const res = await fetch(`https://${domain}${path}`, {
        method: "GET",
        redirect: "manual",
        headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
        signal: AbortSignal.timeout(4000),
      });
      // Status code only. Intentionally never touching res.body / res.text().
      return { path, status: res.status, exposed: res.status === 200 };
    } catch (_) {
      return { path, status: null, exposed: false };
    }
  });
  // Run all probes concurrently; one slow path can't stall the rest.
  return Promise.all(probes);
}

// --- Status-only probe of ONE path (used by single-finding re-checks) ---
// IMPORTANT (ethical/legal): mirrors checkSensitiveFiles — we ONLY inspect the HTTP
// status code. We deliberately never read, parse, log, or store the response body,
// since the path may contain real secrets. Status-only is enough to confirm exposure.
export async function checkFileStatus(domain, path) {
  try {
    const res = await fetch(`https://${domain}${path}`, {
      method: "GET",
      redirect: "manual",
      headers: { "User-Agent": "BreachLens/1.0 (security scanner)" },
      signal: AbortSignal.timeout(6000),
    });
    // Status code only. Intentionally never touching res.body / res.text().
    return { reachable: true, status: res.status, exposed: res.status === 200 };
  } catch (_) {
    return { reachable: false, status: null, exposed: false };
  }
}

// --- Cookie security flags (operates on Set-Cookie headers already fetched) ---
export function analyzeCookies(setCookies = []) {
  const result = {
    total: 0,
    missingSecure: [],
    missingHttpOnly: [],
    missingSameSite: [],
  };
  for (const raw of setCookies) {
    if (!raw || typeof raw !== "string") continue;
    const parts = raw.split(";").map((p) => p.trim());
    const name = (parts[0] || "").split("=")[0].trim();
    if (!name) continue;
    result.total += 1;
    const attrs = parts.slice(1).map((p) => p.toLowerCase());
    const has = (attr) => attrs.some((a) => a === attr || a.startsWith(attr + "="));
    if (!has("secure")) result.missingSecure.push(name);
    if (!has("httponly")) result.missingHttpOnly.push(name);
    if (!has("samesite")) result.missingSameSite.push(name);
  }
  return result;
}

// --- Mixed content (only meaningful when the page itself is served over HTTPS) ---
export function analyzeMixedContent(body = "", servedHttps = true) {
  if (!servedHttps || !body) return { applicable: servedHttps, count: 0, samples: [] };
  const re = /(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
  const hosts = new Set();
  let count = 0;
  let m;
  while ((m = re.exec(body)) !== null) {
    count += 1;
    try {
      hosts.add(new URL(m[1]).host);
    } catch (_) {}
    if (count >= 200) break; // bound the work
  }
  return { applicable: true, count, samples: Array.from(hosts).slice(0, 6) };
}

// --- Tech-stack fingerprinting (informational only) ---
// Simple, easy-to-extend lookup table of body path patterns -> technology.
const TECH_BODY_PATTERNS = [
  { re: /\/wp-content\/|\/wp-includes\//i, name: "WordPress" },
  { re: /\/_next\//i, name: "Next.js" },
  { re: /\/_nuxt\//i, name: "Nuxt" },
  { re: /\/cdn-cgi\//i, name: "Cloudflare" },
  { re: /\/sites\/default\/|drupal/i, name: "Drupal" },
  { re: /\/media\/jui\/|joomla/i, name: "Joomla" },
  { re: /cdn\.shopify\.com|shopify/i, name: "Shopify" },
  { re: /wix\.com|wixstatic\.com/i, name: "Wix" },
  { re: /squarespace/i, name: "Squarespace" },
  { re: /data-reactroot|react(?:\.production)?\.min\.js/i, name: "React" },
  { re: /ng-version=|angular/i, name: "Angular" },
  { re: /\/wp-json\//i, name: "WordPress" },
  { re: /gatsby/i, name: "Gatsby" },
  { re: /webflow/i, name: "Webflow" },
];

export function fingerprintTech(server, poweredBy, body = "") {
  const detected = new Set();
  for (const { re, name } of TECH_BODY_PATTERNS) {
    if (re.test(body)) detected.add(name);
  }
  // Light hints from headers too
  if (poweredBy) {
    if (/php/i.test(poweredBy)) detected.add("PHP");
    if (/asp\.net/i.test(poweredBy)) detected.add("ASP.NET");
    if (/express/i.test(poweredBy)) detected.add("Express");
  }
  if (server) {
    if (/cloudflare/i.test(server)) detected.add("Cloudflare");
    if (/nginx/i.test(server)) detected.add("nginx");
    if (/apache/i.test(server)) detected.add("Apache");
    if (/^gws$|google frontend/i.test(server)) detected.add("Google Frontend");
  }
  return {
    server: server || null,
    poweredBy: poweredBy || null,
    detected: Array.from(detected),
  };
}
