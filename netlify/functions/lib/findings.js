// Turn the raw scan result into a list of discrete "findings" — one per issue —
// each of which Pass 1 classifies independently. Also provides a deterministic
// fallback classification used if the LLM is unavailable.

import { inferProvider } from "./checks.js";

// --- Record-value suggestions for email-auth / CAA findings (literal, paste-ready) ---

// Map common mail providers (by MX hostname) to their SPF include: token.
function spfIncludeForMx(mxList = []) {
  const hosts = mxList.map((m) => String(m.exchange || "").toLowerCase());
  const joined = hosts.join(" ");
  if (/aspmx\.l\.google\.com|googlemail\.com|google\.com/.test(joined)) return "include:_spf.google.com";
  if (/mail\.protection\.outlook\.com|outlook\.com/.test(joined)) return "include:spf.protection.outlook.com";
  if (/zoho/.test(joined)) return "include:zoho.com";
  if (/mailgun/.test(joined)) return "include:mailgun.org";
  if (/sendgrid/.test(joined)) return "include:sendgrid.net";
  if (/pphosted|proofpoint/.test(joined)) return "include:_spf.pphosted.com";
  if (/mimecast/.test(joined)) return "include:_netblocks.mimecast.com";
  if (/messagingengine|fastmail/.test(joined)) return "include:spf.messagingengine.com";
  if (/secureserver\.net/.test(joined)) return "include:secureserver.net";
  return null;
}

// Build the safest correct SPF record we can suggest from the domain's MX situation.
export function buildSpfSuggestion(mxList = []) {
  if (!mxList || mxList.length === 0) {
    // No mail servers detected → the strict, safe default that forbids all senders.
    return "v=spf1 -all";
  }
  const inc = spfIncludeForMx(mxList);
  if (inc) return `v=spf1 ${inc} -all`;
  // MX present but provider unknown → authorize the domain's own MX hosts.
  return "v=spf1 mx -all";
}

export function buildDmarcSuggestion(domain) {
  return `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; ruf=mailto:dmarc@${domain}; fo=1`;
}

export function buildCaaSuggestion() {
  return '0 issue "letsencrypt.org"';
}

// Build the list of raw findings to send to Pass 1.
export function deriveFindings(scan) {
  const findings = [];
  const provider = inferProvider(scan.nameservers);

  // Email auth
  if (!scan.dns.spf) {
    const spfVal = buildSpfSuggestion(scan.dns.mx);
    const mxNote = (scan.dns.mx && scan.dns.mx.length)
      ? `MX records point to: ${scan.dns.mx.map((m) => m.exchange).join(", ")}.`
      : "No MX (mail) records were found for this domain.";
    findings.push({
      id: "spf-missing",
      type: "email-auth",
      label: "Missing SPF record",
      detail:
        `No SPF (Sender Policy Framework) TXT record was found for this domain. ${mxNote} A correct, safe SPF record for this domain would be: ${spfVal}`,
      suggestedSnippet: spfVal,
    });
  }
  if (!scan.dns.dmarc) {
    const dmarcVal = buildDmarcSuggestion(scan.domain);
    findings.push({
      id: "dmarc-missing",
      type: "email-auth",
      label: "Missing DMARC record",
      detail:
        `No DMARC policy record was found at _dmarc.${scan.domain}. A correct starter DMARC record (monitor-only) would be: ${dmarcVal}`,
      suggestedSnippet: dmarcVal,
    });
  }

  // SSL / TLS
  if (scan.ssl) {
    if (scan.ssl.error) {
      findings.push({
        id: "ssl-error",
        type: "tls",
        label: "TLS/SSL could not be verified",
        detail: `Connecting over HTTPS failed or the certificate could not be read (${scan.ssl.error}).`,
      });
    } else if (scan.ssl.expiresInDays !== null) {
      if (scan.ssl.expiresInDays <= 0) {
        findings.push({
          id: "ssl-expired",
          type: "tls",
          label: "Expired TLS certificate",
          detail: `The TLS certificate appears to have expired (${scan.ssl.expiresInDays} days).`,
        });
      } else if (scan.ssl.expiresInDays <= 14) {
        findings.push({
          id: "ssl-expiring",
          type: "tls",
          label: "TLS certificate expiring very soon",
          detail: `The TLS certificate expires in ${scan.ssl.expiresInDays} days (issuer: ${scan.ssl.issuer || "unknown"}).`,
        });
      } else if (scan.ssl.expiresInDays <= 30) {
        findings.push({
          id: "ssl-expiring-soon",
          type: "tls",
          label: "TLS certificate expiring within a month",
          detail: `The TLS certificate expires in ${scan.ssl.expiresInDays} days (issuer: ${scan.ssl.issuer || "unknown"}).`,
        });
      }
    }
  }

  // Security headers
  const headerMap = [
    {
      key: "hsts",
      id: "hdr-hsts",
      label: "Missing HTTP Strict-Transport-Security header",
      detail:
        "The HSTS header is absent, so browsers aren't forced to use HTTPS.",
    },
    {
      key: "csp",
      id: "hdr-csp",
      label: "Missing Content-Security-Policy header",
      detail:
        "No Content-Security-Policy header was returned, increasing XSS/injection risk.",
    },
    {
      key: "xfo",
      id: "hdr-xfo",
      label: "Missing X-Frame-Options header",
      detail:
        "No X-Frame-Options header was returned, allowing potential clickjacking via framing.",
    },
    {
      key: "xcto",
      id: "hdr-xcto",
      label: "Missing X-Content-Type-Options header",
      detail:
        "No X-Content-Type-Options: nosniff header was returned, allowing MIME-type sniffing.",
    },
  ];
  if (scan.headers && scan.headers.reachable) {
    for (const hm of headerMap) {
      if (!scan.headers[hm.key]) {
        findings.push({
          id: hm.id,
          type: "header",
          label: hm.label,
          detail: hm.detail,
        });
      }
    }
  }

  // Notable subdomains (dev/staging/test/admin etc. exposed publicly)
  const notable = pickNotableSubdomains(scan.subdomains || []);
  for (const sub of notable) {
    findings.push({
      id: `subdomain-${sub}`,
      type: "subdomain",
      label: `Sensitive-looking subdomain exposed: ${sub}`,
      detail: `The subdomain "${sub}" is publicly discoverable via certificate transparency logs and its name suggests a non-production or administrative environment.`,
    });
  }

  // Large attack surface (lots of subdomains)
  if ((scan.subdomains || []).length > 25) {
    findings.push({
      id: "subdomain-surface",
      type: "subdomain",
      label: "Large public subdomain footprint",
      detail: `${scan.subdomains.length} subdomains are publicly discoverable via certificate transparency, which expands the attack surface.`,
    });
  }

  // CAA record — only flag a genuine "missing" (not an "unknown" lookup failure)
  if (scan.dns && scan.dns.caa && scan.dns.caa.status === "missing") {
    const caaVal = buildCaaSuggestion();
    findings.push({
      id: "caa-missing",
      type: "dns",
      label: "No CAA record set",
      detail:
        `The domain has no CAA (Certification Authority Authorization) DNS record, so any certificate authority is permitted to issue certificates for it. A starter CAA record would be: ${caaVal}`,
      suggestedSnippet: caaVal,
    });
  }

  // Cookie security flags (grouped per missing attribute to avoid clutter)
  if (scan.cookies && scan.cookies.total > 0) {
    const c = scan.cookies;
    if (c.missingSecure.length) {
      findings.push({
        id: "cookie-secure",
        type: "cookie",
        label: `${c.missingSecure.length} cookie${c.missingSecure.length === 1 ? "" : "s"} missing the Secure flag`,
        detail: `These cookies can be transmitted over unencrypted HTTP: ${c.missingSecure.slice(0, 8).join(", ")}.`,
      });
    }
    if (c.missingHttpOnly.length) {
      findings.push({
        id: "cookie-httponly",
        type: "cookie",
        label: `${c.missingHttpOnly.length} cookie${c.missingHttpOnly.length === 1 ? "" : "s"} missing the HttpOnly flag`,
        detail: `These cookies are readable by client-side JavaScript, exposing them to theft via XSS: ${c.missingHttpOnly.slice(0, 8).join(", ")}.`,
      });
    }
    if (c.missingSameSite.length) {
      findings.push({
        id: "cookie-samesite",
        type: "cookie",
        label: `${c.missingSameSite.length} cookie${c.missingSameSite.length === 1 ? "" : "s"} missing the SameSite attribute`,
        detail: `Without SameSite, these cookies may be sent on cross-site requests, enabling CSRF: ${c.missingSameSite.slice(0, 8).join(", ")}.`,
      });
    }
  }

  // Mixed content (only when the page itself was served over HTTPS)
  if (scan.mixedContent && scan.mixedContent.applicable && scan.mixedContent.count > 0) {
    findings.push({
      id: "mixed-content",
      type: "mixed-content",
      label: `Mixed content: ${scan.mixedContent.count} insecure resource reference${scan.mixedContent.count === 1 ? "" : "s"}`,
      detail: `The HTTPS homepage references resources over plain http:// (e.g. ${(scan.mixedContent.samples || []).join(", ") || "various hosts"}), which browsers may block or which weaken the page's security.`,
    });
  }

  // Sensitive paths disclosed in robots.txt
  if (scan.robots && scan.robots.sensitiveDisallows && scan.robots.sensitiveDisallows.length) {
    findings.push({
      id: "robots-sensitive",
      type: "info-leak",
      label: "robots.txt discloses sensitive-looking paths",
      detail: `robots.txt lists Disallow entries that point to potentially sensitive areas: ${scan.robots.sensitiveDisallows.join(", ")}. robots.txt is public, so this advertises these paths to anyone.`,
    });
  }

  // Exposed sensitive files — each is individually serious, so NOT grouped
  for (const f of scan.exposedFiles || []) {
    if (!f.exposed) continue;
    findings.push({
      id: `exposed-file-${f.path}`,
      type: "exposure",
      path: f.path,
      label: `Publicly accessible file: ${f.path}`,
      detail: `A request to ${f.path} returned HTTP 200, indicating the file is publicly served. (Only the status code was checked; the contents were intentionally not read.)`,
    });
  }

  // Tech-stack fingerprint is informational context, NOT a scored finding.
  const techStack = scan.tech || { server: null, poweredBy: null, detected: [] };

  return { findings, provider, techStack };
}

const NOTABLE_PATTERNS = [
  "dev",
  "develop",
  "development",
  "staging",
  "stage",
  "test",
  "testing",
  "qa",
  "uat",
  "admin",
  "internal",
  "intranet",
  "vpn",
  "jenkins",
  "gitlab",
  "git",
  "jira",
  "confluence",
  "phpmyadmin",
  "db",
  "database",
  "backup",
  "old",
  "legacy",
  "beta",
  "sandbox",
  "demo",
];

function pickNotableSubdomains(subdomains) {
  const hits = [];
  for (const sub of subdomains) {
    const firstLabel = sub.split(".")[0];
    if (NOTABLE_PATTERNS.some((p) => firstLabel === p || firstLabel.startsWith(p + "-") || firstLabel.endsWith("-" + p))) {
      hits.push(sub);
    }
  }
  // cap to keep Pass 1 fan-out reasonable
  return hits.slice(0, 6);
}

// --- Deterministic fallback severity map (used if the LLM is unavailable) ---
const SEVERITY_MAP = {
  "spf-missing": "medium",
  "dmarc-missing": "high",
  "ssl-error": "high",
  "ssl-expired": "critical",
  "ssl-expiring": "high",
  "ssl-expiring-soon": "medium",
  "hdr-hsts": "medium",
  "hdr-csp": "medium",
  "hdr-xfo": "low",
  "hdr-xcto": "low",
  "subdomain-surface": "low",
  "caa-missing": "low",
  "cookie-secure": "medium",
  "cookie-httponly": "medium",
  "cookie-samesite": "low",
  "mixed-content": "medium",
  "robots-sensitive": "medium",
};

const FALLBACK_TEXT = {
  "spf-missing": {
    explanation:
      "Without an SPF record, attackers can more easily spoof emails from your domain, putting your brand and customers at risk of phishing.",
    recommendation:
      "Publish an SPF TXT record listing the mail servers allowed to send on your behalf, e.g. \"v=spf1 include:_spf.yourprovider.com -all\".",
  },
  "dmarc-missing": {
    explanation:
      "Without DMARC, you have no policy telling receiving mail servers what to do with spoofed messages, and no visibility into abuse of your domain.",
    recommendation:
      'Add a DMARC TXT record at _dmarc.yourdomain with at least "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to start monitoring, then tighten to p=quarantine or p=reject.',
  },
  "ssl-error": {
    explanation:
      "The site's HTTPS certificate could not be verified, which may mean visitors see security warnings or that traffic isn't properly encrypted.",
    recommendation:
      "Verify the certificate is installed correctly on port 443 and that the full chain is served. Consider a free, auto-renewing certificate from Let's Encrypt.",
  },
  "ssl-expired": {
    explanation:
      "An expired certificate causes browsers to block the site with a full-page security warning, which destroys user trust and breaks the site.",
    recommendation:
      "Renew the TLS certificate immediately and enable automatic renewal so this cannot recur.",
  },
  "ssl-expiring": {
    explanation:
      "The certificate expires very soon; if it lapses, visitors will be blocked by browser security warnings.",
    recommendation:
      "Renew the certificate now and enable auto-renewal (most providers and Let's Encrypt support this).",
  },
  "ssl-expiring-soon": {
    explanation:
      "The certificate expires within a month. While not urgent, an unmonitored expiry can cause an outage.",
    recommendation:
      "Schedule renewal and enable automatic certificate renewal to avoid surprises.",
  },
  "hdr-hsts": {
    explanation:
      "Without HSTS, a visitor's first request can be downgraded to insecure HTTP, exposing them to interception.",
    recommendation:
      'Add the header "Strict-Transport-Security: max-age=31536000; includeSubDomains" once you are confident all subdomains support HTTPS.',
  },
  "hdr-csp": {
    explanation:
      "A missing Content-Security-Policy makes cross-site scripting (XSS) attacks easier to execute if any input is mishandled.",
    recommendation:
      "Define a Content-Security-Policy header that restricts script and resource origins; start in report-only mode to avoid breakage.",
  },
  "hdr-xfo": {
    explanation:
      "Without X-Frame-Options, your pages can be embedded in malicious frames, enabling clickjacking.",
    recommendation:
      'Add "X-Frame-Options: SAMEORIGIN" (or a frame-ancestors directive in your CSP).',
  },
  "hdr-xcto": {
    explanation:
      "Without X-Content-Type-Options, browsers may MIME-sniff responses, which can turn benign files into attack vectors.",
    recommendation: 'Add the header "X-Content-Type-Options: nosniff".',
  },
  "subdomain-surface": {
    explanation:
      "A large number of publicly discoverable subdomains widens the attack surface; forgotten or unmaintained hosts are common entry points.",
    recommendation:
      "Inventory all subdomains, decommission unused ones, and ensure each remaining host is patched and monitored.",
  },
  "caa-missing": {
    explanation:
      "Without a CAA record, any certificate authority can issue a certificate for your domain, which slightly raises the risk of unauthorized or mis-issued certificates.",
    recommendation:
      'Add a CAA DNS record naming your CA, e.g. "0 issue \\"letsencrypt.org\\"", to restrict who can issue certificates for the domain.',
  },
  "cookie-secure": {
    explanation:
      "Cookies without the Secure flag can be sent over unencrypted HTTP, where they can be intercepted — a serious risk for session cookies.",
    recommendation:
      "Set the Secure attribute on all cookies so they are only ever sent over HTTPS.",
  },
  "cookie-httponly": {
    explanation:
      "Cookies without HttpOnly are readable by JavaScript, so a single cross-site scripting flaw can let an attacker steal them (e.g. session hijacking).",
    recommendation:
      "Add the HttpOnly attribute to cookies that don't need to be accessed by client-side scripts, especially session cookies.",
  },
  "cookie-samesite": {
    explanation:
      "Without a SameSite attribute, cookies may be sent on cross-site requests, which can enable cross-site request forgery (CSRF).",
    recommendation:
      'Set SameSite=Lax (or Strict) on your cookies unless you specifically need cross-site behavior.',
  },
  "mixed-content": {
    explanation:
      "Your secure page loads some resources over plain HTTP. Browsers may block them or show warnings, and any HTTP resource can be tampered with in transit.",
    recommendation:
      "Update all resource URLs to https:// (or protocol-relative) and consider a Content-Security-Policy with upgrade-insecure-requests.",
  },
  "robots-sensitive": {
    explanation:
      "Your robots.txt lists paths to sensitive areas. Because robots.txt is public, this effectively hands attackers a map of where to look.",
    recommendation:
      "Remove sensitive paths from robots.txt and protect those areas with authentication or network restrictions instead of relying on obscurity.",
  },
};

// Per-file fallback copy for the exposed-file probe (keyed by path).
const EXPOSED_FILE_INFO = {
  "/.git/config": {
    severity: "critical",
    explanation:
      "An exposed .git/config means your Git repository is publicly accessible, often allowing attackers to download your entire source code and any secrets committed to it.",
    recommendation:
      "Block all access to the .git directory at the web server/CDN level immediately, and rotate any credentials that may have been committed.",
  },
  "/.git/HEAD": {
    severity: "critical",
    explanation:
      "An exposed .git/HEAD indicates the Git repository is publicly reachable, which can let attackers reconstruct your source code and leaked secrets.",
    recommendation:
      "Deny web access to the entire .git directory now, and audit the repo history for committed secrets.",
  },
  "/.env": {
    severity: "critical",
    explanation:
      "A publicly accessible .env file commonly contains database passwords, API keys and other secrets — this is one of the most damaging exposures possible.",
    recommendation:
      "Remove the file from the web root immediately, block access to dotfiles, and rotate every credential it contained.",
  },
  "/wp-config.php.bak": {
    severity: "critical",
    explanation:
      "A backup of wp-config.php is served as plain text (the .bak isn't executed by PHP), exposing your WordPress database credentials and secret keys.",
    recommendation:
      "Delete the backup file, block access to .bak files, and rotate the database password and WordPress salts.",
  },
  "/.DS_Store": {
    severity: "medium",
    explanation:
      "An exposed .DS_Store file leaks the names of files and folders in that directory, helping attackers discover hidden or sensitive paths.",
    recommendation:
      "Delete .DS_Store files from the server and block access to them; add them to .gitignore/deploy ignore lists.",
  },
};

export function fallbackClassify(finding) {
  let severity = SEVERITY_MAP[finding.id];
  let text = FALLBACK_TEXT[finding.id];

  // Exposed-file findings have dynamic ids (exposed-file-/path)
  if (!severity && finding.type === "exposure") {
    const info = EXPOSED_FILE_INFO[finding.path] || {
      severity: "high",
      explanation:
        "A sensitive file appears to be publicly accessible, which can leak configuration or source code.",
      recommendation:
        "Block public access to this file at the web server or CDN level and rotate any secrets it may contain.",
    };
    severity = info.severity;
    text = { explanation: info.explanation, recommendation: info.recommendation };
  }

  // Subdomain findings have dynamic ids
  if (!severity && finding.type === "subdomain") {
    severity = "medium";
    text = {
      explanation:
        "A non-production or administrative subdomain is publicly discoverable. These environments are often less hardened and can leak data or provide a foothold.",
      recommendation:
        "Restrict access to this host (IP allow-listing, VPN, or auth), confirm it is intentionally public, and remove it from public DNS if it is not needed.",
    };
  }

  severity = severity || "low";
  text = text || {
    explanation: "This finding may warrant review.",
    recommendation: "Review this item and remediate according to best practice.",
  };

  const snippet = finding.suggestedSnippet || FIX_SNIPPETS[finding.id] || null;

  // For record-based findings, make the recommendation itself contain the literal value.
  let recommendation = text.recommendation;
  if (snippet) {
    if (finding.id === "spf-missing") {
      recommendation = `Add this exact TXT record at your domain's root, then expand it as you add senders: ${snippet}`;
    } else if (finding.id === "dmarc-missing") {
      recommendation = `Add this exact TXT record at _dmarc.${(finding.detail.match(/_dmarc\.([^\s.]+(?:\.[^\s.]+)+)/) || [])[1] || "yourdomain"} to start monitoring, then tighten p=none to quarantine/reject: ${snippet}`;
    } else if (finding.id === "caa-missing") {
      recommendation = `Add this exact CAA record (replace the CA with whichever issues your certs): ${snippet}`;
    }
  }

  return {
    id: finding.id,
    title: finding.label,
    severity,
    explanation: text.explanation,
    recommendation,
    fixSnippet: snippet,
  };
}

// Paste-ready literal values for record-based findings.
const FIX_SNIPPETS = {
  "spf-missing": "v=spf1 include:_spf.yourprovider.com -all",
  "dmarc-missing": "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
  "caa-missing": '0 issue "letsencrypt.org"',
};

// Used by the LLM path to backfill a snippet when Claude omits one for a record-based finding.
export function defaultFixSnippet(finding) {
  if (finding && finding.suggestedSnippet) return finding.suggestedSnippet;
  return FIX_SNIPPETS[finding && finding.id] || null;
}
