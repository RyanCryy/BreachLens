// Netlify Function (v2): POST /api/chat
// Stateless follow-up Q&A. The client sends the full report JSON + prior chat turns
// on every message (no server-side persistence). Claude answers ONLY from the report.

import { callLLM, LLMError, callLLMJson } from "./lib/llm.js";
import { recheckFinding, isRecheckable, STATUS } from "./lib/recheck.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

const MAX_HISTORY = 12;

export default async function chat(req) {
  if (req.method === "OPTIONS") {
    return new Response("", { status: 204, headers: CORS });
  }
  if (req.method !== "POST") {
    return json(405, { error: "Method not allowed. Use POST." });
  }

  let body;
  try {
    body = await req.json();
  } catch (_) {
    return json(400, { error: "Invalid JSON body." });
  }

  const { message, report, scan, history } = body || {};
  if (!message || typeof message !== "string") {
    return json(400, { error: "Missing 'message'." });
  }
  if (!report) {
    return json(400, { error: "Missing report context." });
  }

  // Domain the re-check would target — derived from the report, falling back to the
  // raw scan signals. Wired here so the re-check branch (task 7.2) can pass it to
  // recheckFinding({ domain, findingId }).
  const domain = report?.domain || scan?.domain;

  // --- Recheck-intent resolution stage (Requirements 7.1, 7.2) ---
  // Determine whether this message is a Recheck_Intent and, if so, which existing
  // finding(s) it refers to. The resolved ids are ALWAYS a subset of the ids actually
  // present in report.findings — the model can never fabricate a target (Req 7.2).
  const recheckResolution = await resolveRecheckIntent({ message, report });

  // --- Recheck branch resolution + deterministic outcome templating ---
  // When the message is a Recheck_Intent we branch on the resolved finding set and,
  // for the single-recheckable case, delegate status computation to the shared router
  // (recheckFinding) — never inferring resolution from the stale report context
  // (Requirement 8.3). Every branch returns via the same json(200, { reply }) shape so
  // the frontend treats it like a normal chat reply. When recheck === false we fall
  // through, byte-for-byte, to the existing read-only answer path (Requirement 7.6).
  if (recheckResolution && recheckResolution.recheck === true) {
    const ids = Array.isArray(recheckResolution.findingIds) ? recheckResolution.findingIds : [];

    // 0 matches → no matching finding to re-check; do NOT call the router or any check (Req 7.3).
    if (ids.length === 0) {
      return json(200, {
        reply:
          "I don't see a matching finding in this report to re-check. Try naming the specific issue (for example \"re-check SPF\" or \"is the certificate still expiring?\").",
      });
    }

    // >1 matches → list the candidates and ask the user to pick one; no router/check (Req 7.5).
    if (ids.length > 1) {
      const list = ids.map((id) => `- ${findingTitle(report, id)} (${id})`).join("\n");
      return json(200, {
        reply:
          "More than one finding could match that. Which one would you like me to re-check?\n" +
          list,
      });
    }

    // Exactly one match.
    const findingId = ids[0];
    const title = findingTitle(report, findingId);

    // Non-recheckable → say so; do NOT call the router/check; do NOT fabricate a status (Req 7.4).
    if (!isRecheckable(findingId)) {
      return json(200, {
        reply: `The "${title}" finding (${findingId}) can't be automatically re-checked, so I can't confirm its current status here.`,
      });
    }

    // Recheckable → delegate to the shared router and template the outcome deterministically.
    try {
      const result = await recheckFinding({ domain, findingId });
      const status = result && result.status;
      // Router returned no usable status (unavailable) → couldn't complete; emit no status
      // statement and leave stored state unchanged (Req 8.5).
      if (
        status !== STATUS.RESOLVED &&
        status !== STATUS.UNRESOLVED &&
        status !== STATUS.INDETERMINATE
      ) {
        return json(200, { reply: routerUnavailableReply() });
      }
      return json(200, { reply: templateOutcome(findingId, title, status, result.message) });
    } catch (_) {
      // recheckFinding threw (router unavailable) → couldn't complete (Req 8.5).
      return json(200, { reply: routerUnavailableReply() });
    }
  }

  const context = buildContext(scan, report);

  const system = [
    "You are BreachLens, a friendly security analyst answering follow-up questions about a security report you already produced for a specific domain.",
    "",
    "STRICT RULES:",
    "- Answer ONLY using the findings and data in the report context below.",
    "- Do NOT invent new vulnerabilities, speculate about issues that weren't scanned, or imply you ran new checks.",
    "- If asked about something outside the report (e.g. penetration testing, source code, things not scanned), say plainly that it wasn't part of this passive scan and suggest what kind of check would cover it.",
    "- Be conversational and clear, for a non-technical business owner. Plain text only — no JSON, no markdown headers.",
    "- Keep answers concise (a short paragraph or a few short sentences) unless more detail is genuinely needed.",
    "",
    "=== REPORT CONTEXT ===",
    context,
    "=== END REPORT CONTEXT ===",
  ].join("\n");

  const messages = [];
  if (Array.isArray(history)) {
    for (const turn of history.slice(-MAX_HISTORY)) {
      if (
        turn &&
        (turn.role === "user" || turn.role === "assistant") &&
        typeof turn.content === "string" &&
        turn.content.trim()
      ) {
        messages.push({ role: turn.role, content: turn.content });
      }
    }
  }
  messages.push({ role: "user", content: message });

  try {
    const reply = await callLLM({
      system,
      messages,
      maxTokens: 700,
      temperature: 0.3,
      timeoutMs: 22000,
    });
    return json(200, { reply: reply.trim() });
  } catch (e) {
    const friendly =
      e instanceof LLMError
        ? "I'm having trouble reaching my analysis engine right now. Please try your question again in a moment."
        : "Something went wrong answering that. Please try again.";
    return json(200, { reply: friendly, degraded: true });
  }
}

// ------------------------------------------------------------------
//  Recheck-intent resolution (Requirements 7.1, 7.2)
//
//  Produces { recheck: boolean, findingIds: string[] } for a chat message.
//  Primary path is a single structured LLM JSON call given the message plus the
//  existing findings (id + title ONLY). A deterministic keyword fallback runs when
//  the LLM call fails or returns unparseable / malformed output, so chat degrades
//  gracefully. In every path the resolved ids are intersected with the ids actually
//  present in report.findings, so the model can never fabricate a target (Req 7.2).
// ------------------------------------------------------------------

// Patterns that signal a re-check intent in the deterministic fallback.
const RECHECK_PATTERNS = [
  /re-?check/i,
  /\bis\b.+\bfixed\b/i,
  /\bdid\b.+(?:get\s+)?fixed\b/i,
  /\bcheck\b.+\bagain\b/i,
  /\bverif(?:y|ied)\b/i,
  /\bstill\b.+\b(?:present|there|broken|missing|an?\s+issue|a\s+problem)\b/i,
];

// Per-id keyword aliases used by the deterministic fallback to map a message to a
// specific finding when the id/title tokens alone aren't enough.
const FINDING_ALIASES = {
  "spf-missing": ["spf"],
  "dmarc-missing": ["dmarc"],
  "caa-missing": ["caa"],
  "hdr-hsts": ["hsts", "strict transport", "strict-transport"],
  "hdr-csp": ["csp", "content security", "content-security"],
  "hdr-xfo": ["x-frame", "xfo", "clickjack", "frame options"],
  "hdr-xcto": ["x-content-type", "xcto", "nosniff", "content type options"],
  "cookie-secure": ["secure cookie", "cookie secure"],
  "cookie-httponly": ["httponly", "http only", "http-only"],
  "cookie-samesite": ["samesite", "same site", "same-site"],
  "mixed-content": ["mixed content", "mixed-content", "insecure content"],
  "robots-sensitive": ["robots", "robots.txt"],
};

export async function resolveRecheckIntent({ message, report }) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  // The authoritative set of ids — resolved ids must be a subset of this (Req 7.2).
  const reportIds = new Set(
    findings
      .map((f) => (f && typeof f.id === "string" ? f.id : null))
      .filter((id) => typeof id === "string" && id.length > 0)
  );

  // Primary: a single structured LLM JSON call.
  try {
    const llm = await llmResolveRecheck(message, findings);
    if (llm && typeof llm.recheck === "boolean") {
      const ids = Array.isArray(llm.findingIds) ? llm.findingIds : [];
      return { recheck: llm.recheck, findingIds: intersectIds(ids, reportIds) };
    }
    // Malformed shape — fall through to the deterministic fallback.
  } catch (_) {
    // LLM unavailable / unparseable — fall through to the deterministic fallback.
  }

  return keywordResolveRecheck(message, findings, reportIds);
}

// Single structured JSON call. Returns { recheck, findingIds } as produced by the
// model (not yet intersected). Throws on LLM/parse failure so the caller can fall back.
async function llmResolveRecheck(message, findings) {
  const findingList = findings
    .filter((f) => f && typeof f.id === "string" && f.id.length > 0)
    .map((f) => ({ id: f.id, title: typeof f.title === "string" ? f.title : "" }));

  const system = [
    "You classify whether a user's chat message is a request to RE-CHECK (re-verify) a security finding that BreachLens already reported for their domain, and which existing finding(s) it refers to.",
    "",
    'Respond with ONLY a JSON object of the exact shape: { "recheck": boolean, "findingIds": string[] }',
    "- recheck: true ONLY when the user is asking to re-verify / re-check / confirm whether an already-reported finding is now fixed (e.g. \"did my SPF get fixed?\", \"re-check DMARC\", \"is the cert still expired?\"). Otherwise false.",
    "- findingIds: the id(s) of the existing finding(s) the message refers to. Use ONLY ids from the list below — never invent an id. Use an empty array when recheck is false or nothing matches.",
    "",
    "Existing findings (id and title only):",
    JSON.stringify(findingList),
  ].join("\n");

  return await callLLMJson({
    system,
    messages: [{ role: "user", content: message }],
    maxTokens: 200,
    temperature: 0,
    timeoutMs: 12000,
  });
}

// Keep only ids that exist in the report, de-duplicated and order-preserving (Req 7.2).
function intersectIds(ids, reportIds) {
  const seen = new Set();
  const out = [];
  for (const id of ids) {
    if (typeof id === "string" && reportIds.has(id) && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

// Deterministic fallback: detect intent via patterns, then map to existing findings
// by matching the message against finding ids, titles, and known aliases. Only ids
// present in the report are ever returned (Req 7.2).
function keywordResolveRecheck(message, findings, reportIds) {
  const text = typeof message === "string" ? message : "";
  const recheck = RECHECK_PATTERNS.some((re) => re.test(text));
  if (!recheck) return { recheck: false, findingIds: [] };

  const lower = text.toLowerCase();
  const matched = [];
  for (const f of findings) {
    if (!f || typeof f.id !== "string" || !reportIds.has(f.id)) continue;
    if (messageMatchesFinding(lower, f) && !matched.includes(f.id)) {
      matched.push(f.id);
    }
  }
  return { recheck: true, findingIds: matched };
}

// Pragmatic match of a lower-cased message against one finding's id / title / aliases.
function messageMatchesFinding(lower, finding) {
  const id = finding.id.toLowerCase();
  if (lower.includes(id)) return true;

  // id tokens (split on - / _), ignoring very short/noise tokens.
  const idTokens = id.split(/[-_]/).filter((t) => t.length >= 3 && t !== "missing");
  if (idTokens.some((t) => lower.includes(t))) return true;

  // title tokens.
  const title = typeof finding.title === "string" ? finding.title.toLowerCase() : "";
  const titleTokens = title.split(/\W+/).filter((t) => t.length >= 4);
  if (titleTokens.some((t) => lower.includes(t))) return true;

  // explicit + prefix-derived aliases.
  const aliases = FINDING_ALIASES[id] || prefixAliases(id);
  if (aliases && aliases.some((a) => a && lower.includes(a))) return true;

  return false;
}

function prefixAliases(id) {
  if (id.startsWith("ssl-")) return ["ssl", "tls", "certificate", "cert", "https"];
  if (id.startsWith("exposed-file-")) {
    const path = id.slice("exposed-file-".length).toLowerCase();
    return ["exposed file", "exposed", path].filter(Boolean);
  }
  if (id.startsWith("subdomain-")) {
    const name = id.slice("subdomain-".length).toLowerCase();
    return ["subdomain", name].filter(Boolean);
  }
  return null;
}

// ------------------------------------------------------------------
//  Chat-triggered re-check outcome templating (Requirement 8)
//
//  Built DETERMINISTICALLY from the Recheck_Status returned by the shared router —
//  no second LLM call — so the status statement is based only on the router result
//  (Requirement 8.3). Every reply identifies the finding by BOTH its Finding_Id and
//  its human-readable title (Requirement 8.2).
// ------------------------------------------------------------------

// Look up a finding's human-readable title from the report by its Finding_Id, falling
// back to the id itself so the reply always names the finding (Requirement 8.2).
function findingTitle(report, findingId) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  for (const f of findings) {
    if (f && f.id === findingId && typeof f.title === "string" && f.title.trim()) {
      return f.title.trim();
    }
  }
  return findingId;
}

// Compose the outcome reply from the router status (Requirements 8.1, 8.2, 8.4). The
// status statement uses the mandated wording: "resolved" / "still present" /
// "could not be confirmed". The router's own message is appended for context, and an
// explicit retry invitation is added for the indeterminate case (Requirement 8.4).
export function templateOutcome(findingId, title, status, routerMessage) {
  const who = `the "${title}" finding (${findingId})`;
  const detail = typeof routerMessage === "string" && routerMessage.trim() ? ` ${routerMessage.trim()}` : "";

  if (status === STATUS.RESOLVED) {
    return `Good news — I re-checked ${who} and it now looks resolved.${detail}`;
  }
  if (status === STATUS.UNRESOLVED) {
    return `I re-checked ${who} and it's still present.${detail}`;
  }
  // indeterminate
  return `I re-checked ${who}, but the result could not be confirmed.${detail} You can ask me to re-check it again in a moment.`;
}

// Reply used when the router is unavailable / returns no usable status (Requirement 8.5).
// No status statement is emitted, and (chat being stateless server-side) the finding's
// stored status is left unchanged.
function routerUnavailableReply() {
  return "I couldn't complete that re-check just now. Please ask me to try again in a moment.";
}

function buildContext(scan, report) {
  const lines = [];
  lines.push(`Domain: ${report?.domain || scan?.domain || "(unknown)"}`);
  if (report) {
    lines.push(`Overall risk score: ${report.overallRiskScore}/100 (${report.riskLevel})`);
    lines.push(`Summary: ${report.summary}`);
    lines.push(`Top priority: ${report.topPriority}`);
    lines.push("");
    lines.push("Findings:");
    for (const f of report.findings || []) {
      lines.push(
        `- [${String(f.severity).toUpperCase()}] ${f.title}: ${f.explanation} Recommendation: ${f.recommendation}`
      );
    }
    if (!(report.findings || []).length) {
      lines.push("- No notable exposures were found.");
    }
  }
  if (scan) {
    lines.push("");
    lines.push("Raw scan signals:");
    lines.push(`- SPF present: ${scan.dns?.spf}; DMARC present: ${scan.dns?.dmarc}`);
    lines.push(`- MX records: ${(scan.dns?.mx || []).map((m) => m.exchange).join(", ") || "none"}`);
    lines.push(
      `- TLS: ${scan.ssl?.expiresInDays != null ? scan.ssl.expiresInDays + " days to expiry" : "n/a"}, issuer ${scan.ssl?.issuer || "n/a"}`
    );
    lines.push(
      `- Security headers — HSTS: ${scan.headers?.hsts}, CSP: ${scan.headers?.csp}, X-Frame-Options: ${scan.headers?.xfo}, X-Content-Type-Options: ${scan.headers?.xcto}`
    );
    lines.push(`- Public subdomains found: ${(scan.subdomains || []).length}`);
    if ((scan.subdomains || []).length) {
      lines.push(`  (${scan.subdomains.slice(0, 30).join(", ")}${scan.subdomains.length > 30 ? ", …" : ""})`);
    }
    lines.push(`- Inferred DNS/hosting provider: ${scan.provider || "unknown"}`);
  }
  return lines.join("\n");
}

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}
