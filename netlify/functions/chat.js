// Netlify Function (v2): POST /api/chat
// Stateless follow-up Q&A. The client sends the full report JSON + prior chat turns
// on every message (no server-side persistence). Claude answers ONLY from the report.

import { callLLM, LLMError } from "./lib/llm.js";

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
