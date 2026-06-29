// Multi-pass AI analysis.
// Pass 1: classify each finding independently and concurrently (Promise.all).
// Pass 2: a senior-analyst synthesis call that scores overall risk and orders findings.
// Both passes degrade gracefully to a deterministic rule-based report.

import { callLLMJson } from "./llm.js";
import { fallbackClassify, deriveFindings, defaultFixSnippet } from "./findings.js";

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// --- PASS 1: one isolated LLM call per finding, run concurrently ---
// Findings are classified in parallel (Promise.all). LLM output is token-bound,
// so N small concurrent calls finish faster than one big batched call that has to
// generate all the prose sequentially. Each call degrades to its deterministic
// rule on failure, and the whole pass is bounded by the handler's analysis budget.
// Severity is ALWAYS the deterministic rule value; the LLM only supplies prose.
function pass1System(provider, tech) {
  const techLine =
    tech && tech.detected && tech.detected.length
      ? `- The site appears to be built with: ${tech.detected.join(", ")}. Where relevant, tailor remediation steps to those technologies (e.g. the right config file or plugin), but only when you are confident it applies.`
      : null;
  return [
    "You are a meticulous security analyst scoring exactly ONE finding in isolation.",
    "You are given a single security finding about a domain's public footprint.",
    "Judge its severity on its own merits — do NOT assume the presence or absence of other issues.",
    "",
    "Return ONLY a JSON object with this exact shape:",
    '{ "title": string, "explanation": string, "recommendation": string, "fixSnippet": string | null }',
    "",
    "Rules:",
    "- title: a short, human-readable name for the issue.",
    "- Do NOT assign a severity — severity is determined separately by a fixed deterministic rule, not by you. Focus only on clear, accurate explanatory and remediation text.",
    "- explanation: 1-2 sentences of plain English explaining why it matters to a non-technical owner. No jargon dumps.",
    "- recommendation: a SPECIFIC, actionable fix. Avoid generic advice.",
    "- For email-authentication (SPF, DMARC) and CAA findings specifically, the recommendation text MUST contain the exact, literal, copy-pasteable record value inline (not a vague description like 'add the appropriate SPF configuration'). If the finding details include a suggested record value, use that exact value (it has already been computed from this domain's actual MX/setup); only adjust it if you are certain it's wrong. Do NOT invent include: directives for mail providers that aren't indicated by the MX records.",
    "- fixSnippet: if (and ONLY if) the fix is a single literal value the user can copy-paste verbatim — e.g. a DNS TXT/CAA record string like \"v=spf1 include:_spf.example.com ~all\" — put exactly that literal value here (matching the value in your recommendation). If the fix requires server configuration, code, or multiple steps (e.g. adding HTTP response headers), set fixSnippet to null. Never put prose or instructions in fixSnippet; it must be a paste-ready value only.",
    provider
      ? `- The domain's DNS/hosting provider has been CONFIDENTLY identified (from a verified nameserver-pattern lookup) as ${provider}. You MAY tailor the fix to ${provider}'s actual dashboard/workflow. Only describe ${provider} UI you are genuinely confident about; otherwise give correct generic steps.`
      : "- The DNS/hosting provider could NOT be confidently identified. You MUST give generic, provider-agnostic fix instructions (e.g. \"Log in to your domain's DNS management dashboard and add a TXT record...\"). Do NOT name or guess any specific provider, platform, or registrar.",
    "- NEVER infer, guess, or name a specific DNS/hosting provider yourself. Only reference a provider by name if one was explicitly given to you above as a confidently-matched value.",
    techLine,
    "- Return ONLY the JSON. No markdown fences, no preamble.",
  ]
    .filter(Boolean)
    .join("\n");
}

// Keep fixSnippet to a clean paste-ready literal, or null.
function normalizeSnippet(s) {
  if (!s || typeof s !== "string") return null;
  const trimmed = s.trim();
  if (!trimmed || trimmed.toLowerCase() === "null") return null;
  return trimmed;
}

async function classifyOne(finding, provider, tech) {
  const userContent = [
    `Domain finding to score:`,
    `- Issue: ${finding.label}`,
    `- Details: ${finding.detail}`,
    `- Category: ${finding.type}`,
    finding.suggestedSnippet
      ? `- Pre-computed correct record value for this domain (use this verbatim in both the recommendation and fixSnippet): ${finding.suggestedSnippet}`
      : null,
  ]
    .filter(Boolean)
    .join("\n");

  try {
    const json = await callLLMJson({
      system: pass1System(provider, tech),
      messages: [{ role: "user", content: userContent }],
      maxTokens: 600,
      temperature: 0,
      // Tight per-call timeout: a single slow finding shouldn't drag the whole
      // pass. callLLMJson retries once, so worst case ~2x this before fallback.
      timeoutMs: 9000,
    });

    // Severity is ALWAYS the deterministic rule-based value for this finding type,
    // never the LLM's judgment — this keeps badges/score identical across repeat scans.
    const rule = fallbackClassify(finding);

    return {
      id: finding.id,
      type: finding.type,
      title: json.title || finding.label,
      severity: rule.severity,
      explanation: json.explanation || rule.explanation,
      recommendation: json.recommendation || rule.recommendation,
      fixSnippet: normalizeSnippet(json.fixSnippet) || defaultFixSnippet(finding),
      _source: "llm",
    };
  } catch (e) {
    // Per-finding fallback so a single bad call doesn't sink the report.
    return { ...fallbackClassify(finding), type: finding.type, _source: "fallback" };
  }
}

export async function runPass1(findings, provider, tech, onEach) {
  if (findings.length === 0) return [];
  return Promise.all(
    findings.map(async (f) => {
      const result = await classifyOne(f, provider, tech);
      if (typeof onEach === "function") {
        try {
          onEach(result);
        } catch (_) {}
      }
      return result;
    })
  );
}

// --- PASS 2: senior analyst synthesis (prose only; score/level are deterministic) ---
const PASS2_SYSTEM = [
  "You are a SENIOR security analyst reviewing a junior analyst's individual findings about a domain's public security exposure.",
  "Synthesize them into a single executive narrative for a NON-TECHNICAL business owner.",
  "",
  "You will be given the findings (each with a fixed severity) AND a pre-computed overall risk level + score from a deterministic formula. Treat that risk level as authoritative and write consistently with it. Do NOT output your own score or risk level.",
  "",
  "Return ONLY a JSON object with this exact shape:",
  '{ "summary": string, "topPriority": string }',
  "",
  "Rules:",
  "- summary: 2-3 sentences, plain English, calm and clear, written for a business owner with no security background, consistent with the provided risk level.",
  "- In the summary, where it can be said HONESTLY, weave in 1-2 sentences of directional comparative context (e.g. \"missing DMARC is unfortunately common among small business domains\" or \"these headers are stronger than is typical for sites without a dedicated security team\"). Use ONLY general directional framing — common/uncommon, typical/atypical, stronger/weaker than average. NEVER invent a specific percentage, count, or statistic that sounds authoritative but isn't grounded in real data.",
  "- topPriority: ONE sentence naming the single most important thing to fix first.",
  "- You may be given a detected technology stack as CONTEXT. Mention it briefly in the summary if useful, but do NOT treat the tech stack itself as a vulnerability.",
  "- Base everything ONLY on the findings provided. Do not invent issues.",
  "- Return ONLY the JSON. No markdown fences, no preamble.",
].join("\n");

function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
  );
}

export async function runPass2(classified, domain, tech) {
  const sorted = sortFindings(classified);
  const techNote =
    tech && tech.detected && tech.detected.length
      ? ` Detected technology stack (context only, not a vulnerability): ${tech.detected.join(", ")}.`
      : "";

  if (sorted.length === 0) {
    return {
      overallRiskScore: 5,
      riskLevel: "Low",
      summary: `No notable public security exposures were detected for ${domain} across DNS, email authentication, TLS, HTTP headers, cookies, exposed files, and certificate-transparency subdomain data.${techNote} This is a good baseline — keep monitoring as your footprint changes.`,
      findings: [],
      topPriority:
        "Maintain current good practices and re-scan periodically as infrastructure changes.",
      _source: "none",
    };
  }

  // Score and level are computed DETERMINISTICALLY from the (rule-based) severities,
  // so identical findings always yield an identical score/level across repeat scans.
  const score = computeFallbackScore(sorted);
  const riskLevel = scoreToLevel(score);

  const userContent = JSON.stringify(
    {
      domain,
      overallRiskScore: score,
      riskLevel,
      detectedTechStack: (tech && tech.detected) || [],
      findings: sorted.map((f) => ({
        title: f.title,
        severity: f.severity,
        explanation: f.explanation,
      })),
    },
    null,
    2
  );

  try {
    const json = await callLLMJson({
      system: PASS2_SYSTEM,
      messages: [
        {
          role: "user",
          content: `Findings for ${domain} (risk level ${riskLevel}, score ${score}/100):\n\n${userContent}`,
        },
      ],
      maxTokens: 800,
      temperature: 0,
      timeoutMs: 10000,
    });

    return {
      overallRiskScore: score,
      riskLevel,
      summary: json.summary || synthFallbackSummary(domain, sorted),
      findings: sorted,
      topPriority: json.topPriority || sorted[0].recommendation,
      _source: "llm",
    };
  } catch (e) {
    return buildFallbackReport(domain, sorted);
  }
}

// --- Deterministic scoring helpers / full fallback ---
function computeFallbackScore(findings) {
  const weights = { critical: 40, high: 22, medium: 10, low: 3 };
  let score = 0;
  for (const f of findings) score += weights[f.severity] || 0;
  return Math.min(100, score);
}

function scoreToLevel(score) {
  if (score >= 70) return "Critical";
  if (score >= 45) return "High";
  if (score >= 20) return "Medium";
  return "Low";
}

function synthFallbackSummary(domain, findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const parts = [];
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }
  return `We reviewed the public security footprint of ${domain} and found ${findings.length} item${
    findings.length === 1 ? "" : "s"
  } worth attention (${parts.join(", ")}). These are based entirely on publicly visible signals — addressing the highest-severity items first will meaningfully reduce your exposure.`;
}

export function buildFallbackReport(domain, sortedFindings) {
  const score = computeFallbackScore(sortedFindings);
  return {
    overallRiskScore: score,
    riskLevel: scoreToLevel(score),
    summary: synthFallbackSummary(domain, sortedFindings),
    findings: sortedFindings,
    topPriority: sortedFindings.length
      ? sortedFindings[0].recommendation
      : "No action needed right now.",
    _source: "fallback",
  };
}

// Attach the (informational) tech-stack context to a finished report.
// Sets report.techStack and appends a neutral, non-scored "info" finding for display.
export function attachTechStack(report, techStack) {
  report.techStack = techStack || { server: null, poweredBy: null, detected: [] };
  const detected = (techStack && techStack.detected) || [];
  if (detected.length) {
    report.findings = report.findings || [];
    report.findings.push({
      id: "tech-stack",
      type: "tech",
      title: `Detected technology stack: ${detected.join(", ")}`,
      severity: "info",
      informational: true,
      explanation:
        "These technologies were inferred from public response headers and page markup. This is context for the report, not a vulnerability — but knowing your stack helps prioritize patching and configuration.",
      recommendation: "",
      _source: "deterministic",
    });
  }
  return report;
}

// ============================================================
//  PASS 3 — narrative layer (attacker's-eye view + risk trajectory)
//  One combined call after Pass 2. Grounded strictly in real findings.
//  Returns { attackScenario, ifUnaddressed } or null (caller omits on failure).
// ============================================================
const PASS3_SYSTEM = [
  "You are a security analyst writing a brief, plain-English narrative for a non-technical business owner, based on a security report you already produced.",
  "",
  "Return ONLY a JSON object with this exact shape:",
  '{ "attackScenario": string, "ifUnaddressed": string }',
  "",
  "HARD CONSTRAINTS (critical):",
  "- Use ONLY the findings provided. NEVER invent, assume, or imply a vulnerability that is not in the findings list.",
  "- attackScenario: 3-5 sentences describing a realistic, SPECIFIC way the EXISTING findings could be chained together by an attacker. Frame it explicitly as a hypothetical, illustrative scenario — 'here's how these gaps COULD be exploited' — NOT a claim that any attack is happening or has happened. Do not use alarmist language.",
  "- If there are no real (non-informational) findings, do NOT fabricate an attack. Instead, attackScenario should be a short positive note explaining why the public attack surface looks low.",
  "- ifUnaddressed: 2-3 sentences, explicitly SPECULATIVE in tone ('risk would likely continue to grow', 'this gap tends to widen'), describing how risk may compound over time if the top findings are left unfixed. Reference only findings that actually exist. Never predict a specific timeframe or certainty ('you will be hacked in X days' is forbidden). If the scan is clean, give a brief reassuring maintenance note instead.",
  "- Return ONLY the JSON. No markdown fences, no preamble.",
].join("\n");

export async function runPass3(report, domain) {
  const scored = (report.findings || []).filter((f) => f.severity !== "info" && !f.informational);
  const hasRealFindings = scored.length > 0;

  const payload = {
    domain,
    overallRiskLevel: report.riskLevel,
    overallRiskScore: report.overallRiskScore,
    cleanScan: !hasRealFindings,
    findings: scored.map((f) => ({
      title: f.title,
      severity: f.severity,
      explanation: f.explanation,
    })),
  };

  try {
    const json = await callLLMJson({
      system: PASS3_SYSTEM,
      messages: [
        {
          role: "user",
          content: `Report context for ${domain}:\n\n${JSON.stringify(payload, null, 2)}`,
        },
      ],
      maxTokens: 700,
      temperature: 0.4,
      timeoutMs: 10000,
    });
    const attackScenario =
      typeof json.attackScenario === "string" ? json.attackScenario.trim() : "";
    const ifUnaddressed =
      typeof json.ifUnaddressed === "string" ? json.ifUnaddressed.trim() : "";
    if (!attackScenario && !ifUnaddressed) return null;
    return { attackScenario, ifUnaddressed };
  } catch (e) {
    // Graceful omission — the page simply won't render these sections.
    return null;
  }
}

// --- Top-level orchestration (one-shot helper; scan.js uses the streaming path) ---
export async function analyze(scan) {
  const { findings, provider, techStack } = deriveFindings(scan);

  let classified;
  try {
    classified = await runPass1(findings, provider, techStack);
  } catch (e) {
    // Total Pass 1 failure -> classify everything deterministically
    classified = findings.map((f) => ({
      ...fallbackClassify(f),
      type: f.type,
      _source: "fallback",
    }));
  }

  const report = await runPass2(classified, scan.domain, techStack);
  report.provider = provider;
  report.domain = scan.domain;
  attachTechStack(report, techStack);
  const narrative = await runPass3(report, scan.domain);
  if (narrative) {
    report.attackScenario = narrative.attackScenario;
    report.ifUnaddressed = narrative.ifUnaddressed;
  }
  return report;
}
