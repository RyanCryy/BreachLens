// Netlify Function (v2): POST /api/recheck
// Thin HTTP wrapper around the shared Recheck_Router (lib/recheck.js). Re-verifies
// a SINGLE previously reported finding without re-running the full scan. It never
// computes a Recheck_Status itself — it validates the request, then delegates to
// recheckFinding(), which is the single source of truth for both this endpoint and
// the chat path (Requirement 9.2).

import { normalizeDomain, isValidDomain } from "./lib/checks.js";
import { recheckFinding, STATUS } from "./lib/recheck.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

const MAX_FINDING_ID_LEN = 256;

export default async function recheck(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS });
  }
  if (req.method !== "POST") {
    return json(405, { error: "Method not allowed. Use POST." });
  }

  // Strict validation order (Req 2.5): parse body -> domain -> findingId,
  // returning on the FIRST failure encountered, before any check runs.

  // 1. Parse body (Req 2.1)
  let body;
  try {
    body = await req.json();
  } catch (_) {
    return json(400, { error: "Request body could not be parsed as JSON." });
  }

  // 2. Validate domain (Req 2.2, 2.4): must be a non-empty string; normalize first,
  // then validate. normalizeDomain returns "" for non-strings/empty input.
  const rawDomain = body && body.domain;
  if (!rawDomain || typeof rawDomain !== "string") {
    return json(400, {
      error: "Please provide a valid domain name, e.g. example.com.",
    });
  }
  const domain = normalizeDomain(rawDomain);
  if (!domain || !isValidDomain(domain)) {
    return json(400, {
      error:
        "Please enter a valid domain name, e.g. example.com (no http:// or paths).",
    });
  }

  // 3. Validate findingId (Req 2.3): non-empty string, <= 256 chars.
  const findingId = body && body.findingId;
  if (!findingId || typeof findingId !== "string") {
    return json(400, { error: "Missing or empty 'findingId'." });
  }
  if (findingId.length > MAX_FINDING_ID_LEN) {
    return json(400, {
      error: `'findingId' exceeds the ${MAX_FINDING_ID_LEN}-character limit.`,
    });
  }

  // Valid request. Delegate to the shared router. A non-recheckable / unrecognized
  // id is NOT a 400 — recheckFinding returns 200 + indeterminate naturally
  // (Req 1.7, 2.6). Any unexpected error is converted to 200 + indeterminate so no
  // unhandled error reaches the caller (Req 4.5).
  try {
    const result = await recheckFinding({ domain, findingId });
    return json(200, result);
  } catch (_) {
    return json(200, {
      findingId,
      status: STATUS.INDETERMINATE,
      message:
        "The re-check could not be completed. Please try the re-check again.",
    });
  }
}

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}
