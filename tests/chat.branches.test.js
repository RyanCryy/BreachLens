// Chat orchestration branch unit tests (Task 7.5)
//
// Verifies the recheck-intent branching in chat.js with the intent step and the
// shared router under our control:
//   - non-recheck message            → read-only path (router NOT called)
//   - recheck, 0 matches             → "no matching finding" (router NOT called)
//   - recheck, >1 matches            → lists candidates (router NOT called)
//   - recheck, 1 non-recheckable     → "can't be automatically re-checked" (router NOT called)
//   - recheck, 1 recheckable         → recheckFinding invoked; reply reflects its status
//   - router status overrides stale report context
//   - router unavailable (throws / no status) → "couldn't complete" reply
//
// _Requirements: 7.1, 7.3, 7.4, 7.5, 7.6, 8.3, 8.4, 8.5, 8.6, 9.2_

import { describe, it, expect, beforeEach, vi } from "vitest";

// Hoisted spies so the vi.mock factories below can reference them and tests can
// drive them per-case. callLLMJson deterministically drives resolveRecheckIntent;
// callLLM is the read-only branch spy; recheckFinding is the shared-router spy.
const { mockCallLLM, mockCallLLMJson, mockRecheckFinding } = vi.hoisted(() => ({
  mockCallLLM: vi.fn(),
  mockCallLLMJson: vi.fn(),
  mockRecheckFinding: vi.fn(),
}));

// Mock the LLM module but keep the REAL LLMError (so `e instanceof LLMError` holds)
// and the real extractJson.
vi.mock("../netlify/functions/lib/llm.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    callLLM: mockCallLLM,
    callLLMJson: mockCallLLMJson,
  };
});

// Mock the router module but keep the REAL STATUS enum and REAL isRecheckable so the
// non-recheckable branch (subdomain-*) classifies correctly; only recheckFinding is a spy.
vi.mock("../netlify/functions/lib/recheck.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    recheckFinding: mockRecheckFinding,
  };
});

import chat from "../netlify/functions/chat.js";
import { LLMError } from "../netlify/functions/lib/llm.js";
import { STATUS } from "../netlify/functions/lib/recheck.js";

// A report with both recheckable findings and one non-recheckable (subdomain-*) finding.
const REPORT = {
  domain: "example.com",
  overallRiskScore: 50,
  riskLevel: "medium",
  summary: "Test report.",
  topPriority: "Fix SPF.",
  findings: [
    {
      id: "spf-missing",
      title: "SPF record missing",
      severity: "high",
      explanation: "No SPF record was found.",
      recommendation: "Publish an SPF record.",
    },
    {
      id: "dmarc-missing",
      title: "DMARC record missing",
      severity: "high",
      explanation: "No DMARC record was found.",
      recommendation: "Publish a DMARC record.",
    },
    {
      id: "subdomain-dev",
      title: "Exposed subdomain dev.example.com",
      severity: "low",
      explanation: "A development subdomain is publicly resolvable.",
      recommendation: "Take it offline.",
    },
  ],
};

function makeReq(body) {
  return new Request("https://example.com/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function callChat(body) {
  const res = await chat(makeReq(body));
  const data = await res.json();
  return { res, data };
}

beforeEach(() => {
  mockCallLLM.mockReset();
  mockCallLLMJson.mockReset();
  mockRecheckFinding.mockReset();
  // Defaults: not a recheck intent; read-only LLM unavailable; router resolves benignly.
  mockCallLLMJson.mockResolvedValue({ recheck: false, findingIds: [] });
  mockCallLLM.mockRejectedValue(new LLMError("OPENAI_API_KEY is not configured"));
  mockRecheckFinding.mockResolvedValue({
    findingId: "spf-missing",
    status: STATUS.RESOLVED,
    message: "An SPF record is now published.",
  });
});

describe("chat orchestration branches", () => {
  it("non-recheck message takes the read-only path (router NOT called, degraded reply)", async () => {
    // Intent says not a recheck → falls through to the read-only answer path. With no
    // working LLM, callLLM throws LLMError and chat returns the degraded friendly reply.
    mockCallLLMJson.mockResolvedValue({ recheck: false, findingIds: [] });

    const { res, data } = await callChat({
      message: "What does the SPF finding mean?",
      report: REPORT,
    });

    expect(res.status).toBe(200);
    expect(mockRecheckFinding).not.toHaveBeenCalled();
    expect(mockCallLLM).toHaveBeenCalledTimes(1); // proves the read-only branch ran
    expect(data.degraded).toBe(true);
    expect(data.reply).toMatch(/trouble reaching my analysis engine/i);
  });

  it("recheck intent with 0 matching findings replies 'no matching finding' (router NOT called)", async () => {
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: [] });

    const { res, data } = await callChat({
      message: "re-check the thing",
      report: REPORT,
    });

    expect(res.status).toBe(200);
    expect(mockRecheckFinding).not.toHaveBeenCalled();
    expect(mockCallLLM).not.toHaveBeenCalled();
    expect(data.reply).toMatch(/don't see a matching finding/i);
  });

  it("recheck intent with >1 matches lists the candidates (router NOT called)", async () => {
    mockCallLLMJson.mockResolvedValue({
      recheck: true,
      findingIds: ["spf-missing", "dmarc-missing"],
    });

    const { res, data } = await callChat({
      message: "re-check my email records",
      report: REPORT,
    });

    expect(res.status).toBe(200);
    expect(mockRecheckFinding).not.toHaveBeenCalled();
    expect(data.reply).toMatch(/more than one finding/i);
    // Lists each candidate by Finding_Id.
    expect(data.reply).toContain("spf-missing");
    expect(data.reply).toContain("dmarc-missing");
  });

  it("recheck intent on exactly 1 non-recheckable finding says it can't be auto re-checked (router NOT called)", async () => {
    // subdomain-dev is genuinely non-recheckable per the real isRecheckable.
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["subdomain-dev"] });

    const { res, data } = await callChat({
      message: "re-check the dev subdomain",
      report: REPORT,
    });

    expect(res.status).toBe(200);
    expect(mockRecheckFinding).not.toHaveBeenCalled();
    expect(data.reply).toMatch(/can't be automatically re-checked/i);
    // Names the finding by both title and Finding_Id.
    expect(data.reply).toContain("subdomain-dev");
    expect(data.reply).toContain("Exposed subdomain dev.example.com");
  });

  it("recheck intent on exactly 1 recheckable finding invokes the router and reflects its status", async () => {
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["spf-missing"] });
    mockRecheckFinding.mockResolvedValue({
      findingId: "spf-missing",
      status: STATUS.RESOLVED,
      message: "An SPF record is now published.",
    });

    const { res, data } = await callChat({
      message: "did my SPF get fixed?",
      report: REPORT,
    });

    expect(res.status).toBe(200);
    // Router called exactly once with the resolved domain + findingId (Req 7.1, 9.2).
    expect(mockRecheckFinding).toHaveBeenCalledTimes(1);
    expect(mockRecheckFinding).toHaveBeenCalledWith({
      domain: "example.com",
      findingId: "spf-missing",
    });
    // No read-only LLM answer in the recheck branch.
    expect(mockCallLLM).not.toHaveBeenCalled();
    // Reply reflects the router's resolved status and names the finding both ways.
    expect(data.reply).toMatch(/resolved/i);
    expect(data.reply).toContain("spf-missing");
    expect(data.reply).toContain("SPF record missing");
  });

  it("uses scan.domain when report.domain is absent", async () => {
    const reportNoDomain = { ...REPORT, domain: undefined };
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["spf-missing"] });

    await callChat({
      message: "re-check SPF",
      report: reportNoDomain,
      scan: { domain: "fallback.example" },
    });

    expect(mockRecheckFinding).toHaveBeenCalledWith({
      domain: "fallback.example",
      findingId: "spf-missing",
    });
  });

  it("router status overrides stale report context (still present, not resolved)", async () => {
    // The report context might imply DMARC is fine, but the router is the only source
    // of truth for the status statement (Req 8.3). Router says UNRESOLVED → "still present".
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["dmarc-missing"] });
    mockRecheckFinding.mockResolvedValue({
      findingId: "dmarc-missing",
      status: STATUS.UNRESOLVED,
      message: "Still no DMARC record found.",
    });

    const { data } = await callChat({
      message: "is DMARC fixed now?",
      report: REPORT,
    });

    expect(data.reply).toMatch(/still present/i);
    expect(data.reply).not.toMatch(/now looks resolved/i);
    expect(data.reply).toContain("dmarc-missing");
    expect(data.reply).toContain("DMARC record missing");
  });

  it("indeterminate router status yields 'could not be confirmed' with a retry invitation (Req 8.4)", async () => {
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["spf-missing"] });
    mockRecheckFinding.mockResolvedValue({
      findingId: "spf-missing",
      status: STATUS.INDETERMINATE,
      message: "The SPF DNS lookup didn't return a clear answer.",
    });

    const { data } = await callChat({ message: "re-check SPF", report: REPORT });

    expect(data.reply).toMatch(/could not be confirmed/i);
    expect(data.reply).toMatch(/again/i);
  });

  it("router unavailable (recheckFinding throws) replies 'couldn't complete' (Req 8.5)", async () => {
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["spf-missing"] });
    mockRecheckFinding.mockRejectedValue(new Error("router down"));

    const { res, data } = await callChat({ message: "re-check SPF", report: REPORT });

    expect(res.status).toBe(200);
    expect(mockRecheckFinding).toHaveBeenCalledTimes(1);
    expect(data.reply).toMatch(/couldn't complete that re-check/i);
    // No status statement emitted on the unavailable path.
    expect(data.reply).not.toMatch(/still present|now looks resolved/i);
  });

  it("router returning no usable status also replies 'couldn't complete' (Req 8.5)", async () => {
    mockCallLLMJson.mockResolvedValue({ recheck: true, findingIds: ["spf-missing"] });
    mockRecheckFinding.mockResolvedValue({
      findingId: "spf-missing",
      status: "not-a-real-status",
      message: "",
    });

    const { data } = await callChat({ message: "re-check SPF", report: REPORT });

    expect(data.reply).toMatch(/couldn't complete that re-check/i);
  });
});
