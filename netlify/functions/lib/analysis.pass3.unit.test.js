import { describe, it, expect, beforeEach, vi } from "vitest";

// vi.mock MUST be at the top so vitest hoists it above the ./analysis.js import,
// making callLLMJson an in-memory auto-mocked vi.fn (no network access).
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass3 } from "./analysis.js";
import { createLLMJsonMock } from "./analysis.pass3.arbitraries.js";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative — Pass 3 example / unit tests
//
// Representative example cases that complement the property suite
// (analysis.pass3.property*.test.js). Subsequent tasks (6.2 multi-finding
// payload mapping, 6.3 out-of-scope certificate timeline) add their own
// describe blocks to this same file.
//
// callLLMJson is stubbed via the shared controller so every case runs fully
// in-memory with no network access.
// ---------------------------------------------------------------------------

describe("Feature: exploit-narrative, Pass 3 unit tests", () => {
  const llm = createLLMJsonMock(callLLMJson);

  beforeEach(() => {
    llm.reset();
    llm.resolveWith({ attackScenario: "x", ifUnaddressed: "y" });
  });

  // -------------------------------------------------------------------------
  // Task 6.1 — clean-scan example
  //
  // When every finding is excluded (empty list, or only info/informational
  // findings), the payload reports cleanScan === true with findings === [],
  // and Pass 3 still invokes the LLM exactly once (it does NOT hard-skip on a
  // clean scan, unlike Pass 2).
  //
  // _Requirements: 6.1, 6.3, 6.4, 3.6_
  // -------------------------------------------------------------------------
  describe("clean-scan behavior (Task 6.1)", () => {
    it("empty findings -> cleanScan true, findings [], LLM called once", async () => {
      const report = {
        findings: [],
        riskLevel: "Low",
        overallRiskScore: 0,
      };

      await runPass3(report, "example.com");

      const payload = llm.lastPayload();
      expect(payload.cleanScan).toBe(true);
      expect(payload.findings).toEqual([]);
      // Pass 3 does not hard-skip on a clean scan — the LLM is invoked once.
      expect(llm.callCount()).toBe(1);
    });

    it("only info/informational findings are all excluded -> cleanScan true, findings [], LLM called once", async () => {
      const report = {
        findings: [
          // Excluded because severity === "info".
          { title: "Informational note", severity: "info", explanation: "fyi" },
          // Excluded because the informational flag is truthy.
          {
            title: "Flagged informational",
            severity: "high",
            explanation: "low priority",
            informational: true,
          },
          // Excluded: severity "info" AND informational truthy.
          {
            title: "Doubly excluded",
            severity: "info",
            explanation: "noise",
            informational: 1,
          },
        ],
        riskLevel: "Low",
        overallRiskScore: 3,
      };

      await runPass3(report, "example.com");

      const payload = llm.lastPayload();
      expect(payload.cleanScan).toBe(true);
      expect(payload.findings).toEqual([]);
      // Still exactly one LLM call even though the scan is clean.
      expect(llm.callCount()).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Task 6.2 — multi-finding payload mapping example
  //
  // A representative severity-ordered list of scored findings flows through
  // unchanged into the payload mapping as { title, severity, explanation } in
  // order, while excluded findings (severity === "info" OR truthy
  // informational flag) are dropped. Extra fields on the source findings
  // (id, recommendation) are ignored by the mapping.
  //
  // _Requirements: 3.2, 3.3_
  // -------------------------------------------------------------------------
  describe("multi-finding payload mapping (Task 6.2)", () => {
    it("scored findings flow through in order as { title, severity, explanation }; info/informational are dropped", async () => {
      const report = {
        // Severity-ordered (critical -> high -> medium -> low) with two
        // excluded findings interleaved to prove they are dropped without
        // disturbing the order of the scored ones.
        findings: [
          {
            title: "Exposed admin panel",
            severity: "critical",
            explanation: "The admin console is reachable from the public internet.",
            id: "f-1",
            recommendation: "Restrict access by IP allowlist.",
          },
          // Excluded: severity === "info".
          {
            title: "Server banner disclosed",
            severity: "info",
            explanation: "Informational only.",
            id: "f-info",
          },
          {
            title: "Missing DMARC record",
            severity: "high",
            explanation: "Email spoofing protection is not configured.",
            id: "f-2",
            recommendation: "Publish a DMARC policy.",
          },
          // Excluded: informational flag is truthy even though severity scores.
          {
            title: "Verbose error pages",
            severity: "medium",
            explanation: "Stack traces shown to users.",
            informational: true,
            id: "f-flagged",
          },
          {
            title: "Outdated TLS version",
            severity: "medium",
            explanation: "TLS 1.0 is still enabled.",
            id: "f-3",
          },
          {
            title: "Cookie without Secure flag",
            severity: "low",
            explanation: "Session cookie may be sent over plaintext.",
            id: "f-4",
          },
        ],
        riskLevel: "High",
        overallRiskScore: 72,
      };

      await runPass3(report, "example.com");

      const payload = llm.lastPayload();

      // Only the four scored findings survive, in their original order, each
      // mapped to exactly { title, severity, explanation }.
      expect(payload.findings).toEqual([
        {
          title: "Exposed admin panel",
          severity: "critical",
          explanation: "The admin console is reachable from the public internet.",
        },
        {
          title: "Missing DMARC record",
          severity: "high",
          explanation: "Email spoofing protection is not configured.",
        },
        {
          title: "Outdated TLS version",
          severity: "medium",
          explanation: "TLS 1.0 is still enabled.",
        },
        {
          title: "Cookie without Secure flag",
          severity: "low",
          explanation: "Session cookie may be sent over plaintext.",
        },
      ]);

      // Each mapped entry carries exactly the three allowed keys — no id,
      // recommendation, or informational leaks through.
      for (const f of payload.findings) {
        expect(Object.keys(f).sort()).toEqual(["explanation", "severity", "title"]);
      }

      // With real findings present this is not a clean scan.
      expect(payload.cleanScan).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Task 6.3 — out-of-scope certificate-timeline example
  //
  // The certificate-history timeline is built in checks.js and rendered in its
  // own report section; it is outside the scope of Pass 3 (Requirement 9).
  // Even when the base report carries a certificate-history timeline (and other
  // unrelated fields), Pass 3 must NOT forward that data into its payload — the
  // payload must still have exactly the five top-level keys (domain,
  // overallRiskLevel, overallRiskScore, cleanScan, findings) — and the Pass 3
  // output must be unaffected by the timeline's presence or content.
  //
  // _Requirements: 9.2, 9.3, 3.1_
  // -------------------------------------------------------------------------
  describe("out-of-scope certificate-timeline (Task 6.3)", () => {
    const FIVE_KEYS = [
      "cleanScan",
      "domain",
      "findings",
      "overallRiskLevel",
      "overallRiskScore",
    ];

    // A representative scored finding so the run is not a clean scan.
    const scoredFinding = {
      title: "Missing DMARC record",
      severity: "high",
      explanation: "Email spoofing protection is not configured.",
    };

    // A rich, unrelated certificate-history timeline plus other out-of-scope
    // fields that live on the report but must never reach Pass 3's payload.
    const certificateTimeline = [
      { issuedAt: "2021-01-01", issuer: "Let's Encrypt", serial: "0xAB12" },
      { issuedAt: "2022-04-15", issuer: "Let's Encrypt", serial: "0xCD34" },
      { issuedAt: "2023-08-30", issuer: "DigiCert", serial: "0xEF56" },
    ];

    it("payload still has exactly the five top-level keys when the report carries a certificate timeline and other unrelated fields", async () => {
      const report = {
        findings: [scoredFinding],
        riskLevel: "High",
        overallRiskScore: 65,
        // Out-of-scope data that must be ignored by Pass 3.
        certificateTimeline,
        certHistory: { firstSeen: "2018-02-02", renewals: 7 },
        dnsRecords: ["A", "AAAA", "MX", "TXT"],
        rawHtml: "<html><body>not for pass 3</body></html>",
        screenshots: ["base64-blob-1", "base64-blob-2"],
      };

      await runPass3(report, "example.com");

      const payload = llm.lastPayload();

      // Exactly the five canonical top-level keys — no certificateTimeline,
      // certHistory, dnsRecords, rawHtml, or screenshots leak through.
      expect(Object.keys(payload).sort()).toEqual(FIVE_KEYS);
      expect(payload).not.toHaveProperty("certificateTimeline");
      expect(payload).not.toHaveProperty("certHistory");
      expect(payload).not.toHaveProperty("dnsRecords");
      expect(payload).not.toHaveProperty("rawHtml");
      expect(payload).not.toHaveProperty("screenshots");
    });

    it("payload and Pass 3 output are unaffected by the presence/absence/content of the certificate timeline", async () => {
      const baseReport = {
        findings: [scoredFinding],
        riskLevel: "High",
        overallRiskScore: 65,
      };

      // Run 1: report with no timeline at all.
      llm.reset();
      llm.resolveWith({ attackScenario: "scenario text", ifUnaddressed: "impact text" });
      const outWithout = await runPass3({ ...baseReport }, "example.com");
      const payloadWithout = llm.lastPayload();

      // Run 2: same report plus a populated certificate timeline.
      llm.reset();
      llm.resolveWith({ attackScenario: "scenario text", ifUnaddressed: "impact text" });
      const outWithFull = await runPass3(
        { ...baseReport, certificateTimeline },
        "example.com"
      );
      const payloadWithFull = llm.lastPayload();

      // Run 3: same report with an empty timeline.
      llm.reset();
      llm.resolveWith({ attackScenario: "scenario text", ifUnaddressed: "impact text" });
      const outWithEmpty = await runPass3(
        { ...baseReport, certificateTimeline: [] },
        "example.com"
      );
      const payloadWithEmpty = llm.lastPayload();

      // The serialized payload is identical regardless of timeline data.
      expect(payloadWithFull).toEqual(payloadWithout);
      expect(payloadWithEmpty).toEqual(payloadWithout);

      // And each payload still has exactly the five canonical keys.
      expect(Object.keys(payloadWithFull).sort()).toEqual(FIVE_KEYS);

      // The Pass 3 output is unaffected by the timeline.
      expect(outWithFull).toEqual(outWithout);
      expect(outWithEmpty).toEqual(outWithout);
    });
  });
});
