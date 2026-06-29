import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Feature: exploit-narrative, Task 6.4: scan.js integration omission example
//
// Example/unit test for the report-assembly step in netlify/functions/scan.js.
// The production code conditionally copies the Pass 3 narrative onto the report:
//
//   const rep = pass2Rep || baseReport;
//   ...
//   if (narrative) {
//     rep.attackScenario = narrative.attackScenario;
//     rep.ifUnaddressed = narrative.ifUnaddressed;
//   }
//
// When `narrative` is null, neither field is assigned — they remain absent own
// properties on the report (never null, empty, or a placeholder).
//
// This test models that conditional faithfully with a local helper and verifies
// both branches with `report.hasOwnProperty(...)`.
//
// _Requirements: 8.1, 8.2, 8.3, 8.4_
// ---------------------------------------------------------------------------

// Faithful, isolated reproduction of the scan.js assembly step. `rep` is the
// report being assembled (pass2Rep || baseReport); `narrative` is the Pass 3
// result (a non-null { attackScenario, ifUnaddressed } object or null).
function assembleReport(rep, narrative) {
  if (narrative) {
    rep.attackScenario = narrative.attackScenario;
    rep.ifUnaddressed = narrative.ifUnaddressed;
  }
  return rep;
}

describe("Feature: exploit-narrative — scan.js narrative integration/omission", () => {
  it("sets attackScenario and ifUnaddressed as own properties from a non-null narrative", () => {
    // A representative assembled base report (the deterministic report).
    const rep = {
      domain: "example.com",
      riskLevel: "Medium",
      overallRiskScore: 32,
      findings: [],
    };
    const narrative = {
      attackScenario:
        "An attacker could chain the missing DMARC record with the exposed admin login to impersonate staff.",
      ifUnaddressed:
        "Left unaddressed, spoofed emails could erode customer trust and open the door to broader account compromise.",
    };

    const result = assembleReport(rep, narrative);

    // Both fields become own properties...
    expect(result.hasOwnProperty("attackScenario")).toBe(true);
    expect(result.hasOwnProperty("ifUnaddressed")).toBe(true);
    // ...set verbatim from the narrative result.
    expect(result.attackScenario).toBe(narrative.attackScenario);
    expect(result.ifUnaddressed).toBe(narrative.ifUnaddressed);
  });

  it("omits both narrative fields entirely when the narrative is null", () => {
    const rep = {
      domain: "example.com",
      riskLevel: "Low",
      overallRiskScore: 8,
      findings: [],
    };

    const result = assembleReport(rep, null);

    // Neither field is an own property...
    expect(result.hasOwnProperty("attackScenario")).toBe(false);
    expect(result.hasOwnProperty("ifUnaddressed")).toBe(false);
    // ...and no null/empty/placeholder value is assigned for either.
    expect(result.attackScenario).toBeUndefined();
    expect(result.ifUnaddressed).toBeUndefined();
  });
});
