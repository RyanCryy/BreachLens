import { describe, it, expect, beforeEach, vi } from "vitest";

// `vi.mock` MUST be hoisted above the `./analysis.js` import so that the
// `callLLMJson` dependency inside `runPass2` is the auto-mocked vi.fn — no
// network, fully in-memory, and observable for the "not invoked" assertion.
vi.mock("./llm.js");

import { callLLMJson } from "./llm.js";
import { runPass2 } from "./analysis.js";

// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — Example/edge test
// Requirement 3.5: "WHEN the classified-findings list is empty THEN THE Scanner
// SHALL short-circuit to a _source: \"none\" report (Overall_Risk_Score 5,
// Risk_Level Low, empty Findings) WITHOUT making any Pass_2 LLM call."
//
// This is an example/edge test (not a numbered Property), so it carries no
// "Property N" tag. It pins the empty short-circuit branch of `runPass2`, which
// returns a fixed clean-scan report before reaching the `callLLMJson` synthesis
// call.
//
// Strategy:
//   - Spy on `callLLMJson` (auto-mocked to a vi.fn).
//   - Invoke `runPass2([], domain, tech)` with an empty classified list.
//   - Assert the returned report is the deterministic "none" report: score 5,
//     level "Low", empty findings, _source "none".
//   - Assert `callLLMJson` was NOT invoked — the short-circuit happens before
//     any LLM call.
// ---------------------------------------------------------------------------

const DOMAIN = "example.com";
const TECH = { server: "nginx", poweredBy: null, detected: ["nginx"] };

describe("Feature: deterministic-fallback — runPass2 empty short-circuit (Requirement 3.5)", () => {
  beforeEach(() => {
    callLLMJson.mockReset();
  });

  it('returns a _source: "none" report (score 5, Low, no findings) without calling the LLM', async () => {
    const report = await runPass2([], DOMAIN, TECH);

    expect(report._source).toBe("none");
    expect(report.overallRiskScore).toBe(5);
    expect(report.riskLevel).toBe("Low");
    expect(report.findings).toEqual([]);

    // The defining contract of the short-circuit: no Pass 2 LLM call is made.
    expect(callLLMJson).not.toHaveBeenCalled();
    expect(callLLMJson.mock.calls.length).toBe(0);
  });
});
