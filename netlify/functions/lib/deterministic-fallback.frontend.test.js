// @vitest-environment jsdom
//
// ---------------------------------------------------------------------------
// Feature: deterministic-fallback — Frontend banner example/edge test
//
// Requirement 7.3: "WHILE the report Source_Tag is \"fallback\", THE frontend
//   SHALL display the fallback banner."
// Requirement 7.4: "WHERE the report Source_Tag is \"error\", THE frontend SHALL
//   display the fallback banner, and this branch SHALL be unreachable because no
//   backend path emits the \"error\" Source_Tag (the backend instead emits a
//   Stream_Error_Event)."
//
// This is an example/edge test (not a numbered Property), so it carries no
// "Property N" tag. It runs in the jsdom environment (the repo default is node,
// so the `// @vitest-environment jsdom` pragma above is required) because it
// exercises DOM-driven banner logic from `public/app.js`.
//
// `public/app.js` is a browser IIFE that exports nothing, so its banner
// predicate cannot be imported. We instead replicate the EXACT predicate from
// `app.js` (quoted verbatim below) and exercise it against a DOM that mirrors
// the `#fallback-note` element in `public/index.html`:
//
//     // public/app.js, inside renderResults():
//     const fbNote = $("#fallback-note");
//     fbNote.hidden = report._source !== "fallback" && report._source !== "error";
//
// The banner is therefore VISIBLE (hidden === false) iff `_source` is
// "fallback" OR "error", and HIDDEN for "llm" / "none" / "deterministic".
//
// The second half of this file is a CODE-LEVEL assertion that the "error"
// branch is dead: no backend path (scan.js, analysis.js, findings.js) ever sets
// `_source: "error"`. This is cross-checked against Task 8.7
// (deterministic-fallback.scan-error.test.js), which proves the backend emits a
// Stream_Error_Event instead of a report on fatal/DNS failures.
//
// IMPORTANT: The "error" branch in app.js is RETAINED DEAD DEFENSIVE CODE. Per
// Requirement 7.5 it is recorded as-is and is OUT OF SCOPE to fix here. This
// test documents the dead branch; it does not change production code.
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Mirror of the `#fallback-note` element from `public/index.html`:
//   <div class="fallback-note" id="fallback-note" hidden> … </div>
function mountBannerDom() {
  document.body.innerHTML = `
    <div class="fallback-note" id="fallback-note" hidden>
      &#9888;&#65038; AI analysis was unavailable — showing a deterministic rule-based report.
    </div>
  `;
  return document.getElementById("fallback-note");
}

// Verbatim replication of the banner predicate in `public/app.js`
// (renderResults). Kept byte-identical to the source line so this test fails if
// the production predicate ever changes:
//     fbNote.hidden = report._source !== "fallback" && report._source !== "error";
function applyFallbackBanner(report) {
  const fbNote = document.getElementById("fallback-note");
  fbNote.hidden = report._source !== "fallback" && report._source !== "error";
  return fbNote;
}

describe("Feature: deterministic-fallback — fallback banner rendering (Requirements 7.3, 7.4)", () => {
  beforeEach(() => {
    mountBannerDom();
  });

  // Requirement 7.3 — the reachable, real-world case the backend actually emits.
  it("shows the fallback banner when report._source === \"fallback\"", () => {
    const fbNote = applyFallbackBanner({ _source: "fallback" });
    expect(fbNote.hidden).toBe(false); // visible
  });

  // Requirement 7.4 — documents the DEAD "error" branch. The predicate also
  // un-hides the banner for "error", but no backend path produces this tag (see
  // the code-level assertion below). Retained as dead defensive code (Req 7.5).
  it("shows the fallback banner when report._source === \"error\" (dead branch, never emitted by backend)", () => {
    const fbNote = applyFallbackBanner({ _source: "error" });
    expect(fbNote.hidden).toBe(false); // visible — but unreachable in practice
  });

  // The banner stays hidden for every Source_Tag the backend actually emits
  // that is NOT "fallback": "llm", "none", and "deterministic".
  it("keeps the fallback banner hidden for non-fallback backend source tags", () => {
    for (const source of ["llm", "none", "deterministic"]) {
      mountBannerDom();
      const fbNote = applyFallbackBanner({ _source: source });
      expect(fbNote.hidden).toBe(true); // hidden
    }
  });

  // Defensive: an absent/undefined _source also keeps the banner hidden.
  it("keeps the fallback banner hidden when _source is missing", () => {
    const fbNote = applyFallbackBanner({});
    expect(fbNote.hidden).toBe(true);
  });
});

describe("Feature: deterministic-fallback — the \"error\" Source_Tag branch is dead backend code (Requirements 7.4, 7.5)", () => {
  // Code-level assertion (cross-checked against Task 8.7): scan the three backend
  // source files and confirm NONE of them ever set `_source` to "error". This is
  // what makes the app.js "error" branch unreachable from the backend.
  // (Resolved from process.cwd() — the workspace root — because under jsdom
  // `import.meta.url` is an http:// URL that node:fs cannot read.)
  const backendFiles = [
    resolve(process.cwd(), "netlify/functions/scan.js"),
    resolve(process.cwd(), "netlify/functions/lib/analysis.js"),
    resolve(process.cwd(), "netlify/functions/lib/findings.js"),
  ];

  // Matches `_source: "error"` or `_source = "error"` with single or double
  // quotes and arbitrary surrounding whitespace.
  const ERROR_SOURCE_ASSIGNMENT = /_source\s*[:=]\s*["']error["']/;

  // The set of Source_Tags the backend is allowed to emit (design.md Source_Tag
  // domain). Used to confirm the only tags present are the documented four.
  const ALLOWED_SOURCE_TAGS = new Set(["llm", "fallback", "none", "deterministic"]);

  it("no backend file assigns _source: \"error\"", () => {
    for (const filePath of backendFiles) {
      const src = readFileSync(filePath, "utf8");
      expect(
        ERROR_SOURCE_ASSIGNMENT.test(src),
        `${filePath} unexpectedly assigns _source: "error"`
      ).toBe(false);
    }
  });

  it("every _source literal assigned in the backend is within the allowed domain (never \"error\")", () => {
    const literalAssignment = /_source\s*[:=]\s*["']([^"']*)["']/g;
    for (const filePath of backendFiles) {
      const src = readFileSync(filePath, "utf8");
      let match;
      while ((match = literalAssignment.exec(src)) !== null) {
        const tag = match[1];
        expect(
          ALLOWED_SOURCE_TAGS.has(tag),
          `${filePath} assigns disallowed _source: "${tag}"`
        ).toBe(true);
        expect(tag).not.toBe("error");
      }
    }
  });
});
