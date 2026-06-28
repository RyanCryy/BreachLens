/** @vitest-environment jsdom */
/*
 * DOM tests for the frontend Re-check control (Requirements 5.1–5.7, 6.1–6.8).
 *
 * public/app.js is an IIFE with no exports, so we load it into a jsdom document and
 * reach its internal re-check rendering/state through a guarded test seam: setting
 * window.__BREACHLENS_TEST__ = true before the script evaluates makes it expose
 * { state, isRecheckable, renderFindings, handleRecheckActivation, renderRecheckStatus }
 * on window.__bl. The seam attaches nowhere else (never in the browser).
 *
 * We also force document.readyState to "loading" before evaluation so the script's
 * own init() (which wires the full scan UI: canvas background, matchMedia, scan form)
 * stays deferred and never runs — these tests exercise only the re-check control, whose
 * click handler is wired directly inside renderFindings, not init().
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";

const APP_SRC = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "app.js"),
  "utf8"
);

// Force init() to stay deferred (and never dispatch DOMContentLoaded) so the heavy
// scan UI wiring never runs under jsdom.
function forceLoadingReadyState() {
  Object.defineProperty(document, "readyState", {
    configurable: true,
    get: () => "loading",
  });
}

// Evaluate app.js fresh (new IIFE closure → fresh state) and return its test seam.
function loadApp() {
  document.body.innerHTML = `<div id="findings-list"></div>`;
  forceLoadingReadyState();
  window.__BREACHLENS_TEST__ = true;
  // Indirect eval runs in global scope, where jsdom provides document/window/etc.
  (0, eval)(APP_SRC);
  return window.__bl;
}

// Flush pending microtasks (the async activation handler awaits fetch + res.json()).
const flush = () => new Promise((r) => setTimeout(r, 0));

const recheckable = (id, title) => ({
  id,
  title: title || id,
  severity: "high",
  explanation: "explanation for " + id,
});
const nonRecheckable = (id, title) => ({
  id,
  title: title || id,
  severity: "medium",
  explanation: "explanation for " + id,
});

function okResponse(body) {
  return { ok: true, status: 200, json: async () => body };
}

function cardFor(findingId) {
  return document.querySelector(`.recheck-row[data-finding-id="${findingId}"]`);
}
function buttonFor(findingId) {
  const row = cardFor(findingId);
  return row && row.querySelector(".recheck-btn");
}
function statusFor(findingId) {
  const row = cardFor(findingId);
  return row && row.querySelector(".recheck-status");
}

let app;

beforeEach(() => {
  app = loadApp();
  app.state.domain = "";
  app.state.recheckState.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  delete window.__bl;
  delete window.__BREACHLENS_TEST__;
});

describe("Re-check control rendering (Req 5.1, 5.2)", () => {
  it("renders an activatable Re-check button for a recheckable finding", () => {
    app.renderFindings([recheckable("spf-missing", "SPF record missing")]);

    const btn = buttonFor("spf-missing");
    expect(btn).toBeTruthy();
    expect(btn.disabled).toBe(false);
    expect(btn.classList.contains("is-disabled")).toBe(false);
    expect(btn.textContent).toMatch(/re-check/i);
    // The recheckable row also exposes a live status slot to populate later.
    expect(statusFor("spf-missing")).toBeTruthy();
  });

  it("renders a disabled, non-activatable control for a non-recheckable finding", () => {
    app.renderFindings([nonRecheckable("subdomain-mail", "Subdomain exposed")]);

    const btn = buttonFor("subdomain-mail");
    expect(btn).toBeTruthy();
    expect(btn.disabled).toBe(true);
    expect(btn.classList.contains("is-disabled")).toBe(true);
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    // Non-recheckable cards carry no status slot — nothing can be sent.
    expect(statusFor("subdomain-mail")).toBeFalsy();
  });

  it("does not send a request when a non-recheckable control is interacted with (Req 5.2)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([nonRecheckable("subdomain-mail")]);
    buttonFor("subdomain-mail").click();
    await flush();

    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("Activation request (Req 5.3, 5.7)", () => {
  it("sends exactly ONE POST to /api/recheck with body { domain, findingId } and never /api/scan", async () => {
    const fetchMock = vi.fn(async () =>
      okResponse({ findingId: "spf-missing", status: "resolved", message: "SPF present" })
    );
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/recheck");
    expect(url).not.toBe("/api/scan");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ domain: "example.com", findingId: "spf-missing" });

    // No call ever targets the full-scan endpoint.
    for (const [calledUrl] of fetchMock.mock.calls) {
      expect(calledUrl).not.toBe("/api/scan");
    }
  });
});

describe("No-domain path (Req 5.4)", () => {
  it("shows unavailable and sends nothing when no current domain exists", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = ""; // no current domain

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    expect(fetchMock).not.toHaveBeenCalled();
    const slot = statusFor("spf-missing");
    expect(slot.textContent.toLowerCase()).toContain("unavailable");
    // No re-check ran, so no timestamp is shown.
    expect(slot.querySelector("time")).toBeFalsy();
  });
});

describe("Pending state and card independence (Req 5.5, 5.6)", () => {
  it("disables only the activated card's button while others stay activatable", async () => {
    // A fetch that never resolves keeps the first card pending.
    let release;
    const pending = new Promise((r) => (release = r));
    const fetchMock = vi.fn(() => pending);
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing"), recheckable("dmarc-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    // Activated card: pending + disabled, visually distinct (is-pending).
    const spfSlot = statusFor("spf-missing");
    expect(spfSlot.classList.contains("is-pending")).toBe(true);
    expect(buttonFor("spf-missing").disabled).toBe(true);

    // The other card remains independently activatable.
    expect(buttonFor("dmarc-missing").disabled).toBe(false);
    expect(statusFor("dmarc-missing").classList.contains("is-pending")).toBe(false);

    release && release(okResponse({ status: "resolved", message: "ok" }));
    await flush();
  });
});

describe("Outcome states are visually distinct (Req 6.1, 6.2, 6.3, 6.5)", () => {
  const cases = [
    { status: "resolved", cls: "is-resolved" },
    { status: "unresolved", cls: "is-unresolved" },
    { status: "indeterminate", cls: "is-indeterminate" },
  ];

  for (const { status, cls } of cases) {
    it(`renders a distinct ${cls} state for a ${status} outcome`, async () => {
      const fetchMock = vi.fn(async () =>
        okResponse({ findingId: "spf-missing", status, message: `${status} message` })
      );
      vi.stubGlobal("fetch", fetchMock);
      app.state.domain = "example.com";

      app.renderFindings([recheckable("spf-missing")]);
      buttonFor("spf-missing").click();
      await flush();

      const slot = statusFor("spf-missing");
      expect(slot.className).toBe(`recheck-status ${cls}`);
      // Button is re-enabled after a terminal outcome.
      expect(buttonFor("spf-missing").disabled).toBe(false);
    });
  }

  it("renders a distinct is-failed state on a network/transport failure and re-enables the button", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError("network down");
    });
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    const slot = statusFor("spf-missing");
    expect(slot.className).toBe("recheck-status is-failed");
    expect(buttonFor("spf-missing").disabled).toBe(false);
  });

  it("renders is-failed on a non-2xx response (Req 6.6)", async () => {
    const fetchMock = vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) }));
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    expect(statusFor("spf-missing").className).toBe("recheck-status is-failed");
    expect(buttonFor("spf-missing").disabled).toBe(false);
  });

  it("the four outcome classes are mutually distinct", () => {
    const classes = ["is-resolved", "is-unresolved", "is-indeterminate", "is-failed"];
    expect(new Set(classes).size).toBe(classes.length);
  });
});

describe("Timestamp on completed outcome (Req 6.7)", () => {
  it("renders a timestamp when a completed status is shown", async () => {
    const fetchMock = vi.fn(async () =>
      okResponse({ findingId: "spf-missing", status: "resolved", message: "SPF present" })
    );
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await flush();

    const time = statusFor("spf-missing").querySelector("time");
    expect(time).toBeTruthy();
    expect(time.getAttribute("datetime")).toBeTruthy();
    expect(time.textContent.toLowerCase()).toContain("checked");
  });
});

describe("Re-activation replaces the prior status (Req 6.8)", () => {
  it("replaces a prior resolved outcome with the new unresolved outcome", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okResponse({ status: "resolved", message: "now fixed" }))
      .mockResolvedValueOnce(okResponse({ status: "unresolved", message: "still present" }));
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);

    buttonFor("spf-missing").click();
    await flush();
    expect(statusFor("spf-missing").className).toBe("recheck-status is-resolved");

    buttonFor("spf-missing").click();
    await flush();

    const slot = statusFor("spf-missing");
    // The new outcome fully replaces the old one — no stale resolved state remains.
    expect(slot.className).toBe("recheck-status is-unresolved");
    expect(slot.classList.contains("is-resolved")).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("30s client timeout (Req 6.5)", () => {
  it("aborts after 30s with no response, showing a failed state and re-enabling the button", async () => {
    vi.useFakeTimers();
    // A fetch that only settles when its AbortSignal fires.
    const fetchMock = vi.fn(
      (_url, opts) =>
        new Promise((_resolve, reject) => {
          opts.signal.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError"))
          );
        })
    );
    vi.stubGlobal("fetch", fetchMock);
    app.state.domain = "example.com";

    app.renderFindings([recheckable("spf-missing")]);
    buttonFor("spf-missing").click();
    await vi.advanceTimersByTimeAsync(0);

    // In progress: pending + disabled.
    expect(statusFor("spf-missing").classList.contains("is-pending")).toBe(true);
    expect(buttonFor("spf-missing").disabled).toBe(true);

    // Advance to the 30s client cap → AbortController fires → fetch rejects.
    await vi.advanceTimersByTimeAsync(30000);

    expect(statusFor("spf-missing").className).toBe("recheck-status is-failed");
    expect(buttonFor("spf-missing").disabled).toBe(false);
  });
});
