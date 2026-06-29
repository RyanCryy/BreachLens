import { describe, it, expect } from "vitest";
import {
  CHECK_IDS,
  CHECK_TIMEOUTS,
  CHECK_STATUS,
  TIMEOUT_SENTINEL,
  ERROR_SENTINEL,
  normalizeOutcome,
  runScan,
  RESULT_TYPE,
  resolutionFailureMessage,
} from "./scan-engine.js";
import { withTimeout } from "./checks.js";

// Unit tests for the Passive Scan Engine.
//
// This file is the shared home for the engine's example-based unit tests. Later
// tasks add their own describe blocks here (2.3 normalizer edge cases, 6.3
// resolution-failure message text, 8.2 handler integration), so each concern is
// grouped under its own clearly named describe block.

describe("scan-engine: CHECK_IDS registry (task 1.2)", () => {
  // The 11 defined checks from Requirement 1.3, in registry order. Each maps a
  // requirement-level check name to its canonical engine id.
  const EXPECTED_CHECK_IDS = [
    "dns", // DNS / SPF / DMARC
    "caa", // CAA
    "tls", // TLS certificate
    "subdomains", // subdomains
    "headers", // HTTP headers
    "cookies", // cookies
    "mixed-content", // mixed content
    "tech", // technology stack
    "robots", // robots.txt / sitemap.xml
    "exposed-files", // exposed files
    "provider", // provider inference
  ];

  it("contains exactly the 11 named checks (Requirement 1.3)", () => {
    expect(CHECK_IDS).toEqual(EXPECTED_CHECK_IDS);
  });

  it("has exactly 11 entries with no duplicates", () => {
    expect(CHECK_IDS).toHaveLength(11);
    expect(new Set(CHECK_IDS).size).toBe(11);
  });
});

describe("scan-engine: CHECK_TIMEOUTS budgets (task 1.2)", () => {
  it("defines a timeout for every check id and no extras (Requirement 2.6)", () => {
    expect(Object.keys(CHECK_TIMEOUTS).sort()).toEqual([...CHECK_IDS].sort());
  });

  it("constrains every timeout to the inclusive [6000, 8000] ms range (Requirement 2.6)", () => {
    for (const id of CHECK_IDS) {
      const timeout = CHECK_TIMEOUTS[id];
      expect(typeof timeout, `timeout for "${id}" should be a number`).toBe("number");
      expect(timeout, `timeout for "${id}" >= 6000`).toBeGreaterThanOrEqual(6000);
      expect(timeout, `timeout for "${id}" <= 8000`).toBeLessThanOrEqual(8000);
    }
  });
});

describe("scan-engine: normalizeOutcome edge cases (task 2.3)", () => {
  // The normalizer is pure and maps a settled check (a "ran" result of shape
  // { findings, data? } or an unavailability marker) to a Check_Outcome with
  // exactly one of the three CHECK_STATUS values. Requirements 2.4, 2.5.

  it("classifies a ran result with zero findings as Empty (Requirement 2.5)", () => {
    const outcome = normalizeOutcome("dns", { findings: [] });
    expect(outcome).toEqual({
      id: "dns",
      status: CHECK_STATUS.EMPTY,
      findings: [],
      error: null,
    });
  });

  it("classifies a ran result with one finding as Success (Requirement 2.4)", () => {
    const findings = [{ type: "spf", present: true }];
    const outcome = normalizeOutcome("dns", { findings });
    expect(outcome.status).toBe(CHECK_STATUS.SUCCESS);
    expect(outcome.findings).toEqual(findings);
    expect(outcome.error).toBeNull();
    expect(outcome.id).toBe("dns");
  });

  it("classifies a ran result with multiple findings as Success (Requirement 2.4)", () => {
    const findings = [
      { type: "subdomain", name: "a.example.com" },
      { type: "subdomain", name: "b.example.com" },
      { type: "subdomain", name: "c.example.com" },
    ];
    const outcome = normalizeOutcome("subdomains", { findings });
    expect(outcome.status).toBe(CHECK_STATUS.SUCCESS);
    expect(outcome.findings).toEqual(findings);
    expect(outcome.findings).toHaveLength(3);
    expect(outcome.error).toBeNull();
  });

  it("classifies the TIMEOUT_SENTINEL as Unavailable (Requirement 2.4/2.5 boundary)", () => {
    const outcome = normalizeOutcome("tls", TIMEOUT_SENTINEL);
    expect(outcome).toEqual({
      id: "tls",
      status: CHECK_STATUS.UNAVAILABLE,
      findings: [],
      error: "timeout",
    });
  });

  it("classifies an ERROR_SENTINEL as Unavailable carrying the sanitized reason", () => {
    const outcome = normalizeOutcome("caa", ERROR_SENTINEL("DNS lookup refused"));
    expect(outcome.status).toBe(CHECK_STATUS.UNAVAILABLE);
    expect(outcome.findings).toEqual([]);
    expect(outcome.error).toBe("DNS lookup refused");
    expect(outcome.id).toBe("caa");
  });

  it("classifies a raw Error as Unavailable using the error message, not its stack", () => {
    const err = new Error("connection reset");
    const outcome = normalizeOutcome("headers", err);
    expect(outcome.status).toBe(CHECK_STATUS.UNAVAILABLE);
    expect(outcome.findings).toEqual([]);
    expect(outcome.error).toBe("connection reset");
    // The raw stack trace / internals are never surfaced as the error reason.
    expect(outcome.error).not.toContain("at ");
  });
});

describe("scan-engine: resolution-failure message text (task 6.3)", () => {
  // Build a fully-injected `deps` describing a genuinely unreachable domain:
  // DNS positively reports no usable address (`resolves === false`) AND the
  // homepage fetch is unreachable (`reachable === false`). Every other primitive
  // returns a benign, body-free observation so the only thing under test is the
  // DNS-resolution gate's friendly Resolution_Failure message (Requirements 5.2, 5.3).
  function makeUnreachableDeps() {
    return {
      // DNS positively determined the domain does not resolve.
      checkDns: async () => ({ resolves: false, nameservers: [], spf: false, dmarc: false, mx: [] }),
      lookupCaa: async () => ({ status: "missing", records: [] }),
      checkSsl: async () => ({}),
      checkSubdomains: async () => ({ subdomains: [] }),
      // The site did not respond to the passive homepage fetch.
      checkHeaders: async () => ({ reachable: false, error: "ENOTFOUND" }),
      checkRobotsSitemap: async () => ({ sensitiveDisallows: [], sitemapPresent: false }),
      checkSensitiveFiles: async () => [],
      inferProvider: () => null,
      analyzeCookies: () => ({ missingSecure: [], missingHttpOnly: [], missingSameSite: [] }),
      analyzeMixedContent: () => ({ applicable: false, count: 0, samples: [] }),
      fingerprintTech: () => ({ detected: [] }),
      withTimeout,
      env: {},
    };
  }

  // Assert a string carries no raw-error / stack-trace markers (Requirement 5.3).
  function assertNoStackMarkers(message) {
    expect(message).not.toContain("at "); // stack frame marker
    expect(message).not.toContain("Error:"); // raw Error prefix
    expect(message).not.toContain("\n"); // multi-line stack
  }

  it("returns a RESOLUTION_FAILURE carrying the friendly message for an unreachable domain (Requirement 5.2)", async () => {
    const domain = "definitely-not-a-real-domain.example";
    const result = await runScan(domain, makeUnreachableDeps());

    expect(result.type).toBe(RESULT_TYPE.RESOLUTION_FAILURE);
    expect(result.domain).toBe(domain);
    expect(result.message).toBe(
      `We couldn't find "${domain}". Double-check the spelling — it may not exist or may not be publicly resolvable.`
    );
    // The returned message is the same one the exported helper produces.
    expect(result.message).toBe(resolutionFailureMessage(domain));
  });

  it("excludes stack traces and internal error details from the message (Requirement 5.3)", async () => {
    const domain = "no-such-host.example";
    const result = await runScan(domain, makeUnreachableDeps());

    expect(result.type).toBe(RESULT_TYPE.RESOLUTION_FAILURE);
    expect(typeof result.message).toBe("string");
    expect(result.message.length).toBeGreaterThan(0);
    assertNoStackMarkers(result.message);
  });

  it("resolutionFailureMessage(domain) is parameterized only by the domain and is stack-free (Requirements 5.2, 5.3)", () => {
    const domain = "example.org";
    const message = resolutionFailureMessage(domain);

    expect(message).toBe(
      `We couldn't find "${domain}". Double-check the spelling — it may not exist or may not be publicly resolvable.`
    );
    expect(message).toContain(domain);
    assertNoStackMarkers(message);
  });
});

describe("scan-engine: handler integration — NDJSON stream (task 8.2)", () => {
  // This test exercises the SAME wiring the refactored streaming handler
  // (`netlify/functions/scan.js`) uses: `runScan` drives an injected `emit` that
  // NDJSON-encodes each engine event into a stream buffer, and the handler then
  // appends exactly one terminal line — `result` for a Scan_Result or `error`
  // for a Resolution_Failure. We reproduce that pipeline here at the engine level
  // so the test stays fully hermetic/offline (no Request, no lib/analysis.js, no
  // network), while still asserting the end-to-end stream contract:
  //   one-or-more `progress` lines, in resolution order, FOLLOWED BY a single
  //   terminal `result` (success) or `error` (resolution failure) line.
  // Requirements 4.1, 4.2, 4.3 (progress emission/ordering) and 5.1 (the distinct
  // error terminal on Resolution_Failure).

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // Build an NDJSON sink mirroring the handler's `send`/`emit`: each event is
  // JSON-encoded with a trailing newline and pushed onto a chunk buffer (the
  // stand-in for `controller.enqueue`). `events()` decodes + parses the buffer
  // back into the ordered list of emitted objects.
  function makeNdjsonStream() {
    const chunks = [];
    const emit = (evt) => chunks.push(encoder.encode(JSON.stringify(evt) + "\n"));
    const events = () =>
      chunks
        .map((c) => decoder.decode(c))
        .join("")
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line));
    return { emit, events };
  }

  // Run `runScan` through the NDJSON stream, then append the handler's terminal
  // line exactly as `scan.js` does: `error` on RESOLUTION_FAILURE, else `result`.
  async function streamScan(domain, deps) {
    const { emit, events } = makeNdjsonStream();
    const result = await runScan(domain, deps, emit);
    if (result.type === RESULT_TYPE.RESOLUTION_FAILURE) {
      emit({ type: "error", message: result.message });
    } else {
      emit({ type: "result", scan: result });
    }
    return { result, events: events() };
  }

  // A fully-injected, body-free `deps` describing a healthy, resolvable domain:
  // DNS resolves, the homepage is reachable, and a few checks carry findings so
  // the scan produces a real Scan_Result. Nothing touches the network.
  function makeResolvableDeps() {
    return {
      checkDns: async () => ({
        resolves: true,
        nameservers: ["ns1.example.com"],
        spf: true,
        dmarc: true,
        mx: [{ exchange: "mail.example.com", priority: 10 }],
      }),
      lookupCaa: async () => ({ status: "present", records: ["0 issue \"letsencrypt.org\""] }),
      checkSsl: async () => ({ valid: true, validTo: "2099-01-01", issuer: "Test CA", expiresInDays: 365 }),
      checkSubdomains: async () => ({ subdomains: ["www.example.com", "api.example.com"] }),
      checkHeaders: async () => ({
        reachable: true,
        servedHttps: true,
        hsts: true,
        csp: false,
        xfo: true,
        xcto: true,
        server: "nginx",
        setCookies: [],
      }),
      checkRobotsSitemap: async () => ({ sensitiveDisallows: [], sitemapPresent: true, sitemapUrlCount: 3 }),
      checkSensitiveFiles: async () => [{ path: "/.env", status: 404, exposed: false }],
      inferProvider: () => "Example DNS",
      analyzeCookies: () => ({ total: 0, missingSecure: [], missingHttpOnly: [], missingSameSite: [] }),
      analyzeMixedContent: () => ({ applicable: true, count: 0, samples: [] }),
      fingerprintTech: () => ({ server: "nginx", poweredBy: null, detected: ["nginx"] }),
      withTimeout,
      env: {},
    };
  }

  // A fully-injected `deps` describing a genuinely unreachable domain: DNS
  // positively reports no usable address AND the homepage is unreachable, so the
  // engine's DNS-resolution gate fires (Req 5.1).
  function makeUnreachableDeps() {
    return {
      checkDns: async () => ({ resolves: false, nameservers: [], spf: false, dmarc: false, mx: [] }),
      lookupCaa: async () => ({ status: "missing", records: [] }),
      checkSsl: async () => ({}),
      checkSubdomains: async () => ({ subdomains: [] }),
      checkHeaders: async () => ({ reachable: false, error: "ENOTFOUND" }),
      checkRobotsSitemap: async () => ({ sensitiveDisallows: [], sitemapPresent: false }),
      checkSensitiveFiles: async () => [],
      inferProvider: () => null,
      analyzeCookies: () => ({ missingSecure: [], missingHttpOnly: [], missingSameSite: [] }),
      analyzeMixedContent: () => ({ applicable: false, count: 0, samples: [] }),
      fingerprintTech: () => ({ detected: [] }),
      withTimeout,
      env: {},
    };
  }

  it("emits progress lines followed by exactly one terminal `result` line for a resolvable scan (Req 4.1, 4.2, 4.3)", async () => {
    const { result, events } = await streamScan("example.com", makeResolvableDeps());

    // The engine produced a full Scan_Result, not a resolution failure.
    expect(result.type).toBe(RESULT_TYPE.SCAN);

    // Every line is a valid NDJSON object with a `type` discriminator.
    expect(events.length).toBeGreaterThan(0);
    for (const evt of events) expect(typeof evt.type).toBe("string");

    // Exactly one terminal `result`, no `error`, and it is the LAST line.
    const terminals = events.filter((e) => e.type === "result" || e.type === "error");
    expect(terminals).toHaveLength(1);
    expect(events.filter((e) => e.type === "error")).toHaveLength(0);
    const terminal = events[events.length - 1];
    expect(terminal.type).toBe("result");
    expect(terminal.scan).toBeDefined();
    expect(terminal.scan.type).toBe(RESULT_TYPE.SCAN);
    expect(terminal.scan.outcomes).toHaveLength(CHECK_IDS.length);

    // Every line before the terminal is a `progress` event naming a defined
    // check (Req 4.1) — one per defined check (Req 4.3).
    const progress = events.slice(0, -1);
    expect(progress.length).toBe(CHECK_IDS.length);
    for (const evt of progress) {
      expect(evt.type).toBe("progress");
      expect(CHECK_IDS).toContain(evt.check);
    }

    // One progress event per defined check — no omissions, no duplicates (Req 4.3).
    expect(progress.map((e) => e.check).sort()).toEqual([...CHECK_IDS].sort());

    // Progress events are emitted in resolution order with strictly increasing
    // `seq` (Req 4.2), and every progress line strictly precedes the terminal.
    for (let i = 1; i < progress.length; i++) {
      expect(progress[i].seq).toBeGreaterThan(progress[i - 1].seq);
    }
    const terminalIndex = events.indexOf(terminal);
    expect(terminalIndex).toBe(events.length - 1);
    expect(terminalIndex).toBeGreaterThanOrEqual(progress.length);
  });

  it("emits progress lines followed by a single terminal `error` line for a resolution failure (Req 5.1)", async () => {
    const domain = "definitely-not-a-real-domain.example";
    const { result, events } = await streamScan(domain, makeUnreachableDeps());

    // The engine returned the distinct Resolution_Failure error state.
    expect(result.type).toBe(RESULT_TYPE.RESOLUTION_FAILURE);

    // Exactly one terminal line, and it is an `error` (never a `result`).
    const terminals = events.filter((e) => e.type === "result" || e.type === "error");
    expect(terminals).toHaveLength(1);
    expect(events.filter((e) => e.type === "result")).toHaveLength(0);
    const terminal = events[events.length - 1];
    expect(terminal.type).toBe("error");
    expect(typeof terminal.message).toBe("string");
    expect(terminal.message.length).toBeGreaterThan(0);

    // Progress lines still precede the terminal — one per defined check.
    const progress = events.slice(0, -1);
    expect(progress.length).toBe(CHECK_IDS.length);
    for (const evt of progress) {
      expect(evt.type).toBe("progress");
      expect(CHECK_IDS).toContain(evt.check);
    }
    expect(events.indexOf(terminal)).toBe(events.length - 1);
  });
});
