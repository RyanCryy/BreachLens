import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Passive-only request constraint smoke tests (Requirements 3.3, 3.4, 3.5)
// ---------------------------------------------------------------------------
//
// These are SMOKE / review-style example tests, not property-based tests: the
// behaviors under test (HTTP verb, attached headers, TLS port) are fixed by the
// primitives in `lib/checks.js` and do not vary with input. They assert the
// engine's passive-observation guarantees hold at the network boundary by
// mocking the only two ways the primitives touch the network:
//
//   - global `fetch` — used by checkSensitiveFiles, checkFileStatus, checkHeaders,
//     checkSubdomains, checkRobotsSitemap. We capture every fetch call and assert
//     the verb is read-only (GET / default) and that no credential headers are
//     attached (only the existing User-Agent).
//   - `node:tls` connect — used by checkSsl. We capture the connect options and
//     assert it dials port 443, sets a servername (SNI), and that the socket is
//     only used for a handshake (no data is ever written to the target).
//
// Both mocks are fully hermetic — NO real network or TLS connection is ever made.

// --- node:tls mock -----------------------------------------------------------
// Captures the options passed to tls.connect and exposes a fake socket whose
// `write` is a spy, so we can assert checkSsl performs only a handshake and never
// writes application data to the target (Requirement 3.5).
const tlsConnectCalls = [];
let lastTlsSocket = null;

vi.mock("node:tls", () => {
  const connect = vi.fn((options, secureConnectListener) => {
    tlsConnectCalls.push(options);

    const handlers = {};
    const socket = {
      authorized: true,
      // A minimal, valid-looking peer certificate so checkSsl reads cleanly.
      getPeerCertificate: vi.fn(() => ({
        valid_to: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toUTCString(),
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toUTCString(),
        issuer: { O: "Test CA", CN: "Test CA" },
        subject: { CN: options && options.servername },
      })),
      on: vi.fn((event, handler) => {
        handlers[event] = handler;
        return socket;
      }),
      removeAllListeners: vi.fn(() => socket),
      destroy: vi.fn(),
      // A handshake-only client never writes/ends application data. These are
      // spies so the test can assert they are NEVER invoked.
      write: vi.fn(),
      end: vi.fn(),
    };

    lastTlsSocket = socket;

    // The real `tls.connect` invokes the secureConnect callback asynchronously
    // (on the 'secureConnect' event), AFTER returning the socket. We mirror that
    // with a microtask so checkSsl's internal `socket` reference is assigned
    // before the callback runs.
    if (typeof secureConnectListener === "function") {
      queueMicrotask(() => secureConnectListener());
    }

    return socket;
  });

  return { default: { connect }, connect };
});

// Import AFTER vi.mock so the mocked node:tls is wired into checks.js.
import {
  checkSensitiveFiles,
  checkFileStatus,
  checkHeaders,
  checkSubdomains,
  checkRobotsSitemap,
  checkSsl,
} from "./checks.js";

// --- global fetch mock -------------------------------------------------------
// A minimal Response-like object: enough surface for every fetching primitive
// (status / ok / url / headers.get/has/getSetCookie / text).
function makeResponse() {
  return {
    status: 200,
    ok: true,
    url: "https://example.com/",
    headers: {
      get: () => null, // no security/content-type headers
      has: () => false, // no security headers present
      getSetCookie: () => [], // no Set-Cookie headers
    },
    text: async () => "", // body is read but irrelevant to these constraints
  };
}

let fetchMock;

beforeEach(() => {
  tlsConnectCalls.length = 0;
  lastTlsSocket = null;
  fetchMock = vi.fn(async () => makeResponse());
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// Mutating HTTP verbs that a passive scanner must NEVER use.
const MUTATING_VERBS = ["POST", "PUT", "PATCH", "DELETE"];

// Header names that would attach credentials — none may appear on any request.
const CREDENTIAL_HEADER_RE = /^(authorization|cookie|proxy-authorization|x-api-key|api-key|x-auth-token)$/i;

// Pull the `init` (2nd) argument from each recorded fetch call.
function fetchInits() {
  return fetchMock.mock.calls.map(([, init]) => init || {});
}

const DOMAIN = "example.com";

describe("scan-engine smoke: read-only HTTP verbs (Requirement 3.3)", () => {
  it("checkSensitiveFiles issues only GET requests (no mutating verbs)", async () => {
    await checkSensitiveFiles(DOMAIN);
    expect(fetchMock).toHaveBeenCalled();
    for (const init of fetchInits()) {
      // checkSensitiveFiles explicitly sets method: "GET".
      expect(init.method).toBe("GET");
      expect(MUTATING_VERBS).not.toContain(init.method);
    }
  });

  it("checkFileStatus issues only a GET request (no mutating verbs)", async () => {
    await checkFileStatus(DOMAIN, "/.env");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [init] = fetchInits();
    expect(init.method).toBe("GET");
    expect(MUTATING_VERBS).not.toContain(init.method);
  });

  it("checkHeaders issues only a GET request (no mutating verbs)", async () => {
    await checkHeaders(DOMAIN);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [init] = fetchInits();
    expect(init.method).toBe("GET");
    expect(MUTATING_VERBS).not.toContain(init.method);
  });

  it("checkSubdomains uses a default-GET request (no method override, never a mutating verb)", async () => {
    await checkSubdomains(DOMAIN);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [init] = fetchInits();
    // crt.sh lookup relies on the default verb (GET) — method is left undefined.
    expect(init.method === undefined || init.method === "GET").toBe(true);
    expect(MUTATING_VERBS).not.toContain(init.method);
  });

  it("checkRobotsSitemap uses default-GET requests (no method override, never a mutating verb)", async () => {
    await checkRobotsSitemap(DOMAIN);
    expect(fetchMock).toHaveBeenCalled();
    for (const init of fetchInits()) {
      expect(init.method === undefined || init.method === "GET").toBe(true);
      expect(MUTATING_VERBS).not.toContain(init.method);
    }
  });

  it("across every fetching primitive, no request ever uses a mutating verb", async () => {
    await Promise.all([
      checkSensitiveFiles(DOMAIN),
      checkFileStatus(DOMAIN, "/.git/config"),
      checkHeaders(DOMAIN),
      checkSubdomains(DOMAIN),
      checkRobotsSitemap(DOMAIN),
    ]);
    expect(fetchMock).toHaveBeenCalled();
    for (const init of fetchInits()) {
      const verb = init.method ?? "GET";
      expect(verb).toBe("GET");
    }
  });
});

describe("scan-engine smoke: no credentials attached (Requirement 3.4)", () => {
  // Every fetching primitive attaches exactly one header — a descriptive
  // User-Agent — and NEVER any authentication/credential header.
  async function assertNoCredentialHeaders(invoke) {
    await invoke();
    expect(fetchMock).toHaveBeenCalled();
    for (const init of fetchInits()) {
      const headers = init.headers || {};
      const keys = Object.keys(headers);
      for (const key of keys) {
        expect(
          CREDENTIAL_HEADER_RE.test(key),
          `header "${key}" must not be a credential header`
        ).toBe(false);
      }
      // The only header any passive primitive sets is the User-Agent.
      const lowerKeys = keys.map((k) => k.toLowerCase());
      expect(lowerKeys).toContain("user-agent");
      expect(lowerKeys).toEqual(["user-agent"]);
    }
  }

  it("checkSensitiveFiles attaches only a User-Agent (no credentials)", async () => {
    await assertNoCredentialHeaders(() => checkSensitiveFiles(DOMAIN));
  });

  it("checkFileStatus attaches only a User-Agent (no credentials)", async () => {
    await assertNoCredentialHeaders(() => checkFileStatus(DOMAIN, "/.env"));
  });

  it("checkHeaders attaches only a User-Agent (no credentials)", async () => {
    await assertNoCredentialHeaders(() => checkHeaders(DOMAIN));
  });

  it("checkSubdomains attaches only a User-Agent (no credentials)", async () => {
    await assertNoCredentialHeaders(() => checkSubdomains(DOMAIN));
  });

  it("checkRobotsSitemap attaches only a User-Agent (no credentials)", async () => {
    await assertNoCredentialHeaders(() => checkRobotsSitemap(DOMAIN));
  });
});

describe("scan-engine smoke: TLS handshake on port 443 only (Requirement 3.5)", () => {
  it("checkSsl connects to port 443 with a servername (SNI) set", async () => {
    await checkSsl(DOMAIN);
    expect(tlsConnectCalls).toHaveLength(1);
    const options = tlsConnectCalls[0];
    expect(options.port).toBe(443);
    expect(options.host).toBe(DOMAIN);
    expect(options.servername).toBe(DOMAIN);
  });

  it("checkSsl performs only a handshake and never writes data to the target", async () => {
    await checkSsl(DOMAIN);
    expect(lastTlsSocket).not.toBeNull();
    // A handshake-only TLS client never sends application data.
    expect(lastTlsSocket.write).not.toHaveBeenCalled();
    expect(lastTlsSocket.end).not.toHaveBeenCalled();
    // It reads the presented certificate (the entire point of the handshake)...
    expect(lastTlsSocket.getPeerCertificate).toHaveBeenCalled();
    // ...then tears the connection down without further exchange.
    expect(lastTlsSocket.destroy).toHaveBeenCalled();
  });

  it("checkSsl makes no HTTP fetch (TLS path is socket-only)", async () => {
    await checkSsl(DOMAIN);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
