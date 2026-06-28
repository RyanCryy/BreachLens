import { describe, it, expect } from "vitest";
import recheck from "../netlify/functions/recheck.js";

// Endpoint contract unit tests for the POST /api/recheck Netlify Function (task 6.3).
//
// These tests exercise recheck.js purely as an HTTP contract: method handling,
// JSON parsing, request validation, validation ORDER, and the non-recheckable
// short-circuit. They are fully hermetic — no path here reaches the network.
// Validation-failure paths return BEFORE recheckFinding is ever called, and the
// unrecognized-id path short-circuits to `indeterminate` inside recheckFinding
// without running any passive check (routeFor returns null).
//
// Requirements covered: 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6.

// Build a Web Request the same way the Netlify runtime would hand one to the
// function. Body is only attached when provided (GET/OPTIONS carry none).
function makeRequest({ method = "POST", body, headers } = {}) {
  const init = { method, headers: headers || { "content-type": "application/json" } };
  if (body !== undefined) init.body = body;
  return new Request("https://x/api/recheck", init);
}

// Convenience: a request whose JSON body is the given object.
function jsonRequest(obj, method = "POST") {
  return makeRequest({ method, body: JSON.stringify(obj) });
}

async function parseBody(res) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

describe("recheck endpoint — method handling", () => {
  it("responds to OPTIONS preflight with 204 and CORS headers", async () => {
    const res = await recheck(makeRequest({ method: "OPTIONS" }));
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
  });

  it("rejects non-POST methods (GET) with 405", async () => {
    const res = await recheck(makeRequest({ method: "GET" }));
    expect(res.status).toBe(405);
    const body = await parseBody(res);
    expect(body.error).toMatch(/POST/i);
  });
});

describe("recheck endpoint — body parsing", () => {
  it("returns 400 when the body is not valid JSON", async () => {
    const res = await recheck(makeRequest({ body: "{ not valid json" }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/json/i);
  });
});

describe("recheck endpoint — domain validation", () => {
  it("returns 400 when domain is missing", async () => {
    const res = await recheck(jsonRequest({ findingId: "spf-missing" }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/domain/i);
  });

  it("returns 400 when domain is invalid", async () => {
    const res = await recheck(jsonRequest({ domain: "invalid_domain!!", findingId: "spf-missing" }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/domain/i);
  });

  it("accepts and normalizes a domain with scheme + path (unrecognized id short-circuits)", async () => {
    // "https://Example.com/path" normalizes to "example.com" and passes validation.
    // Pairing it with an unrecognized id means we reach recheckFinding but run NO
    // network check — it returns 200 + indeterminate. This proves normalization works
    // without any real network access.
    const res = await recheck(
      jsonRequest({ domain: "https://Example.com/path", findingId: "totally-unknown-id" })
    );
    expect(res.status).toBe(200);
    const body = await parseBody(res);
    expect(body.status).toBe("indeterminate");
  });
});

describe("recheck endpoint — findingId validation", () => {
  it("returns 400 when findingId is missing", async () => {
    const res = await recheck(jsonRequest({ domain: "example.com" }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/findingId/i);
  });

  it("returns 400 when findingId is empty", async () => {
    const res = await recheck(jsonRequest({ domain: "example.com", findingId: "" }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/findingId/i);
  });

  it("accepts a 255-character findingId (under the limit)", async () => {
    // 255 unrecognized chars: passes length validation, then short-circuits to
    // indeterminate (no network).
    const id = "z".repeat(255);
    const res = await recheck(jsonRequest({ domain: "example.com", findingId: id }));
    expect(res.status).toBe(200);
    const body = await parseBody(res);
    expect(body.status).toBe("indeterminate");
  });

  it("accepts a 256-character findingId (at the boundary)", async () => {
    const id = "z".repeat(256);
    const res = await recheck(jsonRequest({ domain: "example.com", findingId: id }));
    expect(res.status).toBe(200);
    const body = await parseBody(res);
    expect(body.status).toBe("indeterminate");
  });

  it("returns 400 for a 257-character findingId (over the limit)", async () => {
    const id = "z".repeat(257);
    const res = await recheck(jsonRequest({ domain: "example.com", findingId: id }));
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/256|limit/i);
  });
});

describe("recheck endpoint — validation order", () => {
  it("returns the domain error first when BOTH domain and findingId are invalid", async () => {
    // Domain is validated before findingId (Req 2.5), so an invalid domain wins even
    // though the findingId (257 chars) is also invalid.
    const res = await recheck(
      jsonRequest({ domain: "invalid_domain!!", findingId: "z".repeat(257) })
    );
    expect(res.status).toBe(400);
    const body = await parseBody(res);
    expect(body.error).toMatch(/domain/i);
    expect(body.error).not.toMatch(/findingId/i);
  });
});

describe("recheck endpoint — non-recheckable findings", () => {
  it("returns 200 + indeterminate for a totally unknown id (NOT 400)", async () => {
    const res = await recheck(
      jsonRequest({ domain: "example.com", findingId: "totally-unknown-id" })
    );
    expect(res.status).toBe(200);
    const body = await parseBody(res);
    expect(body.status).toBe("indeterminate");
    expect(body.findingId).toBe("totally-unknown-id");
  });

  it("returns 200 + indeterminate for a non-recheckable subdomain id", async () => {
    // subdomain-* ids are explicitly Non_Recheckable: routeFor returns null and the
    // orchestrator short-circuits to indeterminate with no network check.
    const res = await recheck(
      jsonRequest({ domain: "example.com", findingId: "subdomain-dev" })
    );
    expect(res.status).toBe(200);
    const body = await parseBody(res);
    expect(body.status).toBe("indeterminate");
  });
});
