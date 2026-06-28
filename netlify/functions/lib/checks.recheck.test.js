import { describe, it, expect, afterEach, vi } from "vitest";
import { checkFileStatus } from "./checks.js";

// Unit tests for the status-only file probe used by single-finding re-checks.
//
// The ethical contract of this primitive (design: "lib/checks.js (modified)",
// Requirement 3.11) is that it inspects ONLY the HTTP status code and NEVER
// reads, parses, logs, or stores the response body — the probed path may hold
// real secrets. These tests pin both the status-to-result mapping (Req 3.9) and
// the never-touch-the-body guarantee (Req 3.11) using a fetch double whose body
// accessors throw/record if anything ever reaches for them.

// Build a Response-like double whose body accessors record (and reject) access.
// `bodyAccess` collects the name of any body accessor that was invoked so the
// test can assert the set stayed empty.
function makeResponseDouble(status, bodyAccess) {
  const trip = (name) => {
    bodyAccess.push(name);
    throw new Error(`response body was accessed via ${name}`);
  };
  const res = {
    status,
    headers: new Map(),
    text: () => trip("text"),
    json: () => trip("json"),
    arrayBuffer: () => trip("arrayBuffer"),
    blob: () => trip("blob"),
    formData: () => trip("formData"),
  };
  // `body` is a getter so even *reading* the property (not just calling it) is recorded.
  Object.defineProperty(res, "body", {
    get() {
      trip("body");
    },
    enumerable: true,
  });
  return res;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("checkFileStatus — status-to-result mapping (Req 3.9)", () => {
  it("returns exposed: true only on HTTP 200", async () => {
    const bodyAccess = [];
    vi.stubGlobal("fetch", vi.fn(async () => makeResponseDouble(200, bodyAccess)));

    const result = await checkFileStatus("example.com", "/.env");

    expect(result).toEqual({ reachable: true, status: 200, exposed: true });
    expect(bodyAccess).toEqual([]);
  });

  it.each([301, 302, 401, 403, 404, 410, 500, 503])(
    "returns exposed: false for non-200 status %i (still reachable)",
    async (status) => {
      const bodyAccess = [];
      vi.stubGlobal("fetch", vi.fn(async () => makeResponseDouble(status, bodyAccess)));

      const result = await checkFileStatus("example.com", "/.git/config");

      expect(result).toEqual({ reachable: true, status, exposed: false });
      expect(bodyAccess).toEqual([]);
    }
  );
});

describe("checkFileStatus — never reads the response body (Req 3.11)", () => {
  it("does not invoke any body accessor on a 200 response", async () => {
    const bodyAccess = [];
    const res = makeResponseDouble(200, bodyAccess);
    // Spy on each accessor so we can assert call counts directly too.
    const textSpy = vi.spyOn(res, "text");
    const jsonSpy = vi.spyOn(res, "json");
    const arrayBufferSpy = vi.spyOn(res, "arrayBuffer");
    vi.stubGlobal("fetch", vi.fn(async () => res));

    await checkFileStatus("example.com", "/secret.bak");

    expect(textSpy).not.toHaveBeenCalled();
    expect(jsonSpy).not.toHaveBeenCalled();
    expect(arrayBufferSpy).not.toHaveBeenCalled();
    expect(bodyAccess).toEqual([]);
  });

  it("does not invoke any body accessor on a non-200 response", async () => {
    const bodyAccess = [];
    vi.stubGlobal("fetch", vi.fn(async () => makeResponseDouble(403, bodyAccess)));

    await checkFileStatus("example.com", "/wp-config.php.bak");

    expect(bodyAccess).toEqual([]);
  });

  it("issues a status-only GET with redirect: manual and never reads the body", async () => {
    const bodyAccess = [];
    const fetchMock = vi.fn(async () => makeResponseDouble(200, bodyAccess));
    vi.stubGlobal("fetch", fetchMock);

    await checkFileStatus("example.com", "/.env");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("GET");
    expect(init.redirect).toBe("manual");
    expect(bodyAccess).toEqual([]);
  });
});

describe("checkFileStatus — failure handling (Req 3.9)", () => {
  it("returns the unreachable sentinel when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("network down");
    }));

    const result = await checkFileStatus("example.com", "/.env");

    expect(result).toEqual({ reachable: false, status: null, exposed: false });
  });

  it("returns the unreachable sentinel when the request times out (AbortError)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      const err = new Error("The operation timed out");
      err.name = "TimeoutError";
      throw err;
    }));

    const result = await checkFileStatus("example.com", "/.git/HEAD");

    expect(result).toEqual({ reachable: false, status: null, exposed: false });
  });
});
