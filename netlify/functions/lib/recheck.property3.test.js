import { describe, it, expect, vi } from "vitest";
import fc from "fast-check";
import { recheckFinding, STATUS } from "./recheck.js";

// ---------------------------------------------------------------------------
// Property 3: Each recheckable family maps to the correct check and resolution
//             predicate.
//
// For any recheckable Finding_Id family and any generated *successful* observation
// for that family, recheckFinding SHALL invoke exactly the mapped check(s) for that
// family and SHALL return the Recheck_Status dictated by that family's documented
// truth table (design.md "Finding-to-check mapping table").
//
// The orchestrator's I/O is fully injected via `deps`, so every iteration runs
// in-memory with no real network access. Each fake dependency returns
// fast-check-generated values matching the corresponding real check's output shape:
//   checkDns           -> { spf, dmarc, caa: { status } }
//   checkSsl           -> { expiresInDays, error: null }
//   checkHeaders       -> { reachable: true, hsts/csp/xfo/xcto, setCookies, body, servedHttps }
//   analyzeCookies     -> { missingSecure, missingHttpOnly, missingSameSite }
//   analyzeMixedContent-> { count }
//   checkRobotsSitemap -> { sensitiveDisallows }
//   checkFileStatus    -> { reachable: true, status }
//
// **Validates: Requirements 1.1, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9**
// ---------------------------------------------------------------------------

const DOMAIN = "example.com";

// id -> boolean key on the headers observation (design HEADER_KEYS).
const HEADER_KEY = {
  "hdr-hsts": "hsts",
  "hdr-csp": "csp",
  "hdr-xfo": "xfo",
  "hdr-xcto": "xcto",
};

// id -> the analyzeCookies "missing*" list that tracks the attribute (design COOKIE_ATTRS).
const COOKIE_MISSING_KEY = {
  "cookie-secure": "missingSecure",
  "cookie-httponly": "missingHttpOnly",
  "cookie-samesite": "missingSameSite",
};

// Build a full set of injectable check dependencies as spies. Every check defaults
// to a benign, reachable, "no issue" value; per-scenario overrides replace only the
// dependency under test so we can both (a) drive the generated observation and
// (b) assert which dependency the family's route actually invoked.
function makeDeps() {
  return {
    checkDns: vi.fn(async () => ({ spf: false, dmarc: false, caa: { status: "missing" } })),
    checkSsl: vi.fn(async () => ({ expiresInDays: 365, error: null })),
    checkHeaders: vi.fn(async () => ({
      reachable: true,
      hsts: false,
      csp: false,
      xfo: false,
      xcto: false,
      setCookies: [],
      body: "",
      servedHttps: true,
    })),
    checkRobotsSitemap: vi.fn(async () => ({ sensitiveDisallows: [] })),
    analyzeCookies: vi.fn(() => ({ missingSecure: [], missingHttpOnly: [], missingSameSite: [] })),
    analyzeMixedContent: vi.fn(() => ({ count: 0 })),
    // checkFileStatus is used both as the robots reachability probe (/robots.txt)
    // and as the exposed-file status-only probe. Default to reachable so the robots
    // family's reachability guard passes.
    checkFileStatus: vi.fn(async () => ({ reachable: true, status: 404, exposed: false })),
  };
}

// A non-200 HTTP status generator (for the exposed-file "resolved" branch).
const nonOkStatusArb = fc
  .integer({ min: 100, max: 599 })
  .filter((s) => s !== 200);

// Per-family scenario generators. Each yields a plain descriptor; the predicate
// configures the matching dependency, runs recheckFinding, and asserts.
const scenarioArb = fc.oneof(
  // --- SPF (Req 3.1): record present -> resolved, absent -> unresolved.
  fc.record({ family: fc.constant("spf"), present: fc.boolean() }),

  // --- DMARC (Req 3.2): record present -> resolved, absent -> unresolved.
  fc.record({ family: fc.constant("dmarc"), present: fc.boolean() }),

  // --- CAA (Req 3.3): present -> resolved, missing -> unresolved, unknown -> indeterminate.
  fc.record({
    family: fc.constant("caa"),
    status: fc.constantFrom("present", "missing", "unknown"),
  }),

  // --- Security headers (Req 3.4): header present -> resolved, absent -> unresolved.
  fc.record({
    family: fc.constant("header"),
    id: fc.constantFrom("hdr-hsts", "hdr-csp", "hdr-xfo", "hdr-xcto"),
    present: fc.boolean(),
  }),

  // --- SSL (Req 3.5): readable & expiresInDays > 30 -> resolved; <= 30 (incl. expired) -> unresolved.
  // Boundary values {-1, 0, 30, 31} are explicitly included alongside a wide range.
  fc.record({
    family: fc.constant("ssl"),
    id: fc.constantFrom("ssl-error", "ssl-expired", "ssl-expiring", "ssl-expiring-soon", "ssl-weird"),
    days: fc.oneof(
      fc.constantFrom(-1, 0, 30, 31),
      fc.integer({ min: -400, max: 1000 })
    ),
  }),

  // --- Cookie attributes (Req 3.6): missing list empty -> resolved, non-empty -> unresolved.
  fc.record({
    family: fc.constant("cookie"),
    id: fc.constantFrom("cookie-secure", "cookie-httponly", "cookie-samesite"),
    missing: fc.array(fc.string({ minLength: 1 }), { maxLength: 6 }),
  }),

  // --- Mixed content (Req 3.7): count === 0 -> resolved, >= 1 -> unresolved.
  fc.record({ family: fc.constant("mixed-content"), count: fc.nat({ max: 50 }) }),

  // --- Sensitive robots disclosures (Req 3.8): no entries -> resolved, >= 1 -> unresolved.
  fc.record({
    family: fc.constant("robots"),
    disallows: fc.array(fc.string({ minLength: 1 }), { maxLength: 6 }),
  }),

  // --- Exposed file (Req 3.9): still HTTP 200 -> unresolved, any other status -> resolved.
  fc.record({
    family: fc.constant("exposed-file"),
    path: fc.string({ minLength: 1 }),
    status: fc.oneof(fc.constant(200), nonOkStatusArb),
  })
);

// Configure deps for a scenario and return { findingId, expectedStatus, invoked, notInvoked }.
// `invoked` lists the dependency names the family's route MUST call; `notInvoked` lists
// representative dependencies belonging to other families that MUST stay untouched.
function applyScenario(scenario, deps) {
  switch (scenario.family) {
    case "spf": {
      deps.checkDns = vi.fn(async () => ({ spf: scenario.present, dmarc: false, caa: { status: "missing" } }));
      return {
        findingId: "spf-missing",
        expectedStatus: scenario.present ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkDns"],
        notInvoked: ["checkSsl", "checkHeaders", "checkRobotsSitemap", "checkFileStatus"],
      };
    }
    case "dmarc": {
      deps.checkDns = vi.fn(async () => ({ spf: false, dmarc: scenario.present, caa: { status: "missing" } }));
      return {
        findingId: "dmarc-missing",
        expectedStatus: scenario.present ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkDns"],
        notInvoked: ["checkSsl", "checkHeaders", "checkRobotsSitemap", "checkFileStatus"],
      };
    }
    case "caa": {
      deps.checkDns = vi.fn(async () => ({ spf: false, dmarc: false, caa: { status: scenario.status } }));
      const expected =
        scenario.status === "present"
          ? STATUS.RESOLVED
          : scenario.status === "missing"
          ? STATUS.UNRESOLVED
          : STATUS.INDETERMINATE;
      return {
        findingId: "caa-missing",
        expectedStatus: expected,
        invoked: ["checkDns"],
        notInvoked: ["checkSsl", "checkHeaders", "checkRobotsSitemap", "checkFileStatus"],
      };
    }
    case "header": {
      const key = HEADER_KEY[scenario.id];
      deps.checkHeaders = vi.fn(async () => ({
        reachable: true,
        hsts: false,
        csp: false,
        xfo: false,
        xcto: false,
        [key]: scenario.present,
        setCookies: [],
        body: "",
        servedHttps: true,
      }));
      return {
        findingId: scenario.id,
        expectedStatus: scenario.present ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkHeaders"],
        notInvoked: ["checkDns", "checkSsl", "checkRobotsSitemap", "checkFileStatus"],
      };
    }
    case "ssl": {
      deps.checkSsl = vi.fn(async () => ({ expiresInDays: scenario.days, error: null }));
      return {
        findingId: scenario.id,
        expectedStatus: scenario.days > 30 ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkSsl"],
        notInvoked: ["checkDns", "checkHeaders", "checkRobotsSitemap", "checkFileStatus"],
      };
    }
    case "cookie": {
      const missingKey = COOKIE_MISSING_KEY[scenario.id];
      const cookieResult = { missingSecure: [], missingHttpOnly: [], missingSameSite: [] };
      cookieResult[missingKey] = scenario.missing;
      // Headers must be reachable and carry some cookies; cookie analysis is the discriminator.
      deps.checkHeaders = vi.fn(async () => ({
        reachable: true,
        hsts: false,
        csp: false,
        xfo: false,
        xcto: false,
        setCookies: ["sid=abc"],
        body: "",
        servedHttps: true,
      }));
      deps.analyzeCookies = vi.fn(() => cookieResult);
      return {
        findingId: scenario.id,
        expectedStatus: scenario.missing.length === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkHeaders", "analyzeCookies"],
        notInvoked: ["checkDns", "checkSsl", "checkRobotsSitemap"],
      };
    }
    case "mixed-content": {
      deps.checkHeaders = vi.fn(async () => ({
        reachable: true,
        hsts: false,
        csp: false,
        xfo: false,
        xcto: false,
        setCookies: [],
        body: "<html></html>",
        servedHttps: true,
      }));
      deps.analyzeMixedContent = vi.fn(() => ({ count: scenario.count }));
      return {
        findingId: "mixed-content",
        expectedStatus: scenario.count === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkHeaders", "analyzeMixedContent"],
        notInvoked: ["checkDns", "checkSsl", "checkRobotsSitemap"],
      };
    }
    case "robots": {
      // The orchestrator first probes checkFileStatus(domain, "/robots.txt") for
      // reachability; the default reachable probe satisfies that guard.
      deps.checkRobotsSitemap = vi.fn(async () => ({ sensitiveDisallows: scenario.disallows }));
      return {
        findingId: "robots-sensitive",
        expectedStatus: scenario.disallows.length === 0 ? STATUS.RESOLVED : STATUS.UNRESOLVED,
        invoked: ["checkRobotsSitemap", "checkFileStatus"],
        notInvoked: ["checkDns", "checkSsl", "checkHeaders"],
      };
    }
    case "exposed-file": {
      deps.checkFileStatus = vi.fn(async () => ({
        reachable: true,
        status: scenario.status,
        exposed: scenario.status === 200,
      }));
      return {
        findingId: `exposed-file-${scenario.path}`,
        expectedStatus: scenario.status === 200 ? STATUS.UNRESOLVED : STATUS.RESOLVED,
        invoked: ["checkFileStatus"],
        notInvoked: ["checkDns", "checkSsl", "checkHeaders", "checkRobotsSitemap"],
      };
    }
    default:
      throw new Error(`unhandled family ${scenario.family}`);
  }
}

describe("recheck router — Property 3 (family-to-predicate truth table)", () => {
  it("Feature: finding-recheck, Property 3: Each recheckable family maps to the correct check and resolution predicate", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, async (scenario) => {
        const deps = makeDeps();
        const { findingId, expectedStatus, invoked, notInvoked } = applyScenario(scenario, deps);

        const result = await recheckFinding({ domain: DOMAIN, findingId }, deps);

        // Echoes the requested id and yields the truth-table status.
        expect(result.findingId).toBe(findingId);
        expect(result.status).toBe(expectedStatus);

        // The family's mapped check(s) were invoked...
        for (const name of invoked) {
          expect(deps[name]).toHaveBeenCalled();
        }
        // ...and no other family's check was touched.
        for (const name of notInvoked) {
          expect(deps[name]).not.toHaveBeenCalled();
        }
      }),
      { numRuns: 200 }
    );
  });
});
