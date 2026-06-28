import { describe, it, expect } from "vitest";
import * as checks from "./checks.js";

// Smoke test: confirms the ESM test wiring works end to end — Vitest can import
// the real lib/checks.js module in-process without errors. This validates the
// test runner setup (task 1) before any feature logic is built on top of it.
describe("test wiring smoke test", () => {
  it("imports lib/checks.js as an ESM module", () => {
    expect(checks).toBeTypeOf("object");
  });

  it("exposes the expected pure helpers used by the recheck feature", () => {
    expect(checks.normalizeDomain).toBeTypeOf("function");
    expect(checks.isValidDomain).toBeTypeOf("function");
    expect(checks.withTimeout).toBeTypeOf("function");
  });

  it("can call a pure helper from the imported module", () => {
    expect(checks.isValidDomain("example.com")).toBe(true);
    expect(checks.normalizeDomain("https://Example.com/path")).toBe("example.com");
  });
});
