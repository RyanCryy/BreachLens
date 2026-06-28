import { defineConfig } from "vitest/config";

// BreachLens is ESM ("type": "module"). Vitest runs these modules in-process
// for fast, network-free unit and property-based tests; the functions themselves
// still deploy to Deno unchanged.
//
// Default test environment is `node`. Frontend DOM tests opt in to jsdom per file
// via a docblock at the top of the test file:
//
//   /** @vitest-environment jsdom */
//
export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.js"],
    exclude: ["node_modules/**", ".netlify/**", "dist/**"],
  },
});
