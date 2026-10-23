// @ts-check
const { defineConfig } = require("@playwright/test");

/**
 * Playwright E2E Integration Configuration (T12)
 * Orchestrates full trust flow verification across real EVM contracts and Python API.
 */
module.exports = defineConfig({
  testDir: "./tests/e2e",
  testMatch: /.*\.spec\.(js|ts)/,
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
  fullyParallel: false,
  workers: 1, // Sequential execution for deterministic nonce and governance proposal order
  retries: 0,
  reporter: [
    ["list"],
    ["json", { outputFile: "test-results/integration-results.json" }],
  ],
  use: {
    baseURL: process.env.API_BASE_URL || "http://127.0.0.1:8000",
    trace: "off",
  },
});
