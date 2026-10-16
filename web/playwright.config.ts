import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 240_000,
  expect: { timeout: 30_000 },
  use: {
    baseURL: process.env.VITE_TEST_URL ?? "http://127.0.0.1:5173",
    viewport: { width: 1440, height: 1000 },
    screenshot: "only-on-failure",
  },
});
