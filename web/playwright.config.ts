import { defineConfig } from "@playwright/test";

// Serves the built SPA from the real backend; API calls are stubbed in the test (no live intel calls).
export default defineConfig({
  testDir: "e2e",
  use: { baseURL: "http://127.0.0.1:8765" },
  webServer: {
    command: process.platform === "win32" ? "..\\.venv\\Scripts\\python -m verdikt ui --no-open --port 8765" : "../.venv/bin/python -m verdikt ui --no-open --port 8765",
    url: "http://127.0.0.1:8765/",
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
