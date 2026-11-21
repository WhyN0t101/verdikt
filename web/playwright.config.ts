import { defineConfig, devices } from "@playwright/test";

// End to end against the real API and the built SPA (`npm run build` first). The backend is
// scripts/e2e_server.py: fake sources, in-memory database, no live intel calls.
// Locally use an installed browser with PW_CHANNEL=msedge (or chrome); CI installs chromium.
const python = process.platform === "win32" ? "..\\.venv\\Scripts\\python" : "../.venv/bin/python";
const script = process.platform === "win32" ? "..\\scripts\\e2e_server.py" : "../scripts/e2e_server.py";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false, // one in-memory backend shared by every test
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: "http://127.0.0.1:8768", trace: "retain-on-failure" },
  projects: [{ name: "browser", use: { ...devices["Desktop Chrome"], channel: process.env.PW_CHANNEL || undefined } }],
  webServer: {
    command: `${python} ${script}`,
    url: "http://127.0.0.1:8768/",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
