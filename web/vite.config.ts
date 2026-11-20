import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Dev only: `verdikt ui --dev` serves the API on 8765 with a fixed token.
const API = "http://127.0.0.1:8765";
const DEV_TOKEN = "dev-token";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../src/verdikt/web_dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": {
        target: API,
        changeOrigin: true, // rewrites Host to 127.0.0.1:8765 so the API host check passes
        headers: { "x-verdikt-token": DEV_TOKEN },
      },
    },
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
