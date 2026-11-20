// Types come from the OpenAPI schema dumped offline: /openapi.json is token-gated at runtime.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "..");
const venvPython = [join(root, ".venv", "Scripts", "python.exe"), join(root, ".venv", "bin", "python")].find(existsSync);
if (!venvPython) throw new Error("no .venv found: run `uv sync` in the repo root first");

const dir = mkdtempSync(join(tmpdir(), "verdikt-openapi-"));
const schema = join(dir, "openapi.json");
try {
  execFileSync(venvPython, [join(root, "scripts", "dump_openapi.py"), schema], { stdio: "inherit" });
  execFileSync("npx", ["openapi-typescript", schema, "-o", "src/types.ts"], { stdio: "inherit", shell: process.platform === "win32" });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
