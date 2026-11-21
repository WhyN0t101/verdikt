import { expect, test, type Page } from "@playwright/test";

const BAD_IP = "185.220.101.4";
const GOOD_IP = "8.8.8.8";

async function check(page: Page, ioc: string) {
  const box = page.getByLabel("IP, domain, URL or hash");
  await box.fill(ioc);
  await box.press("Enter");
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText(ioc);
}

test.beforeEach(async ({ page }) => {
  // any console error (CSP violation, failed module, React error) fails the test
  const errors: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  (page as Page & { errors: string[] }).errors = errors;
});

test.afterEach(async ({ page }, info) => {
  // the refusal test provokes a 422 on purpose; the browser logs it as a console error
  const expected = info.title.includes("internal targets") ? /status of 422/ : /^$/;
  const errors = (page as Page & { errors: string[] }).errors.filter((e) => !expected.test(e));
  expect(errors).toEqual([]);
});

test("empty state, then a malicious check shows verdict, sources and log", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Check an indicator" })).toBeVisible();

  await check(page, BAD_IP);
  const verdict = page.getByRole("region", { name: "Verdict" });
  await expect(verdict).toContainText("Malicious");
  await expect(verdict).toContainText("sources agree");

  const sources = page.getByRole("region", { name: "Sources" });
  await expect(sources).toContainText("virustotal");
  await expect(sources).toContainText("20/92 engines malicious");
  await expect(sources).toContainText("threatfox");

  await expect(page.getByRole("region", { name: "Source log" })).toContainText(/virustotal/i);
  await expect(page.getByRole("region", { name: "Diagnostics" })).toContainText("high confidence");
});

test("a clean indicator is safe with evidence, and defanged input is accepted", async ({ page }) => {
  await page.goto("/");
  await check(page, GOOD_IP);
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText("Safe");

  await page.getByLabel("IP, domain, URL or hash").fill("hxxp://evil[.]example/a");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText("http://evil.example/a");
});

test("internal targets are refused with a clear message and nothing is added to history", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("IP, domain, URL or hash").fill("192.168.1.10");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("alert")).toContainText("internal");
  await expect(page.getByRole("navigation", { name: "History" })).not.toContainText("192.168");
});

test("history lists checks and reopens one", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await check(page, GOOD_IP);
  const history = page.getByRole("navigation", { name: "History" });
  await expect(history).toContainText(BAD_IP);
  await history.getByRole("button", { name: new RegExp(BAD_IP.replaceAll(".", "\\.")) }).first().click();
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText("Malicious");
});

test("a repeat check shows the earlier report under Seen before and opens it", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await check(page, BAD_IP);
  const seen = page.getByRole("region", { name: "Report actions" });
  await expect(seen).toContainText("Seen before");
  await seen.getByRole("button", { name: /185/ }).first().click();
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText(BAD_IP);
});

test("keyboard: Ctrl+K focuses search, 3 opens Raw JSON, 1 returns to the map, Esc clears", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("3");
  await expect(page.getByRole("tab", { name: /Raw JSON/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("pre")).toContainText('"schema_version"');
  await expect(page.locator("pre")).toContainText("fake"); // vendor raw is only in the raw tab
  await page.keyboard.press("1");
  await expect(page.getByRole("tab", { name: /Map/ })).toHaveAttribute("aria-selected", "true");

  await page.keyboard.press("Control+k");
  await expect(page.getByLabel("IP, domain, URL or hash")).toBeFocused();
  await page.keyboard.type("abc");
  await page.keyboard.press("Escape");
  await expect(page.getByLabel("IP, domain, URL or hash")).toHaveValue("");
});

test("graph tab renders the relationship graph for related indicators", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await page.getByRole("tab", { name: /Graph/ }).click();
  await expect(page.getByRole("img", { name: /Relationship graph with 3 nodes/ })).toBeVisible();
  await expect(page.locator("canvas").first()).toBeVisible();
});

test("feedback is recorded and the STIX export downloads a bundle", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await page.getByRole("button", { name: "False positive" }).click();
  await expect(page.getByText("Feedback recorded.")).toBeVisible();

  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export STIX" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^verdikt-[0-9a-f]+\.stix\.json$/);
  const path = await file.path();
  const bundle = JSON.parse(await (await import("node:fs/promises")).readFile(path, "utf-8"));
  expect(bundle.type).toBe("bundle");
  expect(bundle.objects[1].pattern).toBe(`[ipv4-addr:value = '${BAD_IP}']`);
});

test("theme toggle switches and persists across reloads", async ({ page }) => {
  await page.goto("/");
  const html = page.locator("html");
  await page.getByRole("button", { name: /Switch to (light|dark) theme/ }).click();
  const chosen = await html.getAttribute("data-theme");
  expect(["light", "dark"]).toContain(chosen);
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", chosen ?? "");
});

test("the API refuses calls without the session token and with a foreign Host", async ({ page, request }) => {
  await page.goto("/");
  expect((await request.get("/api/health")).status()).toBe(401);
  expect((await request.get("/api/health", { headers: { "x-verdikt-token": "wrong" } })).status()).toBe(401);
  expect((await request.get("/api/health", { headers: { "x-verdikt-token": "e2e-token", host: "evil.example" } })).status()).toBe(421);
  const ok = await request.get("/api/health", { headers: { "x-verdikt-token": "e2e-token" } });
  expect(await ok.json()).toEqual({ status: "ok" });
});

test("pages are served with a strict CSP and the token is injected", async ({ page }) => {
  const res = await page.goto("/");
  expect(res?.headers()["content-security-policy"]).toContain("default-src 'self'");
  expect(await page.locator('meta[name="verdikt-token"]').getAttribute("content")).toBe("e2e-token");
});
