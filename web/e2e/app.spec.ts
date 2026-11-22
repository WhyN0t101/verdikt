import { type APIRequestContext, expect, test, type Page } from "@playwright/test";

const BAD_IP = "185.220.101.4";
const GOOD_IP = "8.8.8.8";
const FLIP = "9.9.9.9"; // the fake VirusTotal answers clean on the first lookup and malicious afterwards (scripts/e2e_server.py)

// The backend is one in-memory server shared by every test, so a test that adds a watchlist entry
// removes it again (through the API, so it also happens when an assertion failed first).
async function unwatch(request: APIRequestContext, ioc: string) {
  await request.delete(`/api/watchlist?ioc=${encodeURIComponent(ioc)}`, { headers: { "x-verdikt-token": "e2e-token" } });
}

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

  // provenance: each row says whether it is live, and a verdict reason opens and focuses its row
  await expect(sources).toContainText("live, fetched");
  const vt = sources.getByRole("row", { name: /virustotal/ });
  await expect(vt.getByText("Weight in confidence")).toBeHidden(); // the row starts closed
  await verdict.getByRole("button", { name: /^virustotal: malicious/ }).click();
  await expect(vt.getByText("Weight in confidence")).toBeVisible();
  await expect(vt.getByText("Why this counted")).toBeFocused();
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

test("a repeated check shows a cached answer and the indicator history", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await check(page, BAD_IP);
  await expect(page.getByRole("region", { name: "Sources" })).toContainText("cached, fetched");
  const story = page.getByRole("region", { name: "Indicator history" });
  await expect(story).toContainText("This report");
  await expect(story.getByRole("button", { name: /^Open the report from/ }).first()).toBeVisible();
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

async function goto(page: Page, view: "Check" | "Overview" | "Batch" | "Cases") {
  await page.getByRole("navigation", { name: "Views" }).getByRole("button", { name: view }).click();
}

test("a report shows CVEs with KEV and EPSS context", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  const cves = page.getByRole("region", { name: "Vulnerabilities" });
  await expect(cves).toContainText("CVE-1999-0001");
  await expect(cves).toContainText("EPSS 4.8%");
  await expect(cves.getByText("KEV", { exact: true })).toBeVisible();
  await expect(cves.getByRole("link").first()).toHaveAttribute("rel", /noopener/);
  // context only: the verdict does not depend on CVEs
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText("Malicious");
});

test("overview shows activity, source health, recurring infrastructure and feeds", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await check(page, BAD_IP); // twice, so it counts as recurring
  await goto(page, "Overview");
  await expect(page.getByRole("img", { name: /Checks per day/ })).toBeVisible();
  await expect(page.getByRole("region", { name: "Source health" })).toContainText("virustotal");
  await expect(page.getByRole("region", { name: "Recurring infrastructure" })).toContainText(BAD_IP);
  await expect(page.getByRole("region", { name: "Local feeds" })).toContainText("No feeds yet");
  await expect(page.getByRole("region", { name: "Feedback" })).toBeVisible();

  // a recurring row can start a new check and returns to the Check view
  await page.getByRole("button", { name: `Check ${BAD_IP}` }).click();
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText(BAD_IP);
  await expect(page.getByRole("navigation", { name: "Views" }).getByRole("button", { name: "Check" })).toHaveAttribute("aria-current", "page");
});

test("feedback shows up in the overview counts", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await page.getByRole("button", { name: "False negative" }).click();
  await expect(page.getByText("Feedback recorded.")).toBeVisible();
  await goto(page, "Overview");
  await expect(page.getByRole("region", { name: "Feedback" })).toContainText("False negative");
});

test("watchlist: watch a report, re-check with no change, remove", async ({ page }) => {
  await page.goto("/");
  await check(page, GOOD_IP);
  await page.getByRole("button", { name: "Watch", exact: true }).click();
  await expect(page.getByRole("button", { name: "Watching" })).toBeDisabled();

  await goto(page, "Overview");
  const watch = page.getByRole("region", { name: "Watchlist" });
  await expect(watch).toContainText(GOOD_IP);
  await expect(watch).toContainText("Safe");
  await watch.getByRole("button", { name: "Re-check all" }).click();
  await expect(watch).toContainText("No verdict changed.");
  await watch.getByRole("button", { name: `Stop watching ${GOOD_IP}` }).click();
  await expect(watch).toContainText("Nothing watched yet");
});

test("batch: paste a ticket, extract, check all, skip internal targets, export CSV", async ({ page }) => {
  await page.goto("/");
  await goto(page, "Batch");
  const ticket = `Beacon from ${BAD_IP.replaceAll(".", "[.]")} to ${GOOD_IP}. Ignore 192.168.1.10. Dropped file md5 44d88612fea8a8f36de82e1278abb02f.`;
  await page.getByLabel("Text containing indicators").fill(ticket);
  await page.getByRole("button", { name: "Extract indicators" }).click();

  const results = page.getByRole("region", { name: "Batch results" });
  await expect(results).toContainText("3 indicators found");
  await expect(results).toContainText("1 skipped");
  await expect(results.getByText("192.168.1.10")).toBeHidden(); // inside the closed details
  await expect(results.getByRole("table")).not.toContainText("192.168");

  await results.getByRole("button", { name: /Check all 3/ }).click();
  await expect(results).toContainText("3 checked", { timeout: 15_000 });
  await expect(results.getByRole("row", { name: new RegExp(BAD_IP.replaceAll(".", "\\.")) })).toContainText("Malicious");
  await expect(results.getByRole("row", { name: new RegExp(GOOD_IP.replaceAll(".", "\\.")) })).toContainText("Safe");

  const download = page.waitForEvent("download");
  await results.getByRole("button", { name: "Export CSV" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("verdikt-batch.csv");
  const csv = await (await import("node:fs/promises")).readFile((await file.path()) ?? "", "utf-8");
  const lines = csv.trim().split("\n");
  expect(lines[0]).toBe("ioc,type,level,confidence,agreeing,total,report_id,reasons");
  expect(lines).toHaveLength(4);
  expect(csv).toContain(`${BAD_IP},ip,malicious`);

  // opening a row goes to the Check view with that report
  await results.getByRole("button", { name: `Open report for ${BAD_IP}` }).click();
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText(BAD_IP);
});

test("batch: text with no indicators says so", async ({ page }) => {
  await page.goto("/");
  await goto(page, "Batch");
  await page.getByLabel("Text containing indicators").fill("nothing to see here");
  await page.getByRole("button", { name: "Extract indicators" }).click();
  await expect(page.getByRole("region", { name: "Batch results" })).toContainText("No indicators found");
});

test("each source row explains why it counted the way it did", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  const sources = page.getByRole("region", { name: "Sources" });
  const vt = sources.getByRole("row", { name: /virustotal/ });
  await vt.getByText("Why").click();
  await expect(vt).toContainText("Strong source");
  await expect(vt).toContainText("Weight in confidence: 3");
  await expect(vt).toContainText("malicious 20 >= 5 -> malicious");
  const feed = sources.getByRole("row", { name: /threatfox/ });
  await feed.getByText("Why").click();
  await expect(feed).toContainText("List-only feed");
  await expect(feed).toContainText("No rule matched.");
});

test("cases: create from a report, edit notes and tags, export, reopen the report", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await page.getByRole("button", { name: "New case" }).click();
  await expect(page.getByText("Case created with this report.")).toBeVisible();

  await goto(page, "Cases");
  const list = page.getByRole("region", { name: "Cases", exact: true });
  await list.getByRole("button", { name: `Investigation: ${BAD_IP.replaceAll(".", "[.]")}` }).first().click();
  const detail = page.getByRole("region", { name: "Case detail" });
  await detail.getByLabel("Notes").fill("Seen first in the proxy logs at 09:00.");
  await detail.getByLabel("Tags (comma separated)").fill("Phishing, q4");
  await detail.getByRole("button", { name: "Save case" }).click();
  await expect(detail.getByText("Case saved.")).toBeVisible();
  await expect(list.getByRole("button", { name: "phishing", exact: true })).toBeVisible(); // tag chips are lower-cased

  const download = page.waitForEvent("download");
  await detail.getByRole("button", { name: "Export Markdown" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^verdikt-case-[0-9a-f]{8}\.md$/);
  const md = await (await import("node:fs/promises")).readFile((await file.path()) ?? "", "utf-8");
  expect(md).toContain("# Investigation:");
  expect(md).toContain("Seen first in the proxy logs");
  expect(md).toContain("185[.]220[.]101[.]4"); // defanged for sharing

  await detail.getByRole("button", { name: `Open report for ${BAD_IP}` }).click();
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText(BAD_IP);
});

test("a report can be exported as MISP, Markdown and HTML", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  const read = async (label: string) => {
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: label, exact: true }).click();
    const file = await download;
    return { name: file.suggestedFilename(), text: await (await import("node:fs/promises")).readFile((await file.path()) ?? "", "utf-8") };
  };
  const misp = await read("Export MISP");
  expect(misp.name).toMatch(/\.misp\.json$/);
  expect(JSON.parse(misp.text).Event.Attribute[0].value).toBe(BAD_IP);
  const md = await read("Report (Markdown)");
  expect(md.text).toContain("MALICIOUS: 185[.]220[.]101[.]4");
  const html = await read("Report (HTML)");
  expect(html.text).toContain("<!doctype html>");
  expect(html.text).not.toMatch(/<script/i);
});

test("scheduler panel shows jobs and runs one on demand", async ({ page }) => {
  await page.goto("/");
  await goto(page, "Overview");
  const panel = page.getByRole("region", { name: "Scheduler" });
  await expect(panel).toContainText("watch");
  await expect(panel).toContainText("off"); // nothing is scheduled by default
  await panel.getByRole("button", { name: "Run the watch job now" }).click();
  await expect(panel).toContainText("0 verdict change(s)");
});

test("import a MISP file as a local list and forget it again", async ({ page }) => {
  await page.goto("/");
  await goto(page, "Overview");
  const feeds = page.getByRole("region", { name: "Local feeds" });
  await feeds.getByLabel("Name for the imported list").fill("case-1");
  const misp = { Event: { Attribute: [{ type: "ip-dst", value: "91.92.109.10", to_ids: true }, { type: "ip-dst", value: "8.8.4.4", to_ids: false }] } };
  await feeds.getByLabel("MISP event or STIX bundle file").setInputFiles({ name: "event.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(misp)) });
  await expect(feeds).toContainText("Imported 1 indicator(s) from a misp file as case-1.");
  await expect(feeds).toContainText("import:case-1");

  await goto(page, "Check");
  await check(page, "91.92.109.10");
  await expect(page.getByRole("region", { name: "Verdict" })).toContainText("Malicious"); // blocklisted locally

  await goto(page, "Overview");
  await feeds.getByRole("button", { name: "Forget imported list case-1" }).click();
  await expect(feeds).not.toContainText("import:case-1");
});

test("a verdict flip shows what changed and the indicator history", async ({ page, request }) => {
  try {
    await page.goto("/");
    await check(page, FLIP); // first lookup: safe
    await page.getByRole("button", { name: "Watch", exact: true }).click();
    await expect(page.getByRole("button", { name: "Watching" })).toBeDisabled();

    await goto(page, "Overview");
    const watch = page.getByRole("region", { name: "Watchlist" });
    await watch.getByRole("button", { name: "Re-check all" }).click(); // second lookup: malicious
    await watch.getByRole("button", { name: `What changed for ${FLIP}` }).click({ timeout: 15_000 });

    const changes = page.getByRole("region", { name: "Changes" });
    await expect(changes).toContainText("Changes since");
    await expect(changes).toContainText("Safe");
    await expect(changes).toContainText("Malicious");
    await expect(changes).toContainText("virustotal");

    const story = page.getByRole("region", { name: "Indicator history" });
    await expect(story).toContainText("This report");
    await expect(story).toContainText("Watching since");
    await expect(story).toContainText("1 verdict change");
  } finally {
    await unwatch(request, FLIP);
  }
});

test("a repeat check of a clean indicator says nothing changed", async ({ page }) => {
  await page.goto("/");
  await check(page, GOOD_IP);
  await check(page, GOOD_IP);
  await expect(page.getByRole("region", { name: "Changes" })).toContainText("Nothing changed");
});

test("history search: filter, clear, literal percent sign, and shortcuts ignore the select", async ({ page }) => {
  await page.goto("/");
  await check(page, BAD_IP);
  await check(page, GOOD_IP);
  const history = page.getByRole("navigation", { name: "History" });

  await page.getByLabel("Search history").fill("185.220");
  await expect(history).not.toContainText(GOOD_IP);
  await expect(history).toContainText(BAD_IP);
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(history).toContainText(GOOD_IP);

  const verdict = page.getByRole("combobox", { name: "Verdict" });
  await verdict.selectOption("safe");
  await expect(history).not.toContainText(BAD_IP);
  await expect(history).toContainText(GOOD_IP);
  await page.getByRole("button", { name: "Clear" }).click();

  await page.getByLabel("Search history").fill("%"); // a literal percent sign, not "match anything"
  await expect(page.getByText("No report matches.")).toBeVisible();
  await page.getByRole("button", { name: "Clear" }).click();

  await verdict.focus();
  await page.keyboard.press("2"); // would open the Graph tab if the shortcut ignored selects
  await expect(page.getByRole("tab", { name: /Map/ })).toHaveAttribute("aria-selected", "true");
});

test("batch triage: add results to a new case and to the watchlist", async ({ page, request }) => {
  const iocs = [BAD_IP, GOOD_IP, "44d88612fea8a8f36de82e1278abb02f"];
  try {
    await page.goto("/");
    await goto(page, "Batch");
    const ticket = `Beacon from ${BAD_IP.replaceAll(".", "[.]")} to ${GOOD_IP}. Dropped file md5 ${iocs[2]}.`;
    await page.getByLabel("Text containing indicators").fill(ticket);
    await page.getByRole("button", { name: "Extract indicators" }).click();
    const results = page.getByRole("region", { name: "Batch results" });
    await expect(results).toContainText("3 indicators found");
    await results.getByRole("button", { name: /Check all 3/ }).click();
    await expect(results).toContainText("3 checked", { timeout: 15_000 });

    const triage = page.getByRole("region", { name: "Triage actions" });
    await expect(triage).toContainText("1 selected"); // default: malicious and suspicious, so only the beacon
    await triage.getByLabel("Which results").selectOption("all");
    await expect(triage).toContainText("3 selected");
    await triage.getByLabel("Case to add to").selectOption("new");
    await triage.getByRole("button", { name: "Add 3 to case" }).click();
    await expect(triage).toContainText("3 added to the case");

    // the watch step comes before leaving the page: the Batch table lives in this view's state
    await triage.getByRole("button", { name: "Watch 3" }).click();
    await expect(triage).toContainText("3 added.");
    await expect(triage.getByRole("button", { name: "Watch 0" })).toBeDisabled();
    await expect(triage).toContainText("3 already watched");

    await goto(page, "Cases");
    const made = page.getByRole("region", { name: "Cases", exact: true }).getByRole("button", { name: /^Batch triage, / }).first();
    await expect(made).not.toContainText(BAD_IP); // the title carries no indicator
    await made.click();
    const detail = page.getByRole("region", { name: "Case detail" });
    await expect(detail).toContainText(BAD_IP);
    await expect(detail).toContainText(GOOD_IP);
  } finally {
    for (const ioc of iocs) await unwatch(request, ioc);
  }
});
