import { expect, test } from "@playwright/test";

const report = {
  schema_version: 1,
  id: "abc",
  ioc: "185.220.101.4",
  ioc_type: "ip",
  level: "malicious",
  agreeing: 1,
  total: 1,
  reasons: ["virustotal: malicious 12 >= 5 -> malicious"],
  results: [
    {
      source: "virustotal",
      status: "ok",
      metrics: { malicious: 12 },
      level: "malicious",
      summary: "12/94 engines malicious",
      tags: [],
      link: "https://www.virustotal.com/gui/ip-address/185.220.101.4",
      related: [],
      cached: false,
      fetched_at: "2026-01-01T14:03:15Z",
      raw: null,
    },
  ],
  geo: [],
  graph: { nodes: [{ id: "ip:185.220.101.4", label: "185.220.101.4", kind: "ip", level: "malicious" }], edges: [] },
  duration_ms: 1200,
  created_at: "2026-01-01T14:03:15Z",
};

test("search shows the verdict card", async ({ page }) => {
  await page.route("**/api/check", (route) => route.fulfill({ json: report }));
  await page.goto("/");
  await page.getByLabel("IP, domain, URL or hash").fill("185.220.101.4");
  await page.keyboard.press("Enter");
  const card = page.getByRole("region", { name: "Verdict" });
  await expect(card).toBeVisible();
  await expect(card).toContainText("Malicious");
  await expect(card).toContainText("185.220.101.4");
});
