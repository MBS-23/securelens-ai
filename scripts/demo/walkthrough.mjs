// Recorded tour of the running SecureLens AI platform (real API, worker and dashboard).
// Started by scripts/demo.sh:  node walkthrough.mjs <work-dir with zips> <output dir> <dashboard URL>
import { mkdirSync, readdirSync, renameSync } from "node:fs";
import { chromium } from "../../frontend/node_modules/playwright/index.mjs";

const [D, OUTDIR, BASE] = process.argv.slice(2);
const SHOTS = `${OUTDIR}/screenshots`;
mkdirSync(SHOTS, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1366, height: 820 },
  recordVideo: { dir: `${D}/video`, size: { width: 1366, height: 820 } },
});
const page = await context.newPage();
page.setDefaultTimeout(30_000);

const caption = (text) =>
  page.evaluate((t) => {
    let el = document.getElementById("demo-caption");
    if (!el) {
      el = document.createElement("div");
      el.id = "demo-caption";
      Object.assign(el.style, {
        position: "fixed", left: "50%", bottom: "18px", transform: "translateX(-50%)", zIndex: "9999",
        background: "rgba(11,27,54,.94)", color: "#fff", padding: "9px 16px", borderRadius: "6px",
        font: "500 14px system-ui, sans-serif", pointerEvents: "none", boxShadow: "0 2px 12px rgba(0,0,0,.35)",
        maxWidth: "80vw", textAlign: "center",
      });
      document.body.appendChild(el);
    }
    el.textContent = t;
  }, text);
const pause = (ms) => page.waitForTimeout(ms);
async function shot(name, target = page) {
  await target.evaluate(() => { const el = document.getElementById("demo-caption"); if (el) el.style.visibility = "hidden"; });
  await target.screenshot({ path: `${SHOTS}/${name}.png` });
  await target.evaluate(() => { const el = document.getElementById("demo-caption"); if (el) el.style.visibility = "visible"; });
}
const nav = (name) => page.getByRole("navigation").getByRole("link", { name, exact: true }).click();
async function waitForScan() {
  await page.getByText("Completed", { exact: true }).first().waitFor({ state: "visible", timeout: 180_000 });
  await pause(900);
}
async function uploadScan(zip, repo) {
  await page.getByRole("link", { name: "New scan" }).first().click();
  await page.locator('input[type="file"]').setInputFiles(zip);
  await page.getByLabel("Repository name").fill(repo);
}

// 1 — First run
await page.goto(`${BASE}/setup`);
await caption("SecureLens AI — first run. The 3D mark assembles, then follows the pointer.");
await pause(1200);
for (let i = 0; i <= 24; i++) {
  await page.mouse.move(120 + i * 22, 180 + Math.sin(i / 3) * 140);
  await pause(60);
}
await shot("01-setup");
await page.getByLabel("Organization").fill("Shop Team");
await page.getByLabel("Your name").fill("Olivia Owner");
await page.getByLabel("Email").fill("owner@example.com");
await page.getByLabel("Password", { exact: true }).fill("correct-horse-battery-7");
await caption("Create the organization and its first owner account (works only once).");
await pause(900);
await page.getByRole("button", { name: "Create organization" }).click();
await page.waitForURL(`${BASE}/`);
await caption("Every page change: the mark assembles while the page loads, then the page opens through the lens.");
await pause(2200);
await shot("02-dashboard-empty");

// 2 — Project
await nav("Projects");
await pause(900);
await page.getByRole("button", { name: /new project/i }).click();
await page.getByLabel("Name").fill("Vulnerable Shop");
await page.getByLabel("Description").fill("Deliberately vulnerable demo code: Python, JavaScript, PHP and AI services.");
await caption("Create a project — it groups repositories, scans and findings.");
await pause(1000);
await page.getByRole("dialog").getByRole("button", { name: /create/i }).click();
await page.waitForURL(/\/projects\/[0-9a-f-]+$/);
await pause(1500);

// 3 — Scan real code
await uploadScan(`${D}/vulnerable-shop.zip`, "vulnerable-shop");
await caption("Upload code. It is stored, then parsed in a resource-limited sandbox — never executed.");
await pause(1500);
await shot("03-new-scan");
await page.getByRole("button", { name: "Start scan" }).click();
await page.waitForURL(/\/scans\/[0-9a-f-]+$/);
const shopScanUrl = page.url();
await caption("The worker runs: inventory → data-flow SAST → secrets → dependencies → correlation.");
await waitForScan();
await caption("Scan complete: real findings with severity, confidence, security gate and Risk Index.");
await pause(2200);
await shot("04-scan-detail");
await page.mouse.wheel(0, 700);
await pause(1500);
await shot("05-scan-detail-findings");

// 4 — Findings
await nav("Findings");
await caption("Findings: filter by severity, status, source; each row links to its evidence.");
await pause(2000);
await shot("06-findings");
await page.locator("tr.row-link").first().click();
await caption("Why SecureLens detected this: the evidence, and the data flow from source to sink.");
await pause(2500);
await shot("07-finding-detail");
await page.mouse.wheel(0, 650);
await pause(1600);
await shot("08-finding-detail-more");
await page.mouse.wheel(0, 650);
await pause(1400);
await shot("09-finding-detail-fix");

// 5 — Code view
await page.goto(shopScanUrl);
await page.locator('a[href$="/code"]').first().click();
await caption("Code view: every finding marked on its exact line, secrets masked.");
await pause(2800);
await shot("10-code-view");

// 6 — Retest loop
await nav("Scans");
await pause(700);
await uploadScan(`${D}/payments-api-v1.zip`, "payments-api");
await caption("Retest demo: scan version 1 of payments-api…");
await page.getByRole("button", { name: "Start scan" }).click();
await page.waitForURL(/\/scans\/[0-9a-f-]+$/);
await waitForScan();
await nav("Scans");
await pause(700);
await uploadScan(`${D}/payments-api-v2.zip`, "payments-api");
await caption("…then version 2 after fixes. Same repository name, so SecureLens compares the two.");
await page.getByRole("button", { name: "Start scan" }).click();
await page.waitForURL(/\/scans\/[0-9a-f-]+$/);
await waitForScan();
await nav("Retests");
await pause(1200);
await page.locator("tr.row-link").first().click();
await caption("Retest: RESOLVED only when the file was analysed again and the issue is gone; NEW issues are flagged.");
await pause(2800);
await shot("11-retest");

// 7 — Dashboard with data
await nav("Security dashboard");
await caption("Dashboard with real results: open findings by severity, trend, Risk Index, recent scans.");
await pause(2600);
await shot("12-dashboard");

// 8 — HTML report (self-contained, no scripts)
const reportUrl = shopScanUrl.replace(`${BASE}/projects/`, `${BASE}/api/v1/projects/`) + "/report?format=html";
const report = await page.request.get(reportUrl);
const reportPage = await context.newPage();
await reportPage.setContent(await report.text());
await reportPage.waitForTimeout(1200);
await reportPage.screenshot({ path: `${SHOTS}/13-html-report.png` });
await reportPage.mouse.wheel(0, 900);
await reportPage.waitForTimeout(800);
await reportPage.screenshot({ path: `${SHOTS}/14-html-report-findings.png` });
await reportPage.close();

// 9 — Organization and account
await nav("Risk & gate policy");
await caption("Organization policy: which findings fail the gate, and Risk Index weights.");
await pause(2000);
await shot("15-gate-policy");
await nav("Audit log");
await caption("Audit log: every login, scan, triage and policy change.");
await pause(1800);
await shot("16-audit-log");
await nav("System status");
await caption("System status: what is configured and what is not (AI stays off until a provider is set).");
await pause(1800);
await shot("17-system-status");
await nav("How SecureLens decides");
await caption("Methodology: how findings, confidence, gate and Risk Index are decided.");
await pause(1800);
await shot("18-methodology");
await page.getByRole("link", { name: "Olivia Owner" }).click();
await caption("Account: profile, password change, theme and motion preference.");
await pause(1800);
await shot("19-account");
await page.getByRole("button", { name: "Toggle colour theme" }).click();
await nav("Security dashboard");
await caption("Light theme.");
await pause(2000);
await shot("20-dashboard-light");
await caption("That is the platform today. Next: authentication flows, design system, learning platform.");
await pause(2200);

const videoPath = await page.video().path();
const state = await context.storageState();
await context.close();

// Mobile layout
const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, storageState: state });
const m = await mobile.newPage();
await m.goto(shopScanUrl);
await m.waitForTimeout(1800);
await m.screenshot({ path: `${SHOTS}/21-mobile-scan.png` });
await mobile.close();
await browser.close();
renameSync(videoPath, `${OUTDIR}/walkthrough.webm`);
console.log("wrote", `${OUTDIR}/walkthrough.webm`, "and", readdirSync(SHOTS).length, "screenshots");
