// Rasterise the SecureLens SVGs with the dashboard's Playwright Chromium.
//   node brand/tools/export_png.mjs        (run from securelens-ai/)
// Writes brand/png/* and the dashboard's favicon, touch icon and PWA icons.
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "../../frontend/node_modules/playwright/index.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const brand = join(root, "brand");
const pub = join(root, "frontend", "public");
mkdirSync(join(brand, "png"), { recursive: true });

const read = (name) => readFileSync(join(brand, name), "utf8");
// iOS masks touch icons itself, so that export is full-bleed (no rounded corners).
const fullBleed = (svg) => svg.replace(/<rect width="64" height="64" rx="14"/, '<rect width="64" height="64"');

const jobs = [
  { svg: read("securelens-app-icon.svg"), size: [32, 32], out: [join(brand, "png", "securelens-app-icon-32.png"), join(pub, "favicon-32.png")] },
  { svg: fullBleed(read("securelens-app-icon.svg")), size: [180, 180], out: [join(brand, "png", "securelens-app-icon-180.png"), join(pub, "apple-touch-icon.png")] },
  { svg: read("securelens-app-icon.svg"), size: [192, 192], out: [join(pub, "icon-192.png")] },
  { svg: read("securelens-app-icon.svg"), size: [512, 512], out: [join(brand, "png", "securelens-app-icon-512.png"), join(pub, "icon-512.png")] },
  { svg: read("securelens-logo.svg"), width: 1200, background: "#ffffff", out: [join(brand, "png", "securelens-logo-1200.png")] },
  { svg: read("securelens-logo-inverse.svg"), width: 1200, background: "#0b1b36", out: [join(brand, "png", "securelens-logo-inverse-1200.png")] },
];

const browser = await chromium.launch();
try {
  for (const job of jobs) {
    const viewBox = job.svg.match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
    const [vw, vh] = [Number(viewBox[1]), Number(viewBox[2])];
    const [w, h] = job.size ?? [job.width, Math.round((job.width * vh) / vw)];
    const pad = job.background ? Math.round(w * 0.06) : 0;
    const page = await browser.newPage({ viewport: { width: w + 2 * pad, height: h + 2 * pad } });
    const svg = job.svg.replace(/ width="[^"]*" height="[^"]*"/, ` width="${w}" height="${h}"`);
    await page.setContent(
      `<html><body style="margin:0;padding:${pad}px;background:${job.background ?? "transparent"}">${svg}</body></html>`,
    );
    const [first, ...copies] = job.out;
    await page.screenshot({ path: first, omitBackground: !job.background });
    for (const copy of copies) copyFileSync(first, copy);
    await page.close();
  }
} finally {
  await browser.close();
}
copyFileSync(join(brand, "securelens-app-icon.svg"), join(pub, "favicon.svg"));
console.log("exported", jobs.length, "rasters and favicon.svg");
