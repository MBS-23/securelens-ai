// Render brand/board/index.html to brand/board/securelens-brand-board.png.
//   node brand/tools/export_board.mjs      (run from securelens-ai/)
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium } from "../../frontend/node_modules/playwright/index.mjs";

const board = join(resolve(dirname(fileURLToPath(import.meta.url)), "..", "board"));
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(join(board, "index.html")).href);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: join(board, "securelens-brand-board.png"), fullPage: true });
} finally {
  await browser.close();
}
console.log("wrote", join(board, "securelens-brand-board.png"));
