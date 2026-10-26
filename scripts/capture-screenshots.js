/**
 * Captures the BURHAN console in both interface languages for the README.
 * Usage: node scripts/capture-screenshots.js
 * Requires the Vite dev server on http://localhost:5173.
 */
const { chromium } = require('@playwright/test');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ASSETS = path.join(ROOT, 'docs', 'assets');
const URL = process.env.APP_URL || 'http://localhost:5173';

async function setLanguage(page, target) {
  const current = await page.evaluate(() => document.documentElement.lang);
  if (current === target) return current;
  await page.click('button[title="Toggle Language"]');
  await page.waitForFunction(
    (lang) => document.documentElement.lang === lang,
    target,
    { timeout: 5000 }
  );
  return target;
}

async function capture(browser, lang, filename) {
  const context = await browser.newContext({
    viewport: { width: 1680, height: 1050 },
    deviceScaleFactor: 2,
  });
  const page = await context.newPage();
  await page.goto(URL, { waitUntil: 'networkidle', timeout: 45000 });
  await setLanguage(page, lang);
  await page.waitForTimeout(2500); // charts + fonts settle
  const out = path.join(ASSETS, filename);
  await page.screenshot({ path: out, fullPage: false });
  console.log(`[${lang}] saved -> ${out}`);
  await context.close();
}

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  try {
    await capture(browser, 'en', 'burhan-dashboard-en.png');
    await capture(browser, 'ar', 'burhan-dashboard-ar.png');
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error('Screenshot capture failed:', err.message);
  process.exit(1);
});
