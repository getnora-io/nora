/**
 * Visual Regression Tests for NORA Registry UI
 *
 * Uses Playwright's toHaveScreenshot() for pixel-level comparison.
 * Baselines are committed to git — they ARE the visual contract.
 *
 * First run:  npx playwright test ui-screenshots --update-snapshots
 * Later runs: npx playwright test ui-screenshots
 *
 * Tolerance: 1% pixel diff (maxDiffPixelRatio: 0.01)
 * Viewport:  1280x720 (fixed for deterministic screenshots)
 */

import { test, expect } from '@playwright/test';
import { REGISTRIES } from './contracts/registry-contracts';
import { seedAll, SeedResult } from './contracts/seed';

let seed: SeedResult;

test.beforeAll(async ({ request }) => {
  seed = await seedAll(request);
  await new Promise((r) => setTimeout(r, 1500));
});

// Fixed viewport for stable screenshots
test.use({ viewport: { width: 1280, height: 720 } });

// ── Dashboard ──────────────────────────────────────────────────

test('dashboard', async ({ page }) => {
  await page.goto('/ui/');
  // Wait for stats to load
  await page.waitForSelector('#stat-downloads', { state: 'visible' });
  await expect(page).toHaveScreenshot('dashboard.png', {
    maxDiffPixelRatio: 0.01,
  });
});

// ── Registry List Pages ────────────────────────────────────────

for (const reg of REGISTRIES) {
  test(`list: ${reg.slug}`, async ({ page }) => {
    await page.goto(`/ui/${reg.list.slug}`);
    await page.waitForSelector('#repo-table-body', { state: 'attached' });
    // Small delay for any HTMX-driven content to settle
    await page.waitForTimeout(300);
    await expect(page).toHaveScreenshot(`list-${reg.slug}.png`, {
      maxDiffPixelRatio: 0.01,
    });
  });
}

// ── Detail Pages (seeded registries only) ──────────────────────

test('detail: docker', async ({ page }) => {
  await page.goto(`/ui/docker/${seed.docker.name}`);
  await page.waitForSelector('h1', { state: 'visible' });
  await expect(page).toHaveScreenshot('detail-docker.png', {
    maxDiffPixelRatio: 0.01,
  });
});

test('detail: npm', async ({ page }) => {
  await page.goto(`/ui/npm/${seed.npm.name}`);
  await page.waitForSelector('#install-cmd', { state: 'visible' });
  await expect(page).toHaveScreenshot('detail-npm.png', {
    maxDiffPixelRatio: 0.01,
  });
});

test('detail: maven', async ({ page }) => {
  const mavenPath = `${seed.maven.group}/${seed.maven.artifact}/${seed.maven.version}`;
  await page.goto(`/ui/maven/${mavenPath}`);
  await page.waitForSelector('pre', { state: 'visible' });
  await expect(page).toHaveScreenshot('detail-maven.png', {
    maxDiffPixelRatio: 0.01,
  });
});

test('detail: raw', async ({ page }) => {
  const rawGroup = seed.raw.path.split('/')[0];
  await page.goto(`/ui/raw/${rawGroup}`);
  await page.waitForSelector('h1', { state: 'visible' });
  await expect(page).toHaveScreenshot('detail-raw.png', {
    maxDiffPixelRatio: 0.01,
  });
});
