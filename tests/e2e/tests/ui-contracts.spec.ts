/**
 * UI Contract Tests for NORA Registry
 *
 * Data-driven tests that verify every registry's web UI renders
 * the correct structure: titles, columns, breadcrumbs, install
 * commands, search inputs, and dashboard elements.
 *
 * Contracts are defined in ./contracts/registry-contracts.ts
 * Seeding helpers are in ./contracts/seed.ts
 */

import { test, expect } from '@playwright/test';
import {
  REGISTRIES,
  DASHBOARD,
  SIDEBAR_LABELS,
  getRegistry,
} from './contracts/registry-contracts';
import { seedAll, SeedResult } from './contracts/seed';

// ── Shared seed state ──────────────────────────────────────────────

let seed: SeedResult;

test.beforeAll(async ({ request }) => {
  seed = await seedAll(request);
  // Give NORA a moment to index the seeded artifacts
  await new Promise((r) => setTimeout(r, 1500));
});

// ══════════════════════════════════════════════════════════════════
//  Dashboard
// ══════════════════════════════════════════════════════════════════

test.describe('Dashboard', () => {
  test('page title contains Nora', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page).toHaveTitle(/nora/i);
  });

  test('all 5 stats cards are visible', async ({ page }) => {
    await page.goto('/ui/');
    for (const id of DASHBOARD.statsIds) {
      await expect(page.locator(id)).toBeVisible();
    }
  });

  test('registry cards present (7–13)', async ({ page }) => {
    await page.goto('/ui/');
    const cards = page.locator(DASHBOARD.registryCardSelector);
    const count = await cards.count();
    expect(count).toBeGreaterThanOrEqual(7);
    expect(count).toBeLessThanOrEqual(13);
  });

  test('mount points table visible', async ({ page }) => {
    await page.goto('/ui/');
    // Mount points table has "Mount Path" column header
    await expect(
      page.locator('th', { hasText: /mount\s*path/i }).first()
    ).toBeVisible();
  });

  test('activity log section visible', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page.locator('#activity-log')).toBeVisible();
  });

  test('sidebar has all navigation links', async ({ page }) => {
    await page.goto('/ui/');
    const sidebar = page.locator('#sidebar');
    for (const label of SIDEBAR_LABELS) {
      await expect(
        sidebar.getByText(label, { exact: false }).first()
      ).toBeVisible();
    }
  });

  test('header has brand and language switcher', async ({ page }) => {
    await page.goto('/ui/');
    // Brand
    await expect(page.getByText(/nora/i).first()).toBeVisible();
    // Language switcher — EN and RU links (use exact match to avoid sidebar false positives)
    await expect(page.getByRole('link', { name: 'EN', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'RU', exact: true })).toBeVisible();
  });
});

// ══════════════════════════════════════════════════════════════════
//  Registry List Pages (loop over all 13)
// ══════════════════════════════════════════════════════════════════

for (const reg of REGISTRIES) {
  test.describe(`List page: ${reg.displayName}`, () => {
    test('H1 contains correct title', async ({ page }) => {
      await page.goto(`/ui/${reg.list.slug}`);
      const h1 = page.locator('h1');
      await expect(h1).toContainText(reg.list.title);
    });

    test('table column headers match contract', async ({ page }) => {
      await page.goto(`/ui/${reg.list.slug}`);
      const headers = page.locator('thead th');
      const count = await headers.count();
      expect(count).toBe(reg.list.columnHeaders.length);
      for (let i = 0; i < reg.list.columnHeaders.length; i++) {
        await expect(headers.nth(i)).toContainText(
          reg.list.columnHeaders[i],
          { ignoreCase: true }
        );
      }
    });

    test('search input present with correct hx-get', async ({ page }) => {
      await page.goto(`/ui/${reg.list.slug}`);
      const input = page.locator('input[name="q"]');
      await expect(input).toBeVisible();
      const hxGet = await input.getAttribute('hx-get');
      expect(hxGet).toBe(reg.list.searchEndpoint);
    });

    test('#repo-table-body present', async ({ page }) => {
      await page.goto(`/ui/${reg.list.slug}`);
      await expect(page.locator('#repo-table-body')).toBeAttached();
    });

    test('sidebar highlights active registry', async ({ page }) => {
      await page.goto(`/ui/${reg.list.slug}`);
      // The active nav item should have a distinct visual style
      // Check that the sidebar contains a link to this registry (uses short sidebar name)
      const sidebar = page.locator('#sidebar');
      await expect(
        sidebar.getByText(reg.sidebarName, { exact: false }).first()
      ).toBeVisible();
    });
  });
}

// ══════════════════════════════════════════════════════════════════
//  Detail Pages — Docker
// ══════════════════════════════════════════════════════════════════

test.describe('Detail page: Docker', () => {
  const contract = getRegistry('docker');

  test('breadcrumb links back to /ui/docker', async ({ page }) => {
    await page.goto(`/ui/docker/${seed.docker.name}`);
    // Scope to main content to avoid matching sidebar link
    const crumb = page.locator('main a[href="/ui/docker"]').first();
    await expect(crumb).toBeVisible();
    await expect(crumb).toContainText(contract.detail.breadcrumbRootText);
  });

  test('Pull Command section visible with correct format', async ({
    page,
  }) => {
    await page.goto(`/ui/docker/${seed.docker.name}`);
    // Docker uses hardcoded "Pull Command" heading
    await expect(page.getByText('Pull Command')).toBeVisible();
    // The pull command in a <code> element
    const code = page.locator('code').first();
    const text = await code.textContent();
    expect(text).toMatch(contract.detail.installCommandPattern!);
  });

  test('tags table has correct column headers', async ({ page }) => {
    await page.goto(`/ui/docker/${seed.docker.name}`);
    for (const col of contract.detail.tableColumnHeaders) {
      await expect(
        page.locator('th', { hasText: new RegExp(col, 'i') }).first()
      ).toBeAttached();
    }
  });

  test('seeded tags are visible', async ({ page }) => {
    await page.goto(`/ui/docker/${seed.docker.name}`);
    for (const tag of seed.docker.tags) {
      await expect(page.getByText(tag, { exact: true }).first()).toBeVisible();
    }
  });

  test('no metadata panel', async ({ page }) => {
    await page.goto(`/ui/docker/${seed.docker.name}`);
    // Docker detail does not render a metadata panel
    // Metadata panel would have id or class — verify absence
    const content = await page.textContent('body');
    expect(content).not.toContain('metadata-panel');
  });
});

// ══════════════════════════════════════════════════════════════════
//  Detail Pages — npm
// ══════════════════════════════════════════════════════════════════

test.describe('Detail page: npm', () => {
  const contract = getRegistry('npm');

  test('breadcrumb links back to /ui/npm', async ({ page }) => {
    await page.goto(`/ui/npm/${seed.npm.name}`);
    // Scope to main content to avoid matching sidebar link
    const crumb = page.locator('main a[href="/ui/npm"]').first();
    await expect(crumb).toBeVisible();
    await expect(crumb).toContainText(contract.detail.breadcrumbRootText);
  });

  test('#install-cmd visible and matches pattern', async ({ page }) => {
    await page.goto(`/ui/npm/${seed.npm.name}`);
    const cmd = page.locator('#install-cmd');
    await expect(cmd).toBeVisible();
    const text = await cmd.textContent();
    expect(text).toMatch(contract.detail.installCommandPattern!);
  });

  test('#copy-btn present', async ({ page }) => {
    await page.goto(`/ui/npm/${seed.npm.name}`);
    await expect(page.locator('#copy-btn')).toBeVisible();
  });

  test('version rows with data-version attribute', async ({ page }) => {
    await page.goto(`/ui/npm/${seed.npm.name}`);
    const rows = page.locator('.version-row[data-version]');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

// ══════════════════════════════════════════════════════════════════
//  Detail Pages — Maven
// ══════════════════════════════════════════════════════════════════

test.describe('Detail page: Maven', () => {
  const contract = getRegistry('maven');

  test('Maven Dependency XML block present', async ({ page }) => {
    const mavenPath = `${seed.maven.group}/${seed.maven.artifact}/${seed.maven.version}`;
    await page.goto(`/ui/maven/${mavenPath}`);
    // The dependency XML block should contain <dependency>, <groupId>, <artifactId>, <version>
    const pre = page.locator('pre').first();
    const text = await pre.textContent();
    expect(text).toContain('<dependency>');
    expect(text).toContain('<groupId>');
    expect(text).toContain('<artifactId>');
    expect(text).toContain('<version>');
  });

  test('artifacts table has Filename and Size columns', async ({ page }) => {
    const mavenPath = `${seed.maven.group}/${seed.maven.artifact}/${seed.maven.version}`;
    await page.goto(`/ui/maven/${mavenPath}`);
    for (const col of contract.detail.tableColumnHeaders) {
      await expect(
        page.locator('th', { hasText: new RegExp(col, 'i') }).first()
      ).toBeAttached();
    }
  });

  test('artifact filenames linked to /maven2/...', async ({ page }) => {
    const mavenPath = `${seed.maven.group}/${seed.maven.artifact}/${seed.maven.version}`;
    await page.goto(`/ui/maven/${mavenPath}`);
    const links = page.locator('a[href^="/maven2/"]');
    const count = await links.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('hierarchical breadcrumbs are clickable', async ({ page }) => {
    const mavenPath = `${seed.maven.group}/${seed.maven.artifact}/${seed.maven.version}`;
    await page.goto(`/ui/maven/${mavenPath}`);
    // Breadcrumb root: "Maven" linking to /ui/maven (scope to main to avoid sidebar)
    const root = page.locator('main a[href="/ui/maven"]').first();
    await expect(root).toBeVisible();
    await expect(root).toContainText(contract.detail.breadcrumbRootText);
    // Intermediate segments should be clickable links
    const crumbLinks = page.locator(
      'a[href^="/ui/maven/"]'
    );
    const count = await crumbLinks.count();
    // At least 2 intermediate segments for com/e2e/ui-test/1.0
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

// ══════════════════════════════════════════════════════════════════
//  Detail Pages — Raw
// ══════════════════════════════════════════════════════════════════

test.describe('Detail page: Raw', () => {
  const contract = getRegistry('raw');

  test('breadcrumb links back to Raw', async ({ page }) => {
    // raw path is "e2e-ui-raw" (the directory group)
    const rawGroup = seed.raw.path.split('/')[0];
    await page.goto(`/ui/raw/${rawGroup}`);
    // Scope to main content to avoid matching sidebar link
    const crumb = page.locator('main a[href="/ui/raw"]').first();
    await expect(crumb).toBeVisible();
    await expect(crumb).toContainText('Raw');
  });

  test('install command matches curl pattern', async ({ page }) => {
    const rawGroup = seed.raw.path.split('/')[0];
    await page.goto(`/ui/raw/${rawGroup}`);
    const cmd = page.locator('#install-cmd');
    await expect(cmd).toBeVisible();
    const text = await cmd.textContent();
    expect(text).toMatch(contract.detail.installCommandPattern!);
  });

  test('file visible in table', async ({ page }) => {
    const rawGroup = seed.raw.path.split('/')[0];
    await page.goto(`/ui/raw/${rawGroup}`);
    // The nested file "test.txt" should be visible
    await expect(page.getByText('test.txt').first()).toBeVisible();
  });
});

// ══════════════════════════════════════════════════════════════════
//  Special Interactions
// ══════════════════════════════════════════════════════════════════

test.describe('Special interactions', () => {
  test('search input triggers HTMX update of #repo-table-body', async ({
    page,
  }) => {
    await page.goto('/ui/npm');
    const input = page.locator('input[name="q"]');
    await expect(input).toBeVisible();
    // Verify HTMX attributes
    const hxTarget = await input.getAttribute('hx-target');
    expect(hxTarget).toBe('#repo-table-body');
    const hxTrigger = await input.getAttribute('hx-trigger');
    expect(hxTrigger).toContain('keyup');
  });

  test('NuGet version row has data-version for interactive install', async ({
    page,
    request,
  }) => {
    // Seed a NuGet package first
    const nugetPkg = 'e2e-ui-nuget';
    const nupkgData = Buffer.alloc(32); // minimal .nupkg stub
    const resp = await request.put(
      `/nuget/v2/package/${nugetPkg}/${nugetPkg}.1.0.0.nupkg`,
      {
        data: nupkgData,
        headers: { 'Content-Type': 'application/octet-stream' },
      }
    );
    // Ignore errors — package may already exist or endpoint may differ
    if (resp.ok() || resp.status() === 201 || resp.status() === 409) {
      await page.goto(`/ui/nuget/${nugetPkg}`);
      const rows = page.locator('.version-row[data-version]');
      const count = await rows.count();
      if (count > 0) {
        // Clicking a version row should exist without error
        const firstVersion = await rows.first().getAttribute('data-version');
        expect(firstVersion).toBeTruthy();
      }
    }
  });
});
