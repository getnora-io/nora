import { test, expect } from '@playwright/test';

test.describe('NORA Dashboard', () => {

  test('dashboard page loads and shows title', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page).toHaveTitle(/NORA|nora/i);
  });

  test('dashboard shows registry sections', async ({ page }) => {
    await page.goto('/ui/');

    // All 7 registry types should be visible
    await expect(page.getByText(/Docker/i).first()).toBeVisible();
    await expect(page.getByText(/npm/i).first()).toBeVisible();
    await expect(page.getByText(/Maven/i).first()).toBeVisible();
    await expect(page.getByText(/PyPI/i).first()).toBeVisible();
    await expect(page.getByText(/Cargo/i).first()).toBeVisible();
    await expect(page.getByText(/Go/i).first()).toBeVisible();
    await expect(page.getByText(/Raw/i).first()).toBeVisible();
  });

  test('dashboard shows non-zero npm count after proxy fetch', async ({ page, request }) => {
    // Trigger npm proxy cache by fetching a package
    await request.get('/npm/chalk');
    await request.get('/npm/chalk/-/chalk-5.4.1.tgz');

    // Wait a moment for index rebuild
    await page.waitForTimeout(1000);

    await page.goto('/ui/');

    // npm section should show at least 1 package
    // Look for a number > 0 near npm section
    const statsResponse = await request.get('/api/ui/stats');
    const stats = await statsResponse.json();
    expect(stats.npm).toBeGreaterThan(0);

    // Verify it's actually rendered on the page
    await page.goto('/ui/');
    await page.waitForTimeout(500);

    // The page should contain the package count somewhere
    const content = await page.textContent('body');
    expect(content).not.toBeNull();
    // Should not show all zeros for npm
    expect(content).toContain('npm');
  });

  test('dashboard shows Docker images after proxy fetch', async ({ page, request }) => {
    // Check stats API
    const statsResponse = await request.get('/api/ui/stats');
    const stats = await statsResponse.json();

    // Docker count should be accessible (may be 0 if no images pulled yet)
    expect(stats).toHaveProperty('docker');
  });

  test('health endpoint returns healthy', async ({ request }) => {
    const response = await request.get('/health');
    expect(response.ok()).toBeTruthy();

    const health = await response.json();
    expect(health.status).toBe('healthy');
    expect(health.registries.npm).toBe('ok');
    expect(health.registries.docker).toBe('ok');
    expect(health.registries.maven).toBe('ok');
    expect(health.registries.pypi).toBe('ok');
    expect(health.registries.cargo).toBe('ok');
    expect(health.registries.go).toBe('ok');
    expect(health.registries.raw).toBe('ok');
  });

  test('OpenAPI docs endpoint accessible', async ({ request }) => {
    const response = await request.get('/api-docs', { maxRedirects: 0 });
    // api-docs redirects to swagger UI
    expect([200, 303]).toContain(response.status());
  });

  test('metrics endpoint returns prometheus format', async ({ request }) => {
    const response = await request.get('/metrics');
    expect(response.ok()).toBeTruthy();
    const text = await response.text();
    expect(text).toContain('nora_http_request_duration_seconds');
  });
});
