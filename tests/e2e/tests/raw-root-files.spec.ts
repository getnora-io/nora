import { test, expect } from '@playwright/test';

test.describe('Raw Storage — root-level files', () => {
  const rootFile = `root-test-${Date.now()}.txt`;
  const rootContent = 'root-level-content';
  const subdirFile = `subdir-test-${Date.now()}`;
  const nestedFile = 'nested.txt';
  const nestedContent = 'nested-content';

  // Basic auth for upload (falls back to no-auth for local dev)
  const authHeader = process.env.NORA_AUTH
    ? { Authorization: `Basic ${Buffer.from(process.env.NORA_AUTH).toString('base64')}` }
    : {};

  test.beforeAll(async ({ request }) => {
    // Upload root-level file (no subdirectory)
    const putRoot = await request.put(`/raw/${rootFile}`, {
      data: rootContent,
      headers: authHeader,
    });
    expect(putRoot.status()).toBe(201);

    // Upload file inside a subdirectory
    const putNested = await request.put(`/raw/${subdirFile}/${nestedFile}`, {
      data: nestedContent,
      headers: authHeader,
    });
    expect(putNested.status()).toBe(201);
  });

  test('root file appears in raw listing', async ({ page }) => {
    await page.goto('/ui/raw');
    await expect(page.locator(`text=${rootFile}`)).toBeVisible();
  });

  test('root file detail page shows the file', async ({ page }) => {
    await page.goto(`/ui/raw/${rootFile}`);
    // The detail page should show the file as a version row
    await expect(page.locator(`text=${rootFile}`).first()).toBeVisible();
    // Should NOT show "No versions found"
    await expect(page.locator('text=No versions found')).not.toBeVisible();
  });

  test('root file install command has no trailing /<file>', async ({ page }) => {
    await page.goto(`/ui/raw/${rootFile}`);
    const codeBlock = page.locator('code').first();
    const text = await codeBlock.textContent();
    expect(text).toContain(`/raw/${rootFile}`);
    expect(text).not.toContain(`/raw/${rootFile}/`);
    expect(text).not.toContain('<file>');
  });

  test('subdirectory group detail page shows nested file', async ({ page }) => {
    await page.goto(`/ui/raw/${subdirFile}`);
    await expect(page.locator(`text=${nestedFile}`)).toBeVisible();
    await expect(page.locator('text=No versions found')).not.toBeVisible();
  });

  test('subdirectory renders as browsable folder with nested file link', async ({ page }) => {
    await page.goto(`/ui/raw/${subdirFile}`);
    // Directory view should show the nested file as a clickable link
    await expect(page.locator(`text=${nestedFile}`)).toBeVisible();
    // Should have breadcrumb back to Raw (in main content, not sidebar)
    await expect(page.getByRole('main').getByRole('link', { name: 'Raw' })).toBeVisible();
  });
});
