import { test, expect } from '@playwright/test';

test.describe('Raw Reindex', () => {
  const authHeader = process.env.NORA_AUTH
    ? { Authorization: `Basic ${Buffer.from(process.env.NORA_AUTH).toString('base64')}` }
    : {};

  test('reindex endpoint returns 200', async ({ request }) => {
    const resp = await request.post('/raw/-/reindex');
    expect(resp.status()).toBe(200);
  });

  test('files uploaded via API appear in UI after reindex', async ({ request, page }) => {
    // 1. Upload file via NORA API
    const filename = `reindex-e2e-${Date.now()}`;
    const putResp = await request.put(`/raw/${filename}/data.txt`, {
      data: 'reindex-test',
      headers: authHeader,
    });
    expect(putResp.status()).toBe(201);

    // 2. POST /raw/-/reindex to force index rebuild
    const reindexResp = await request.post('/raw/-/reindex');
    expect(reindexResp.status()).toBe(200);

    // 3. Check API listing contains the new file
    const listResp = await request.get('/api/ui/raw/list');
    expect(listResp.ok()).toBeTruthy();
    const list = await listResp.json();
    const found = list.some((r: any) => r.name === filename);
    expect(found).toBe(true);

    // 4. Check UI shows the file
    await page.goto('/ui/raw');
    await expect(page.locator(`text=${filename}`)).toBeVisible();
  });
});
