import { test, expect } from '@playwright/test';

// The Hugging Face proxy is opt-in (NORA_HF_ENABLED=true): against a NORA without it the
// suite is skipped, not failed. Like the other proxy specs, it reaches the live upstream
// (huggingface.co) through NORA.
const repo = 'hf-internal-testing/tiny-random-gpt2';

test.describe.serial('Hugging Face Proxy', () => {
  test.beforeAll(async ({ request }) => {
    const health = await (await request.get('/health')).json();
    test.skip(!('hf' in (health.registries ?? {})), 'hf is not enabled on this NORA');
  });

  test('model info names its commit, and the listing keeps LFS without Xet', async ({
    request,
  }) => {
    const info = await request.get(`/hf/api/models/${repo}/revision/main?blobs=true`);
    expect(info.ok()).toBeTruthy();
    expect((await info.json()).sha).toMatch(/^[0-9a-f]{40}$/);
    const tree = await request.get(`/hf/api/models/${repo}/tree/main`);
    expect(tree.ok()).toBeTruthy();
    const entries = await tree.json();
    expect(entries.some((e: { lfs?: unknown }) => e.lfs)).toBeTruthy();
    expect(JSON.stringify(entries)).not.toContain('xetHash');
  });

  test('a file arrives whole, with its commit and its digest, twice the same', async ({
    request,
  }) => {
    const digests = new Set<string>();
    for (let i = 0; i < 2; i++) {
      const response = await request.get(`/hf/${repo}/resolve/main/model.safetensors`);
      expect(response.ok()).toBeTruthy();
      const headers = response.headers();
      expect(headers['x-repo-commit']).toMatch(/^[0-9a-f]{40}$/);
      expect(headers['x-linked-etag']).toMatch(/^"[0-9a-f]{64}"$/);
      expect(Object.keys(headers).filter((h) => h.startsWith('x-xet-') || h === 'location')).toEqual(
        []
      );
      const hash = await crypto.subtle.digest('SHA-256', await response.body());
      const digest = Buffer.from(hash).toString('hex');
      expect(headers['x-linked-etag']).toBe(`"${digest}"`);
      digests.add(digest);
    }
    expect(digests.size).toBe(1);
  });

  test('a Xet token route is refused', async ({ request }) => {
    const response = await request.get(`/hf/api/models/${repo}/xet-read-token/main`);
    expect(response.status()).toBe(404);
  });

  test('the dashboard lists the format', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page.getByText('Hugging Face').first()).toBeVisible();
  });
});
