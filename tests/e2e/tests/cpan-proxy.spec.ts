import { test, expect } from '@playwright/test';

const authorPath = 'H/HI/HIDEAKIO';
const distribution = 'Module-Build-XSUtil';
const versions = ['0.18', '0.19'];
const detailPath = `/ui/cpan/${authorPath}/${distribution}`;

test.describe.serial('CPAN Proxy', () => {
  test.beforeAll(async ({ request }) => {
    for (const version of versions) {
      const response = await request.get(
        `/cpan/authors/id/${authorPath}/${distribution}-${version}.tar.gz`
      );

      expect(response.ok()).toBeTruthy();
      expect(response.headers()['content-type']).toBe(
        'application/octet-stream'
      );

      const body = await response.body();
      expect(body.length).toBeGreaterThan(100);
      expect(body[0]).toBe(0x1f);
      expect(body[1]).toBe(0x8b);
    }

    await expect
      .poll(
        async () => {
          const response = await request.get(`/ui/cpan/${authorPath}`);
          return response.text();
        },
        { timeout: 5000 }
      )
      .toContain(detailPath);
  });

  test('author page groups cached releases into one distribution', async ({
    page,
  }) => {
    await page.goto(`/ui/cpan/${authorPath}`);

    const distributionLinks = page.locator(
      `main a[href="${detailPath}"]`
    );
    await expect(distributionLinks).toHaveCount(1);
    await expect(distributionLinks).toHaveText(distribution);

    const row = page.locator('main tbody tr', { hasText: distribution });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('2');
  });

  test('distribution page shows all versions and the cpanm command', async ({
    page,
  }) => {
    await page.goto(detailPath);

    await expect(page.locator('h1')).toContainText(distribution);
    for (const version of versions) {
      await expect(
        page.locator(`.version-row[data-version="${version}"]`)
      ).toHaveCount(1);
    }

    await expect(page.locator('#install-cmd')).toHaveText(
      /^cpanm --from https?:\/\/.+\/cpan Module::Build::XSUtil$/
    );
  });

  test('archive-shaped UI URL redirects to the distribution page', async ({
    page,
  }) => {
    await page.goto(
      `/ui/cpan/${authorPath}/${distribution}-${versions[1]}.tar.gz`
    );

    await expect(page).toHaveURL(new RegExp(`${detailPath}$`));
  });
});
