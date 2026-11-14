import { test, expect } from '@playwright/test';
import * as crypto from 'crypto';

// Composer is opt-in (NORA_COMPOSER_ENABLED=true): against a NORA without it the suite is
// skipped, not failed. It publishes a package of its own and reads it back, so it reaches no
// upstream.
const name = 'nora-e2e/greeter';
const versions = ['1.0.0', '1.1.0'];
const detailPath = `/ui/composer/${name}`;

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// A zip of stored (uncompressed) members: the upload reads only composer.json out of it.
function zip(members: Record<string, string>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [member, text] of Object.entries(members)) {
    const path = Buffer.from(member);
    const body = Buffer.from(text);
    const crc = crc32(body);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x21, 12); // date: 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18); // compressed
    local.writeUInt32LE(body.length, 22); // uncompressed
    local.writeUInt16LE(path.length, 26);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0x21, 14); // date: 1980-01-01
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20); // compressed
    central.writeUInt32LE(body.length, 24); // uncompressed
    central.writeUInt16LE(path.length, 28);
    central.writeUInt32LE(offset, 42);

    locals.push(local, path, body);
    centrals.push(central, path);
    offset += local.length + path.length + body.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centrals.length / 2, 8);
  end.writeUInt16LE(centrals.length / 2, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

const archive = zip({
  'composer.json': JSON.stringify({ name, description: 'NORA e2e package', type: 'library' }),
  'src/Greeter.php': '<?php\nclass Greeter {}\n',
});

test.describe.serial('Composer', () => {
  test.beforeAll(async ({ request }) => {
    const health = await (await request.get('/health')).json();
    test.skip(!('composer' in (health.registries ?? {})), 'composer is not enabled on this NORA');

    for (const version of versions) {
      const response = await request.put(`/composer/packages/upload/${name}/${version}`, {
        data: archive,
      });
      // 201 = created, 409 = uploaded by an earlier run: both leave the version in place
      expect([201, 409]).toContain(response.status());
    }
  });

  test('the repository root points Composer at NORA', async ({ request }) => {
    const response = await request.get('/composer/packages.json');
    expect(response.ok()).toBeTruthy();
    const root = await response.json();
    expect(root['metadata-url']).toMatch(/\/composer\/p2\/%package%\.json$/);
    expect(root['security-advisories']['api-url']).toMatch(
      /\/composer\/api\/security-advisories\/$/
    );
  });

  test('the metadata lists each uploaded version with a NORA download URL', async ({
    request,
  }) => {
    const response = await request.get(`/composer/p2/${name}.json`);
    expect(response.ok()).toBeTruthy();
    const listed: { version: string; dist: { type: string; url: string } }[] = (
      await response.json()
    ).packages[name];
    for (const version of versions) {
      const entry = listed.find((v) => v.version === version);
      expect(entry, `version ${version} is listed`).toBeTruthy();
      expect(entry!.dist.type).toBe('zip');
      expect(new URL(entry!.dist.url).pathname).toContain(`/composer/dists/${name}/`);
    }
  });

  test('the archive downloads whole and by range, with the sha1 the metadata names', async ({
    request,
  }) => {
    const metadata = await (await request.get(`/composer/p2/${name}.json`)).json();
    const dist = metadata.packages[name].find(
      (v: { version: string }) => v.version === versions[0]
    ).dist;
    const path = new URL(dist.url).pathname;

    const whole = await request.get(path);
    expect(whole.ok()).toBeTruthy();
    const body = await whole.body();
    expect(body.equals(archive)).toBeTruthy();
    expect(crypto.createHash('sha1').update(body).digest('hex')).toBe(dist.shasum);

    const part = await request.get(path, { headers: { Range: 'bytes=0-3' } });
    expect(part.status()).toBe(206);
    expect((await part.body()).equals(archive.subarray(0, 4))).toBeTruthy();
  });

  test('a published version is immutable', async ({ request }) => {
    const response = await request.put(`/composer/packages/upload/${name}/${versions[0]}`, {
      data: archive,
    });
    expect(response.status()).toBe(409);
  });

  test('an archive that is not the package is refused', async ({ request }) => {
    const response = await request.put(`/composer/packages/upload/${name}/2.0.0`, {
      data: zip({ 'composer.json': JSON.stringify({ name: 'nora-e2e/other' }) }),
    });
    expect(response.status()).toBe(400);
  });

  test('the list page links the package once it is indexed', async ({ request, page }) => {
    await expect
      .poll(
        async () => {
          const response = await request.get('/ui/composer');
          return response.text();
        },
        { timeout: 5000 }
      )
      .toContain('nora-e2e%2Fgreeter');

    await page.goto('/ui/composer');
    await expect(page.locator('h1')).toContainText('Composer (PHP)');
    await expect(page.locator('main tbody tr', { hasText: name })).toHaveCount(1);

    // The columns and the search every flat registry list has
    const headers = page.locator('thead th');
    await expect(headers).toHaveCount(4);
    for (const [i, header] of ['Name', 'Versions', 'Size', 'Updated'].entries()) {
      await expect(headers.nth(i)).toContainText(header, { ignoreCase: true });
    }
    await expect(page.locator('input[name="q"]')).toHaveAttribute(
      'hx-get',
      '/api/ui/composer/search'
    );
  });

  test('the package page lists its versions as hosted, with the composer command', async ({
    page,
  }) => {
    await page.goto(detailPath);

    await expect(page.locator('h1')).toHaveText(name);
    await expect(page.locator('main a[href="/ui/composer"]').first()).toContainText(
      'Composer (PHP)'
    );
    for (const version of versions) {
      const row = page.locator(`.version-row[data-version="${version}"]`);
      await expect(row).toHaveCount(1);
      await expect(row).toContainText('hosted');
    }
    await expect(page.locator('#install-cmd')).toHaveText(`composer require ${name}`);
  });

  test('the dashboard lists the format', async ({ page }) => {
    await page.goto('/ui/');
    await expect(page.getByText('Composer').first()).toBeVisible();
  });
});
