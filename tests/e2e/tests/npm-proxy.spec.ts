import { test, expect } from '@playwright/test';

test.describe('npm Proxy', () => {

  test('metadata proxy returns rewritten tarball URLs', async ({ request }) => {
    const response = await request.get('/npm/chalk');
    expect(response.ok()).toBeTruthy();

    const metadata = await response.json();
    expect(metadata.name).toBe('chalk');
    expect(metadata.versions).toBeDefined();

    // Tarball URL must point to NORA, not npmjs.org
    const version = metadata.versions['5.4.1'];
    expect(version).toBeDefined();
    expect(version.dist.tarball).not.toContain('registry.npmjs.org');
    expect(version.dist.tarball).toContain('/npm/chalk/-/chalk-5.4.1.tgz');
  });

  test('scoped package @babel/parser works', async ({ request }) => {
    const response = await request.get('/npm/@babel/parser');
    expect(response.ok()).toBeTruthy();

    const metadata = await response.json();
    expect(metadata.name).toBe('@babel/parser');

    // Check tarball URL rewriting for scoped package
    const versions = Object.keys(metadata.versions);
    expect(versions.length).toBeGreaterThan(0);

    const firstVersion = metadata.versions[versions[0]];
    if (firstVersion?.dist?.tarball) {
      expect(firstVersion.dist.tarball).toContain('/npm/@babel/parser/-/');
      expect(firstVersion.dist.tarball).not.toContain('registry.npmjs.org');
    }
  });

  test('tarball download returns gzip data', async ({ request }) => {
    // Ensure metadata is cached first
    await request.get('/npm/chalk');

    const response = await request.get('/npm/chalk/-/chalk-5.4.1.tgz');
    expect(response.ok()).toBeTruthy();
    expect(response.headers()['content-type']).toBe('application/octet-stream');

    const body = await response.body();
    expect(body.length).toBeGreaterThan(100);
    // gzip magic bytes
    expect(body[0]).toBe(0x1f);
    expect(body[1]).toBe(0x8b);
  });

  test('npm publish creates package', async ({ request }) => {
    const pkgName = `e2e-pub-${Date.now()}`;
    const publishBody = {
      name: pkgName,
      versions: {
        '1.0.0': {
          name: pkgName,
          version: '1.0.0',
          dist: {},
        },
      },
      'dist-tags': { latest: '1.0.0' },
      _attachments: {
        [`${pkgName}-1.0.0.tgz`]: {
          data: 'dGVzdA==',
          content_type: 'application/octet-stream',
        },
      },
    };

    const response = await request.put(`/npm/${pkgName}`, {
      data: publishBody,
      headers: { 'Content-Type': 'application/json' },
    });
    expect(response.status()).toBe(201);

    // Verify published package is accessible
    const getResponse = await request.get(`/npm/${pkgName}`);
    expect(getResponse.ok()).toBeTruthy();
    const metadata = await getResponse.json();
    expect(metadata.name).toBe(pkgName);
    expect(metadata.versions['1.0.0']).toBeDefined();
  });

  test('npm publish rejects duplicate version (409)', async ({ request }) => {
    const pkgName = `e2e-dupe-${Date.now()}`;
    const body = {
      name: pkgName,
      versions: { '1.0.0': { name: pkgName, version: '1.0.0', dist: {} } },
      'dist-tags': { latest: '1.0.0' },
      _attachments: { [`${pkgName}-1.0.0.tgz`]: { data: 'dGVzdA==' } },
    };

    await request.put(`/npm/${pkgName}`, {
      data: body,
      headers: { 'Content-Type': 'application/json' },
    });

    // Publish same version again
    const response = await request.put(`/npm/${pkgName}`, {
      data: body,
      headers: { 'Content-Type': 'application/json' },
    });
    expect(response.status()).toBe(409);
  });

  test('npm publish rejects name mismatch (400)', async ({ request }) => {
    const response = await request.put('/npm/legitimate-pkg', {
      data: {
        name: 'evil-pkg',
        versions: { '1.0.0': {} },
        _attachments: { 'a.tgz': { data: 'dGVzdA==' } },
      },
      headers: { 'Content-Type': 'application/json' },
    });
    expect(response.status()).toBe(400);
  });

  test('npm publish rejects path traversal filename (400)', async ({ request }) => {
    const response = await request.put('/npm/safe-pkg', {
      data: {
        name: 'safe-pkg',
        versions: { '1.0.0': {} },
        _attachments: { '../../etc/passwd': { data: 'dGVzdA==' } },
      },
      headers: { 'Content-Type': 'application/json' },
    });
    expect(response.status()).toBe(400);
  });
});
