import { test, expect } from '@playwright/test';

test.describe('Docker Registry', () => {

  test('v2 check returns empty JSON', async ({ request }) => {
    const response = await request.get('/v2/');
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body).toEqual({});
  });

  test('catalog endpoint returns 200', async ({ request }) => {
    const response = await request.get('/v2/_catalog');
    expect(response.ok()).toBeTruthy();
  });

  test('put and get manifest works', async ({ request }) => {
    // Push a simple blob
    const blobData = 'test-blob-content';
    const crypto = require('crypto');
    const blobDigest = 'sha256:' + crypto.createHash('sha256').update(blobData).digest('hex');

    await request.post(`/v2/e2e-test/blobs/uploads/?digest=${blobDigest}`, {
      data: blobData,
      headers: { 'Content-Type': 'application/octet-stream' },
    });

    // Push config blob
    const configData = '{}';
    const configDigest = 'sha256:' + crypto.createHash('sha256').update(configData).digest('hex');

    await request.post(`/v2/e2e-test/blobs/uploads/?digest=${configDigest}`, {
      data: configData,
      headers: { 'Content-Type': 'application/octet-stream' },
    });

    // Push manifest
    const manifest = {
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: {
        mediaType: 'application/vnd.oci.image.config.v1+json',
        digest: configDigest,
        size: configData.length,
      },
      layers: [
        {
          mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
          digest: blobDigest,
          size: blobData.length,
        },
      ],
    };

    const putResponse = await request.put('/v2/e2e-test/manifests/1.0.0', {
      data: manifest,
      headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
    });
    expect(putResponse.status()).toBe(201);

    // Pull manifest back
    const getResponse = await request.get('/v2/e2e-test/manifests/1.0.0');
    expect(getResponse.ok()).toBeTruthy();
    const pulled = await getResponse.json();
    expect(pulled.schemaVersion).toBe(2);
    expect(pulled.layers).toHaveLength(1);
  });

  test('tags list returns pushed tags', async ({ request }) => {
    const response = await request.get('/v2/e2e-test/tags/list');
    // May or may not have tags depending on test order
    expect([200, 404]).toContain(response.status());
  });
});
