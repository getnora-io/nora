/**
 * Test data seeding helpers for UI contract tests.
 *
 * All seeders are idempotent — they use deterministic names and
 * handle 409/conflict responses gracefully. Patterns follow
 * existing docker-proxy.spec.ts and npm-proxy.spec.ts.
 */

import { APIRequestContext } from '@playwright/test';
import * as crypto from 'crypto';

export interface SeedResult {
  docker: { name: string; tags: string[] };
  npm: { name: string; version: string };
  raw: { path: string };
  maven: { group: string; artifact: string; version: string; path: string };
}

/**
 * Push a Docker image with two tags.
 * Follows the OCI distribution spec: blob upload → config blob → manifest PUT.
 */
export async function seedDocker(
  request: APIRequestContext
): Promise<SeedResult['docker']> {
  const name = 'e2e-ui-docker';
  const tags = ['1.0.0', 'latest'];

  // Push layer blob
  const blobData = 'e2e-ui-test-layer-content';
  const blobDigest =
    'sha256:' + crypto.createHash('sha256').update(blobData).digest('hex');

  await request.post(`/v2/${name}/blobs/uploads/?digest=${blobDigest}`, {
    data: blobData,
    headers: { 'Content-Type': 'application/octet-stream' },
  });

  // Push config blob
  const configData = '{}';
  const configDigest =
    'sha256:' + crypto.createHash('sha256').update(configData).digest('hex');

  await request.post(`/v2/${name}/blobs/uploads/?digest=${configDigest}`, {
    data: configData,
    headers: { 'Content-Type': 'application/octet-stream' },
  });

  // Push manifest for each tag
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

  for (const tag of tags) {
    const resp = await request.put(`/v2/${name}/manifests/${tag}`, {
      data: manifest,
      headers: {
        'Content-Type': 'application/vnd.oci.image.manifest.v1+json',
      },
    });
    // 201 = created, 409 = already exists — both OK
    if (resp.status() !== 201 && resp.status() !== 409) {
      throw new Error(
        `seedDocker: unexpected status ${resp.status()} for tag ${tag}`
      );
    }
  }

  return { name, tags };
}

/**
 * Publish an npm package with metadata.
 * Uses the npm publish endpoint (PUT /npm/{name}).
 */
export async function seedNpm(
  request: APIRequestContext
): Promise<SeedResult['npm']> {
  const name = 'e2e-ui-npm';
  const version = '1.0.0';

  const publishBody = {
    name,
    description: 'E2E UI contract test package',
    versions: {
      [version]: {
        name,
        version,
        description: 'E2E UI contract test package',
        author: 'nora-e2e',
        license: 'MIT',
        dist: {},
      },
    },
    'dist-tags': { latest: version },
    _attachments: {
      [`${name}-${version}.tgz`]: {
        data: 'dGVzdA==', // base64("test")
        content_type: 'application/octet-stream',
      },
    },
  };

  const resp = await request.put(`/npm/${name}`, {
    data: publishBody,
    headers: { 'Content-Type': 'application/json' },
  });

  // 201 = created, 409 = already exists — both OK
  if (resp.status() !== 201 && resp.status() !== 409) {
    throw new Error(`seedNpm: unexpected status ${resp.status()}`);
  }

  return { name, version };
}

/**
 * Upload a raw file.
 */
export async function seedRaw(
  request: APIRequestContext
): Promise<SeedResult['raw']> {
  const path = 'e2e-ui-raw/test.txt';

  const resp = await request.put(`/raw/${path}`, {
    data: 'e2e-ui-raw-test-content',
  });

  // 201 = created, 200 = overwritten, 409 = already exists — all OK
  if (!resp.ok() && resp.status() !== 201 && resp.status() !== 409) {
    throw new Error(`seedRaw: unexpected status ${resp.status()}`);
  }

  return { path };
}

/**
 * Upload a Maven artifact (JAR + POM).
 */
export async function seedMaven(
  request: APIRequestContext
): Promise<SeedResult['maven']> {
  const group = 'com/e2e';
  const artifact = 'ui-test';
  const version = '1.0';
  const basePath = `/maven2/${group}/${artifact}/${version}`;

  // Upload JAR
  const jarResp = await request.put(
    `${basePath}/${artifact}-${version}.jar`,
    { data: 'fake-jar-content' }
  );
  if (jarResp.status() !== 201 && jarResp.status() !== 200 && jarResp.status() !== 409) {
    throw new Error(`seedMaven jar: unexpected status ${jarResp.status()}`);
  }

  // Upload POM
  const pomContent = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.e2e</groupId>
  <artifactId>${artifact}</artifactId>
  <version>${version}</version>
</project>`;

  const pomResp = await request.put(
    `${basePath}/${artifact}-${version}.pom`,
    { data: pomContent }
  );
  if (pomResp.status() !== 201 && pomResp.status() !== 200 && pomResp.status() !== 409) {
    throw new Error(`seedMaven pom: unexpected status ${pomResp.status()}`);
  }

  return { group, artifact, version, path: `${group}/${artifact}` };
}

/**
 * Run all seeders. Returns a combined result object.
 */
export async function seedAll(
  request: APIRequestContext
): Promise<SeedResult> {
  const [docker, npm, raw, maven] = await Promise.all([
    seedDocker(request),
    seedNpm(request),
    seedRaw(request),
    seedMaven(request),
  ]);

  return { docker, npm, raw, maven };
}
