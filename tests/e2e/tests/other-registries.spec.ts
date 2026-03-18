import { test, expect } from '@playwright/test';

test.describe('Maven Proxy', () => {
  test('download Maven artifact', async ({ request }) => {
    const response = await request.get(
      '/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.pom'
    );
    expect(response.ok()).toBeTruthy();
    const text = await response.text();
    expect(text).toContain('commons-lang3');
  });

  test('Maven upload works', async ({ request }) => {
    const response = await request.put('/maven2/com/test/smoke/1.0/smoke-1.0.jar', {
      data: 'test-jar-content',
    });
    expect(response.status()).toBe(201);
  });
});

test.describe('PyPI Proxy', () => {
  test('simple index returns HTML', async ({ request }) => {
    const response = await request.get('/simple/');
    expect(response.ok()).toBeTruthy();
    const text = await response.text();
    expect(text).toContain('Simple Index');
  });

  test('package page returns links', async ({ request }) => {
    const response = await request.get('/simple/requests/');
    expect(response.ok()).toBeTruthy();
    const text = await response.text();
    expect(text).toContain('requests');
  });
});

test.describe('Raw Storage', () => {
  test('upload and download file', async ({ request }) => {
    const data = 'raw-e2e-test-content-' + Date.now();

    const putResponse = await request.put('/raw/e2e/test.txt', {
      data: data,
    });
    expect(putResponse.status()).toBe(201);

    const getResponse = await request.get('/raw/e2e/test.txt');
    expect(getResponse.ok()).toBeTruthy();
    const body = await getResponse.text();
    expect(body).toBe(data);
  });
});
