const { test, afterEach } = require('node:test');
const assert = require('node:assert');
const { createApp, REQUIRED_SCOPE } = require('../server');

const createSecurityContext = async () => ({ checkLocalScope: (s) => s === REQUIRED_SCOPE });
const AUTH = { Authorization: 'Bearer valid' };

const servers = [];
async function startApp(options) {
  const app = createApp({ createSecurityContext, ...options });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  servers.push(server);
  return `http://127.0.0.1:${server.address().port}`;
}

afterEach(async () => {
  delete process.env.ALLOWED_PATH_PREFIXES;
  while (servers.length) await new Promise((resolve) => servers.pop().close(resolve));
});

test('/health is public and reveals nothing', async () => {
  const res = await fetch(`${await startApp({})}/health`);
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(await res.json(), { status: 'ok' });
});

test('sets security headers', async () => {
  const res = await fetch(`${await startApp({})}/health`);
  assert.ok(res.headers.get('x-content-type-options'));
  assert.ok(res.headers.get('strict-transport-security'));
});

test('path allowlist: only configured prefixes reach the backend', async () => {
  process.env.ALLOWED_PATH_PREFIXES = '/sap/opu/odata/, /sap/bc/';
  const calls = [];
  const base = await startApp({
    sendRequest: async (dest, req) => {
      calls.push(req.url);
      return { status: 200, data: {} };
    }
  });
  const call = (p) => fetch(`${base}/call?path=${encodeURIComponent(p)}`, { headers: AUTH });
  assert.strictEqual((await call('/sap/opu/odata/x')).status, 200);
  assert.strictEqual((await call('/sap/bc/ping')).status, 200);
  assert.strictEqual((await call('/sap/admin/x')).status, 403);
  assert.strictEqual((await call('/')).status, 403);
  assert.deepStrictEqual(calls, ['/sap/opu/odata/x', '/sap/bc/ping']);
});

test('backend calls carry a timeout and a response size limit', async () => {
  let request;
  const base = await startApp({
    sendRequest: async (dest, req) => {
      request = req;
      return { status: 200, data: {} };
    }
  });
  await fetch(`${base}/call?path=/x`, { headers: AUTH });
  assert.ok(request.timeout > 0);
  assert.ok(request.maxContentLength > 0);
});

test('backend errors do not leak internal details', async () => {
  const secret = 'connect ECONNREFUSED 10.0.0.5:44300';
  const base = await startApp({
    sendRequest: async () => {
      throw new Error(secret);
    }
  });
  const res = await fetch(`${base}/call?path=/x`, { headers: AUTH });
  assert.strictEqual(res.status, 502);
  assert.ok(!JSON.stringify(await res.json()).includes('10.0.0.5'));

  const base2 = await startApp({
    sendRequest: async () => {
      throw Object.assign(new Error(secret), { response: { status: 404 } });
    }
  });
  const res2 = await fetch(`${base2}/call?path=/x`, { headers: AUTH });
  assert.strictEqual(res2.status, 404);
  assert.ok(!JSON.stringify(await res2.json()).includes('10.0.0.5'));
});

test('rate limiting returns 429 once the limit is exceeded', async () => {
  const base = await startApp({ rateLimitMax: 3 });
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await fetch(`${base}/`, { headers: AUTH })).status);
  assert.deepStrictEqual(statuses, [200, 200, 200, 429, 429]);
});
