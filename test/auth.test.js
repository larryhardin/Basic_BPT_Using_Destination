const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { createApp, REQUIRED_SCOPE } = require('../server');

const backendCalls = [];
const sendRequest = async (destination, request) => {
  backendCalls.push({ destination, request });
  return { status: 200, data: { ok: true } };
};

// Fake security context: token "valid" has the scope, "noscope" lacks it, anything else is rejected
const createSecurityContext = async (req, token) => {
  if (token === 'valid') return { checkLocalScope: (s) => s === REQUIRED_SCOPE };
  if (token === 'noscope') return { checkLocalScope: () => false };
  throw new Error('invalid token');
};

let server;
let baseUrl;

before(async () => {
  const app = createApp({ createSecurityContext, sendRequest });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

const get = (path, token) =>
  fetch(baseUrl + path, token ? { headers: { Authorization: `Bearer ${token}` } } : {});

test('rejects request without a token (401)', async () => {
  backendCalls.length = 0;
  const res = await get('/call?path=/sap/x');
  assert.strictEqual(res.status, 401);
  assert.deepStrictEqual(await res.json(), { error: 'Missing bearer token' });
  assert.strictEqual(backendCalls.length, 0);
});

test('rejects a non-bearer Authorization header (401)', async () => {
  const res = await fetch(`${baseUrl}/`, { headers: { Authorization: 'Basic abc' } });
  assert.strictEqual(res.status, 401);
});

test('rejects an invalid token (401)', async () => {
  backendCalls.length = 0;
  const res = await get('/call?path=/sap/x', 'garbage');
  assert.strictEqual(res.status, 401);
  assert.deepStrictEqual(await res.json(), { error: 'Invalid token' });
  assert.strictEqual(backendCalls.length, 0);
});

test('rejects a valid token without the required scope (403)', async () => {
  backendCalls.length = 0;
  const res = await get('/call?path=/sap/x', 'noscope');
  assert.strictEqual(res.status, 403);
  assert.deepStrictEqual(await res.json(), { error: `Missing scope ${REQUIRED_SCOPE}` });
  assert.strictEqual(backendCalls.length, 0);
});

test('allows a valid token with the scope and calls the destination (200)', async () => {
  backendCalls.length = 0;
  const res = await get('/call?path=/sap/x', 'valid');
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(await res.json(), { ok: true });
  assert.strictEqual(backendCalls.length, 1);
  assert.strictEqual(backendCalls[0].request.url, '/sap/x');
});

test('root route is also protected and works with a valid token', async () => {
  assert.strictEqual((await get('/')).status, 401);
  assert.strictEqual((await get('/', 'valid')).status, 200);
});

test('rejects a path that does not start with "/" (400)', async () => {
  const res = await get('/call?path=sap/x', 'valid');
  assert.strictEqual(res.status, 400);
});
