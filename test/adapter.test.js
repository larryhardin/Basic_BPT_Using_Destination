const { test, before, after } = require('node:test');
const assert = require('node:assert');
const xssec = require('@sap/xssec');
const { createApp, createXssecAdapter } = require('../server');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const JWT = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'u', scope: [] })}.sig`;
const AUTH = { Authorization: 'Bearer valid' };

// Stub service: records what the real xssec.createSecurityContext hands to the service
function makeStubService() {
  const calls = [];
  return {
    calls,
    createSecurityContext: async (token, config) => {
      calls.push({ token, config });
      return { checkLocalScope: () => true };
    }
  };
}

test('adapter passes the bearer string as jwt (a decoded Token reaches the service)', async () => {
  const service = makeStubService();
  const req = { headers: { authorization: `Bearer ${JWT}` } };
  const ctx = await createXssecAdapter(xssec, service)(req, JWT);
  assert.ok(ctx.checkLocalScope());
  assert.strictEqual(service.calls.length, 1);
  assert.strictEqual(typeof service.calls[0].token, 'object');
  assert.strictEqual(service.calls[0].token.jwt, JWT);
  assert.strictEqual(service.calls[0].config.jwt, JWT);
});

test('adapter does not pass the raw string as a Token (token option unset)', async () => {
  const service = makeStubService();
  await createXssecAdapter(xssec, service)({ headers: {} }, JWT);
  assert.notStrictEqual(typeof service.calls[0].token, 'string');
});

test('adapter rejects when no jwt is available', async () => {
  const service = makeStubService();
  await assert.rejects(createXssecAdapter(xssec, service)({ headers: {} }, undefined));
  assert.strictEqual(service.calls.length, 0);
});

test('destination name is read from the environment when the app is created', async () => {
  const previous = process.env.DESTINATION_NAME;
  const requests = [];
  const sendRequest = async (destination) => {
    requests.push(destination);
    return { status: 200, data: {} };
  };
  const createSecurityContext = async () => ({ checkLocalScope: () => true });

  let server;
  try {
    // Set after the module was imported, as start() does via xsenv.loadEnv()
    process.env.DESTINATION_NAME = 'Env_Loaded_Destination';
    const app = createApp({ createSecurityContext, sendRequest });
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    const root = await (await fetch(`${base}/`, { headers: AUTH })).json();
    assert.strictEqual(root.destination, 'Env_Loaded_Destination');
    await fetch(`${base}/call?path=/x`, { headers: AUTH });
    assert.deepStrictEqual(requests, [{ destinationName: 'Env_Loaded_Destination' }]);
  } finally {
    if (previous === undefined) delete process.env.DESTINATION_NAME;
    else process.env.DESTINATION_NAME = previous;
    if (server) await new Promise((resolve) => server.close(resolve));
  }
});

let server;
let baseUrl;
const backendCalls = [];

before(async () => {
  const app = createApp({
    createSecurityContext: async () => ({ checkLocalScope: () => true }),
    sendRequest: async (destination, request) => {
      backendCalls.push(request.url);
      return { status: 200, data: {} };
    }
  });
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

const callWithPath = (path) =>
  fetch(`${baseUrl}/call?path=${encodeURIComponent(path)}`, { headers: AUTH });

// The exhaustive guard tests live in pathGuard.test.js; these check the route wiring.
test('/call rejects an unsafe path (400) and never reaches the backend', async () => {
  backendCalls.length = 0;
  for (const path of ['/a/../b', '/.%2e/admin', '//attacker.invalid/admin', '/a/.\t./admin']) {
    assert.strictEqual((await callWithPath(path)).status, 400, JSON.stringify(path));
  }
  assert.strictEqual(backendCalls.length, 0);
});

test('/call forwards a safe path unchanged, including query and literal percent', async () => {
  for (const path of [
    '/sap/opu/odata/svc;v=2/Entity.json?$filter=a eq 1',
    '/reports/100%25.csv',
    '/sap/x?file=../y'
  ]) {
    backendCalls.length = 0;
    assert.strictEqual((await callWithPath(path)).status, 200, path);
    assert.deepStrictEqual(backendCalls, [path]);
  }
});
