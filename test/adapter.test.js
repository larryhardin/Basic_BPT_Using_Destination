const { test, before, after } = require('node:test');
const assert = require('node:assert');
const xssec = require('@sap/xssec');
const { createApp, createXssecAdapter } = require('../server');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const JWT = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ sub: 'u', scope: [] })}.sig`;

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
    const headers = { Authorization: 'Bearer valid' };
    const root = await (await fetch(`${base}/`, { headers })).json();
    assert.strictEqual(root.destination, 'Env_Loaded_Destination');
    await fetch(`${base}/call?path=/x`, { headers });
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

test('rejects paths with ".." segments (400) and does not call the backend', async () => {
  backendCalls.length = 0;
  for (const path of ['/a/../b', '/..', '/a/..%2Fb'.replace('%2F', '/'), '/a\\..\\b']) {
    const res = await fetch(`${baseUrl}/call?path=${encodeURIComponent(path)}`, {
      headers: { Authorization: 'Bearer valid' }
    });
    assert.strictEqual(res.status, 400, path);
  }
  assert.strictEqual(backendCalls.length, 0);
});

test('allows normal paths including dots in names', async () => {
  backendCalls.length = 0;
  const path = '/sap/opu/odata/svc;v=2/Entity.json?$filter=a eq 1';
  const res = await fetch(`${baseUrl}/call?path=${encodeURIComponent(path)}`, {
    headers: { Authorization: 'Bearer valid' }
  });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(backendCalls, [path]);
});
