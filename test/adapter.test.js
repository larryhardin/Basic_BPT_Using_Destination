const { test, before, after } = require('node:test');
const assert = require('node:assert');
const xssec = require('@sap/xssec');
const { createApp, createXssecAdapter, hasTraversal } = require('../server');

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

const TRAVERSAL_PATHS = [
  '/a/../b',
  '/..',
  '/a\\..\\b',
  '/a/%2e%2e/b', // fully encoded
  '/a/%2E%2E/b', // upper case
  '/a/.%2e/admin', // mixed encoding
  '/a/%2e./admin',
  '/a/.%2E/admin',
  '/a/%2E./admin',
  '/a/%252e%252e/admin', // double encoded
  '/a/.%252e/admin',
  '/a/%252e./admin',
  '/a/%25252e%25252e/admin', // triple encoded
  '/a/..%2fadmin', // encoded slash after dots
  '/a%2f..%2fadmin',
  '/a/..%5cadmin', // encoded backslash
  '/a/..;/admin', // path parameter after dots
  '/a/%2e%2e;x=1/admin',
  '/a%3F/../admin', // encoded "?" must not hide a later segment
  '/a/%zz/..', // undecodable escape
  '/a/%2e%2e', // trailing
  '/a/.\t./admin', // literal tab inside a parent segment
  '/a/.\n./admin',
  '/a/.\r./admin',
  '/a/\t../admin',
  '/a/.%09./admin', // encoded tab / LF / CR / NUL
  '/a/.%0a./admin',
  '/a/.%0D./admin',
  '/a/.%00./admin',
  '/a/%09%2e%2e/admin',
  '/a/.%2509./admin', // double-encoded control characters
  '/a/.%250a./admin',
  '/a/x%00y', // NUL anywhere
  '/a/%7f',
  '//a/../../admin', // leading slashes
  '/../admin'
];

test('rejects ".." segments in any encoding (400) and does not call the backend', async () => {
  backendCalls.length = 0;
  for (const path of TRAVERSAL_PATHS) {
    const res = await fetch(`${baseUrl}/call?path=${encodeURIComponent(path)}`, {
      headers: { Authorization: 'Bearer valid' }
    });
    assert.strictEqual(res.status, 400, path);
  }
  assert.strictEqual(backendCalls.length, 0);
});

const VALID_PATHS = [
  '/sap/Entity.json',
  '/sap/a..b/c',
  '/sap/.hidden/..config',
  '/sap/odata/Items(%27a%27)',
  '/sap/x?file=../y',
  '/reports/100%25.csv', // literal percent sign
  '/sap/Items(%27100%25%27)',
  '/a/100%25/b',
  '/sap/odata/Items(%27a%2Fb%27)', // encoded slash inside a key
  '/sap/odata/Items?$filter=name eq %27x%27',
  '/'
];

test('allows legitimate paths, including literal percent signs and ".." in the query', async () => {
  for (const path of VALID_PATHS) {
    backendCalls.length = 0;
    const res = await fetch(`${baseUrl}/call?path=${encodeURIComponent(path)}`, {
      headers: { Authorization: 'Bearer valid' }
    });
    assert.strictEqual(res.status, 200, path);
    assert.deepStrictEqual(backendCalls, [path]);
  }
});

test('hasTraversal agrees with the WHATWG URL parser on random paths', () => {
  // Deterministic PRNG so a failure is reproducible
  let seed = 12345;
  const rand = (n) => {
    seed = (seed * 1664525 + 1013904223) % 4294967296;
    return seed % n;
  };
  // prettier-ignore
  const pieces = ['.', '.', '%2e', '%2E', '/', '/', '\\', '%2f', '%5c', '%09', '%0a', '\t', ';', '%25', '2e', 'a', '..', '%00', '?', '%3F'];
  const BASE = 'http://base.invalid/base/';
  const decodeOrNull = (p) => {
    try {
      return decodeURIComponent(p);
    } catch {
      return null;
    }
  };
  // Anything a parser would resolve outside the base, directly or after one decode, must be rejected
  const escapes = (p) =>
    [p, decodeOrNull(p)].some((candidate) => {
      if (candidate === null) return false;
      try {
        const u = new URL(candidate.replace(/^[/\\]+/, ''), BASE);
        return u.host !== 'base.invalid' || !u.pathname.startsWith('/base/');
      } catch {
        return true; // the parser rejects it, so the guard must too
      }
    });
  for (let i = 0; i < 20000; i++) {
    let p = '/';
    for (let j = rand(10) + 1; j > 0; j--) p += pieces[rand(pieces.length)];
    if (escapes(p.split('?')[0])) {
      assert.ok(hasTraversal(p), `should reject ${JSON.stringify(p)}`);
    }
  }
});

test('hasTraversal unit cases from review feedback', () => {
  assert.strictEqual(hasTraversal('/.%2e/admin'), true);
  assert.strictEqual(hasTraversal('/%2e./admin'), true);
  assert.strictEqual(hasTraversal('/.\t./admin'), true);
  assert.strictEqual(hasTraversal('/reports/100%25.csv'), false);
  assert.strictEqual(hasTraversal('/sap/Items(%27100%25%27)'), false);
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
