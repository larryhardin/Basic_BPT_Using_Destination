const { test } = require('node:test');
const assert = require('node:assert');
const { hasTraversal } = require('../pathGuard');

const UNSAFE = [
  // plain and slash/backslash variants
  '/a/../b',
  '/..',
  '/../admin',
  '/a/%2e%2e',
  '/a\\..\\b',
  '/a/..%5cadmin',
  '/a/..%2fadmin',
  '/a%2f..%2fadmin',
  // mixed and upper-case encoding of the dots
  '/a/%2e%2e/b',
  '/a/%2E%2E/b',
  '/.%2e/admin',
  '/%2e./admin',
  '/a/.%2E/admin',
  '/a/%2E./admin',
  // path parameters
  '/a/..;/admin',
  '/a/%2e%2e;x=1/admin',
  // double, triple and deeper encoding, including encoded hex digits
  '/a/%252e%252e/admin',
  '/a/.%252e/admin',
  '/a/%25252e%25252e/admin',
  '/%25%32%65%25%32%65%25%32%66admin', // reviewer: decodes to /%2e%2e%2fadmin, then /../admin
  '/%25%32%65%25%32%65/admin',
  '/a%252f..%252fadmin',
  `/%${'25'.repeat(3)}2e%${'25'.repeat(3)}2e/x`, // "%25252525..2e" nested 3 deep
  `/%${'25'.repeat(15)}2e%${'25'.repeat(15)}2e/x`, // nesting deeper than the guard follows
  // encoded delimiters must not hide a parent segment (reviewer)
  '/a%3F%2f..%2f..%2fadmin',
  '/a%23%2f..%2f..%2fadmin',
  '/a%253F%252f..%252fadmin',
  '/a%3F/../admin',
  // network-path prefixes (reviewer)
  '//attacker.invalid/admin',
  '/\\attacker.invalid/admin',
  '///x',
  '/ /x', // URL parsers trim the leading space, leaving "/x"
  '/ ../x',
  '/  //attacker.invalid/x',
  '/reports/100%25.csv', // "%25" is outside the grammar
  '/sap/Items(%27100%25%27)',
  '/caf%C3%A9', // non-ASCII escapes are outside the grammar
  '/%E2%82%AC',
  '/a/b c', // raw space
  '/a//b', // empty segment
  '/a/./b',
  '/%2f%2fattacker.invalid/admin',
  '/%5cattacker.invalid/admin',
  '/%252f%252fattacker.invalid/admin',
  // control characters, literal and encoded at any depth (reviewer)
  '/a/.\t./admin',
  '/a/.\n./admin',
  '/a/.\r./admin',
  '/a/\t../admin',
  '/a/.%09./admin',
  '/a/.%0a./admin',
  '/a/.%0D./admin',
  '/a/.%00./admin',
  '/a/%09%2e%2e/admin',
  '/a/.%2509./admin',
  '/a/.%250a./admin',
  '/a/x%00y',
  '/a/%7f',
  // overlong UTF-8 encodings of "." and "/"
  '/a/%c0%ae%c0%ae/b',
  '/a/%c0%af',
  '/a/%e0%80%ae',
  // malformed
  '/a/%zz/..',
  '/a/%ff',
  // invalid UTF-8 run hiding ASCII escapes, in both byte positions (reviewer)
  '/%252e%252e%252f%25ff/admin',
  '/%25ff%252e%252e%252fadmin',
  '/a/100%25AB/b', // "%25AB" could decode to "%AB" and beyond: ambiguous, rejected
  '',
  'a/b',
  'http://attacker.invalid/x'
];

const SAFE = [
  '/',
  '/sap/Entity.json',
  '/sap/a..b/c',
  '/sap/.hidden/..config',
  '/sap/odata/Items(%27a%27)',
  '/sap/odata/Items?$filter=name eq %27x%27',
  '/sap/opu/odata/svc;v=2/Entity.json',
  '/sap/x?file=../y', // ".." in the query string is not part of the path
  '/sap/x?file=%2e%2e%2fy',
  '/%20x',
  '/%20/x',
  '/sap/Items(%27a%27,b=%27c%27)',
  '/sap/x/',
  '/sap/odata/svc;v=2/Entity.json',
  '/sap/a..b/...'
];

test('rejects every known traversal / network-path / control-character form', () => {
  for (const path of UNSAFE) {
    assert.strictEqual(hasTraversal(path), true, `should reject ${JSON.stringify(path)}`);
  }
});

test('accepts legitimate paths, including literal percent signs and encoded delimiters', () => {
  for (const path of SAFE) {
    assert.strictEqual(hasTraversal(path), false, `should accept ${JSON.stringify(path)}`);
  }
});

test('rejects non-string input', () => {
  for (const value of [undefined, null, 42, {}, ['/a']]) {
    assert.strictEqual(hasTraversal(value), true);
  }
});

// ---- Randomized checks against an independent model of a backend ----

// Deterministic PRNG so a failure is reproducible
function prng(seed) {
  let state = seed;
  return (n) => {
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state % n;
  };
}

// Model of a backend that percent-decodes ASCII escapes n times before resolving the path.
// Deliberately written differently from the guard (per escape, not per run).
const decodeAscii = (s) =>
  s.replace(/%([0-7][0-9a-f])/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)));

const BASE = 'http://base.invalid/base/';

function escapesBase(pathname) {
  let level = pathname;
  for (let depth = 0; depth <= 5; depth++) {
    // Real "?"/"#" only end the path in the raw string; once decoded they are plain characters
    const target = (depth === 0 ? level : level.replace(/\?/g, '%3F').replace(/#/g, '%23')).replace(
      /^\//,
      ''
    );
    try {
      const resolved = new URL(target, BASE);
      if (resolved.host !== 'base.invalid' || !resolved.pathname.startsWith('/base/')) return true;
    } catch {
      return true;
    }
    level = decodeAscii(level);
  }
  return false;
}

test('a path accepted by the guard never escapes under any decoding depth (randomized)', () => {
  // prettier-ignore
  const pieces = ['.', '.', '..', '%2e', '%2E', '%252e', '%25%32%65', '%25%32%66', '/', '/', '\\', '%2f', '%252f',
    '%5c', '%255c', '%09', '%0a', '\t', '%00', ';', '%25', '%3F', '%23', '?', '#', 'a', '2', 'e', 'f', '%',
    '%zz', '%c0%ae', ' ', '%2525', '%25%32%35'];
  for (const seed of [1, 12345, 987654321, 424242]) {
    const rand = prng(seed);
    for (let i = 0; i < 40000; i++) {
      let path = '/';
      for (let j = rand(12) + 1; j > 0; j--) path += pieces[rand(pieces.length)];
      const pathname = path.split(/[?#]/)[0];
      if (escapesBase(pathname)) {
        assert.strictEqual(hasTraversal(path), true, `should reject ${JSON.stringify(path)}`);
      }
    }
  }
});

test('benign paths are never rejected (randomized, guards against over-blocking)', () => {
  const pieces = ['a', 'b', 'x', 'y', '_', '-', '7', '%27', 'q%20q', '(', ')', '=', '100_', '(a)'];
  const rand = prng(2024);
  for (let i = 0; i < 20000; i++) {
    let path = '';
    for (let s = rand(5) + 1; s > 0; s--) {
      let segment = '';
      for (let j = rand(4) + 1; j > 0; j--) {
        segment += pieces[rand(pieces.length)];
      }
      path += `/${segment}`;
    }
    assert.strictEqual(hasTraversal(path), false, `should accept ${JSON.stringify(path)}`);
  }
});
