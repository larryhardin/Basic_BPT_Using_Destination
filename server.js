const express = require('express');
const { executeHttpRequest } = require('@sap-cloud-sdk/http-client');

const REQUIRED_SCOPE = 'call-destination';
const DEFAULT_DESTINATION = 'Local_NetWeaver_Test';

// Control characters (NUL, tab, CR, LF, ...) are stripped or ignored by URL parsers and servers,
// which can turn e.g. ".<TAB>." into "..", so they are never allowed.
const hasControlChars = (s) => [...s].some((c) => c.codePointAt(0) <= 0x1f || c === '\u007f');
// Encoded-again dots, slashes, backslashes or control characters ("%252e", "%255c", "%2509", ...)
// only matter to a backend that decodes twice or more; reject them instead of guessing.
const DOUBLE_ENCODED = /%(?:25)+(?:2e|2f|5c|[01][0-9a-f]|7f)/i;
const SENTINEL_BASE = 'http://base.invalid/base/';

const isParentSegment = (segment) => segment.split(';')[0] === '..'; // "..;x" is ".." to some servers

// Returns true if the path could climb out of the destination's URL space. Instead of listing
// encodings, it combines: (1) no control characters, (2) no double-encoded dots/separators,
// and, for both the raw and the once-decoded path (cut at a "?" or "#", which a backend may
// see after decoding): (3) no ".." segment and (4) a resolution with the WHATWG URL parser
// (the same dot-segment rules HTTP clients use) that must stay under the base.
// Decoding happens once only, so literal percent signs ("100%25" -> "100%") stay valid.
function hasTraversal(path) {
  const pathOnly = path.split('?')[0];
  if (hasControlChars(path) || DOUBLE_ENCODED.test(pathOnly)) return true;

  let decoded;
  try {
    decoded = decodeURIComponent(pathOnly);
  } catch {
    return true;
  }
  if (hasControlChars(decoded)) return true;

  return [pathOnly, decoded].some((candidate) => {
    const target = candidate.split(/[?#]/)[0];
    if (target.split(/[/\\]/).some(isParentSegment)) return true;
    try {
      const resolved = new URL(target.replace(/^[/\\]+/, ''), SENTINEL_BASE);
      return resolved.host !== 'base.invalid' || !resolved.pathname.startsWith('/base/');
    } catch {
      return true; // a path the URL parser rejects is not safe to forward
    }
  });
}

// xssec expects a raw JWT string in `jwt`; `token` would need a decoded Token instance
function createXssecAdapter(xssec, authService) {
  return (req, jwt) => xssec.createSecurityContext(authService, { req, jwt });
}

// Dependencies are injectable so the auth checks can be unit tested
function createApp({ createSecurityContext, sendRequest = executeHttpRequest } = {}) {
  // Read here, not at import, so values from default-env.json (loaded in start()) are honored
  const destinationName = process.env.DESTINATION_NAME || DEFAULT_DESTINATION;
  const app = express();
  // Don't advertise the framework via the X-Powered-By header
  app.disable('x-powered-by');

  // Validates the bearer JWT and requires the local scope on every route
  app.use(async (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }
    try {
      const ctx = await createSecurityContext(req, header.slice(7).trim());
      if (!ctx.checkLocalScope(REQUIRED_SCOPE)) {
        return res.status(403).json({ error: `Missing scope ${REQUIRED_SCOPE}` });
      }
      req.securityContext = ctx;
      next();
    } catch (err) {
      console.error('Auth failed:', err.message);
      res.status(401).json({ error: 'Invalid token' });
    }
  });

  app.get('/', (req, res) => {
    res.json({
      message: 'BTP destination demo',
      destination: destinationName,
      usage: '/call?path=/some/path'
    });
  });

  // Calls <destination URL> + path using the BTP Destination service
  app.get('/call', async (req, res) => {
    const path = typeof req.query.path === 'string' ? req.query.path : '/';
    if (!path.startsWith('/')) {
      return res.status(400).json({ error: 'path must start with "/"' });
    }
    // Keep requests inside the destination's URL space
    if (hasTraversal(path)) {
      return res.status(400).json({ error: 'path must not contain ".." segments' });
    }
    try {
      const response = await sendRequest({ destinationName }, { method: 'GET', url: path });
      res.status(response.status).json(response.data);
    } catch (err) {
      console.error(err.message);
      res.status(err.response?.status || 500).json({ error: err.message });
    }
  });

  return app;
}

function start() {
  const xsenv = require('@sap/xsenv');
  // Loads default-env.json (local development) into process.env; no-op if absent
  xsenv.loadEnv();
  const xssec = require('@sap/xssec');
  const { xsuaa } = xsenv.getServices({ xsuaa: { label: 'xsuaa' } });
  const authService = new xssec.XsuaaService(xsuaa);
  const app = createApp({ createSecurityContext: createXssecAdapter(xssec, authService) });
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Listening on port ${port}`));
}

if (require.main === module) {
  start();
}

module.exports = { createApp, createXssecAdapter, hasTraversal, REQUIRED_SCOPE };
