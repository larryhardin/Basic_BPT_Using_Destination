const express = require('express');
const { executeHttpRequest } = require('@sap-cloud-sdk/http-client');

const REQUIRED_SCOPE = 'call-destination';
const DEFAULT_DESTINATION = 'Local_NetWeaver_Test';

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
    const pathOnly = path.split('?')[0];
    if (pathOnly.split(/[/\\]/).some((s) => s === '..' || s.toLowerCase() === '%2e%2e')) {
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

module.exports = { createApp, createXssecAdapter, REQUIRED_SCOPE };
