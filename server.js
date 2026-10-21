const express = require('express');
const { executeHttpRequest } = require('@sap-cloud-sdk/http-client');

const DESTINATION_NAME = process.env.DESTINATION_NAME || 'Local_NetWeaver_Test';
const REQUIRED_SCOPE = 'call-destination';

// Dependencies are injectable so the auth checks can be unit tested
function createApp({ createSecurityContext, sendRequest = executeHttpRequest } = {}) {
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
      destination: DESTINATION_NAME,
      usage: '/call?path=/some/path'
    });
  });

  // Calls <destination URL> + path using the BTP Destination service
  app.get('/call', async (req, res) => {
    const path = typeof req.query.path === 'string' ? req.query.path : '/';
    if (!path.startsWith('/')) {
      return res.status(400).json({ error: 'path must start with "/"' });
    }
    try {
      const response = await sendRequest(
        { destinationName: DESTINATION_NAME },
        { method: 'GET', url: path }
      );
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
  const xssec = require('@sap/xssec');
  const { xsuaa } = xsenv.getServices({ xsuaa: { label: 'xsuaa' } });
  const authService = new xssec.XsuaaService(xsuaa);
  const app = createApp({
    createSecurityContext: (req, token) => xssec.createSecurityContext(authService, { req, token })
  });
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Listening on port ${port}`));
}

if (require.main === module) {
  start();
}

module.exports = { createApp, REQUIRED_SCOPE };
