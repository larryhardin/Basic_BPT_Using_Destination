const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { executeHttpRequest } = require('@sap-cloud-sdk/http-client');
const { hasTraversal } = require('./pathGuard');

const REQUIRED_SCOPE = 'call-destination';
const DEFAULT_DESTINATION = 'Local_NetWeaver_Test';
const BACKEND_TIMEOUT_MS = 10000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

// xssec expects a raw JWT string in `jwt`; `token` would need a decoded Token instance
function createXssecAdapter(xssec, authService) {
  return (req, jwt) => xssec.createSecurityContext(authService, { req, jwt });
}

// Comma-separated list of allowed path prefixes; empty means no prefix restriction
function parseAllowedPrefixes(value) {
  return (value || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
}

// Dependencies are injectable so the auth checks can be unit tested
function createApp({
  createSecurityContext,
  sendRequest = executeHttpRequest,
  rateLimitMax = Number(process.env.RATE_LIMIT_PER_MINUTE) || 60
} = {}) {
  // Read here, not at import, so values from default-env.json (loaded in start()) are honored
  const destinationName = process.env.DESTINATION_NAME || DEFAULT_DESTINATION;
  const allowedPrefixes = parseAllowedPrefixes(process.env.ALLOWED_PATH_PREFIXES);
  const app = express();
  // Don't advertise the framework via the X-Powered-By header
  app.disable('x-powered-by');
  // Cloud Foundry's router is one proxy hop; needed for correct client IPs in rate limiting
  app.set('trust proxy', 1);
  app.use(helmet());

  // Unauthenticated liveness probe for the Cloud Foundry health check; reveals nothing
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      limit: rateLimitMax,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Too many requests' }
    })
  );

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
    if (allowedPrefixes.length > 0 && !allowedPrefixes.some((p) => path.startsWith(p))) {
      return res.status(403).json({ error: 'path is not in the allowed list' });
    }
    try {
      const response = await sendRequest(
        { destinationName },
        {
          method: 'GET',
          url: path,
          timeout: BACKEND_TIMEOUT_MS,
          maxContentLength: MAX_RESPONSE_BYTES,
          maxBodyLength: MAX_RESPONSE_BYTES
        }
      );
      res.status(response.status).json(response.data);
    } catch (err) {
      // Details stay in the log; the caller only learns the status
      console.error('Backend call failed:', err.message);
      const status = err.response?.status;
      if (status) return res.status(status).json({ error: 'Backend returned an error' });
      res.status(502).json({ error: 'Backend call failed' });
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
  const server = app.listen(port, () => console.log(`Listening on port ${port}`));
  // Cloud Foundry sends SIGTERM on restart/stop: finish in-flight requests, then exit
  process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  });
}

if (require.main === module) {
  start();
}

module.exports = { createApp, createXssecAdapter, REQUIRED_SCOPE };
