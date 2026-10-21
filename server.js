const express = require('express');
const { executeHttpRequest } = require('@sap-cloud-sdk/http-client');

const app = express();
const port = process.env.PORT || 3000;
const DESTINATION_NAME = process.env.DESTINATION_NAME || 'Local_NetWeaver_Test';

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
    const response = await executeHttpRequest(
      { destinationName: DESTINATION_NAME },
      { method: 'GET', url: path }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    console.error(err.message);
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.listen(port, () => console.log(`Listening on port ${port}`));
