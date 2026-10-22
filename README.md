# Basic BTP app using a Destination

Express app on SAP BTP (Cloud Foundry) that calls a remote system via the Destination service using SAP Cloud SDK. All routes are protected with XSUAA (JWT + scope `call-destination`).

## Deploy

1. In the BTP cockpit, create a destination named `Local_NetWeaver_Test` in the subaccount with the target URL and auth (for on-premise, a Cloud Connector must be set up).
2. Create the service instances and push:

```powershell
cf create-service destination lite my-destination-service
cf create-service connectivity lite my-connectivity-service
cf create-service xsuaa application my-xsuaa -c xs-security.json
npm install
cf push
```

3. Set `DESTINATION_NAME` in [manifest.yml](./manifest.yml) if your destination has another name.

If you change [xs-security.json](./xs-security.json) later, run `cf update-service my-xsuaa -c xs-security.json`.

## Security (XSUAA)

Every request needs `Authorization: Bearer <JWT>` and the scope `call-destination`. Missing token returns 401; missing scope returns 403. [xs-security.json](./xs-security.json) defines the scope, the `DestinationCaller` role template and the `Basic_BTP_Destination_Caller` role collection.

### Calling from curl / scripts (client credentials)

Create a service key and fetch a token with [get-token.ps1](./get-token.ps1). The client is granted the scope through `authorities`.

```powershell
cf create-service-key my-xsuaa my-xsuaa-key
$t = ./get-token.ps1
curl.exe -i -H "Authorization: Bearer $t" "https://<app-url>/call?path=/sap/opu/odata/iwfnd/catalogservice;v=2/"
```

Tokens expire (about 12 hours); fetch a new one when you get a 401. Treat the service key as a secret.

### Users (browser)

Assign the role collection `Basic_BTP_Destination_Caller` to users in the BTP cockpit (Security > Role Collections). Browser login needs an approuter in front of the app, which is not included here.

## Usage

`GET /call?path=/your/api/path` calls `<destination URL>/your/api/path`. URL-encode query strings inside `path` (for example `path=%2Fsap%2Fx%3Fsap-client%3D100`). `path` must start with `/`. It is rejected with 400 unless the part before the first `?` matches a strict allowlist grammar: `/` followed by non-empty segments separated by single `/`, using only letters, digits, `- . _ ~ ! $ & ' ( ) * + , ; = : @` and these percent-escapes: `%20 %21 %22 %24 %26 %27 %28 %29 %2A %2B %2C %3A %3D %40`. A segment may not be `.` or `..` (also `..;x`). Everything else is rejected, including `%25`, `%2e`, `%2f`, `%3f`, `%5c`, non-ASCII/UTF-8 escapes, raw spaces, backslashes, `//` and control characters. None of the allowed escapes can decode to a dot, slash, backslash, percent, `?` or `#`, so the result does not depend on how many times a backend decodes. The query string after `?` is passed through unchanged (control characters are rejected). Use `curl.exe -i` to see the HTTP status.

## Guard rails

- **Auth:** XSUAA bearer token plus scope `call-destination` on every route except `GET /health` (used as the CF health check).
- **Path allowlist:** `ALLOWED_PATH_PREFIXES` (comma-separated, set in `manifest.yml`, default `/sap/opu/odata/`) limits which backend paths `/call` can reach; others get 403. Unset means no prefix restriction. Add prefixes there when you need other paths (for example `/sap/bc/`).
- **Path validation:** see Usage; applied before the allowlist.
- **Rate limit:** `RATE_LIMIT_PER_MINUTE` (default 60) per client IP, 429 when exceeded.
- **Backend calls:** 10 s timeout, 5 MB response cap, GET only. Errors return only a generic message or the backend status; details go to the log.
- **Headers:** `helmet` security headers, `X-Powered-By` disabled.
- **Operations:** graceful shutdown on SIGTERM, `npm run audit`, weekly Dependabot updates.

## Code quality

```powershell
npm run lint          # ESLint
npm run format:check  # Prettier check
npm run format        # Prettier auto-fix
npm run check         # lint + format check
```

Config: [eslint.config.js](./eslint.config.js), [.prettierrc](./.prettierrc).

## Local run

Run the unit tests (auth checks with and without a token, no BTP needed) with `npm test`.

The app requires an XSUAA binding at startup. Put the `my-xsuaa` credentials into `VCAP_SERVICES` (or `default-env.json`), then `npm start`.
