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

`GET /call?path=/your/api/path` calls `<destination URL>/your/api/path`. URL-encode query strings inside `path` (for example `path=%2Fsap%2Fx%3Fsap-client%3D100`). `path` must start with `/`. It is rejected with 400 if it contains control characters (tab, CR, LF, NUL), double-encoded dots or separators (`%252e`, `%255c`), `..` segments in any encoding (`.%2e`, `%2E%2E`, `..;`), or anything that would resolve outside the destination's URL. Literal percent signs (`%25`) and `..` inside the query string are allowed. Use `curl.exe -i` to see the HTTP status.

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
