# Basic BTP app using a Destination

Express app on SAP BTP (Cloud Foundry) that calls a remote system via the Destination service using SAP Cloud SDK.

## Deploy

1. In the BTP cockpit, create a destination named `Local_NetWeaver_Test` in the subaccount with the target URL and auth.
2. Create the service instance and push:

```powershell
cf create-service destination lite my-destination-service
npm install
cf push
```

3. Set `DESTINATION_NAME` in [manifest.yml](./manifest.yml) if your destination has another name.
4. Open `https://<app-url>/call?path=/your/api/path`.

## Code quality

```powershell
npm run lint          # ESLint
npm run format:check  # Prettier check
npm run format        # Prettier auto-fix
npm run check         # lint + format check
```

Config: [eslint.config.js](./eslint.config.js), [.prettierrc](./.prettierrc).

## Local run

Bind to the service locally (`cf create-service-key` and put the credentials in `VCAP_SERVICES` / `default-env.json`), then `npm start`.
