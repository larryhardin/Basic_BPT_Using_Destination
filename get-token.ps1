# Prints an OAuth client-credentials token for the my-xsuaa-key service key
param([string]$ServiceKey = 'my-xsuaa-key', [string]$Instance = 'my-xsuaa')

$raw = (cf service-key $Instance $ServiceKey) | Select-Object -Skip 2 | Out-String
$c = ($raw | ConvertFrom-Json).credentials
if (-not $c) { $c = $raw | ConvertFrom-Json }

$resp = Invoke-RestMethod -Method Post -Uri "$($c.url)/oauth/token" `
  -Body @{ grant_type = 'client_credentials'; client_id = $c.clientid; client_secret = $c.clientsecret }
$resp.access_token
