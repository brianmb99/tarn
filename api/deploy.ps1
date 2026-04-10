<#
Deploy Tarn API Cloudflare Worker

This script:
1. Applies D1 migrations (idempotent)
2. Installs dependencies
3. Deploys the worker

Secrets needed: JWT_SECRET, BASE_RPC_URL (set via wrangler secret put).

Prerequisites:
1. Cloudflare Account
2. Wrangler CLI installed: npm install -g wrangler
3. Logged into Cloudflare: wrangler login
4. D1 database and KV namespace created (IDs in wrangler.toml)

Usage:
  powershell -ExecutionPolicy Bypass -File tarn-api/deploy.ps1
#>
[CmdletBinding()]
param()

function Write-Info($msg){ Write-Host "[tarn-api-deploy] $msg" -ForegroundColor Cyan }
function Write-Err($msg){ Write-Host "[tarn-api-deploy] ERROR: $msg" -ForegroundColor Red }

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Info "Deploying Tarn API Worker..."
Write-Info "Working directory: $scriptDir"

try {
  $wranglerVersion = wrangler --version 2>&1
  Write-Info "Wrangler found: $wranglerVersion"
} catch {
  Write-Err "Wrangler CLI not found. Install with: npm install -g wrangler"
  exit 1
}

try {
  $whoami = wrangler whoami 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Err "Not logged into Cloudflare. Run: wrangler login"
    exit 1
  }
  Write-Info "Cloudflare authentication: OK"
} catch {
  Write-Err "Failed to check Cloudflare authentication. Run: wrangler login"
  exit 1
}

Write-Info "Applying D1 migrations..."
wrangler d1 migrations apply bookish-api-cache --remote
if ($LASTEXITCODE -ne 0) {
  Write-Err "Migration failed"
  exit 1
}
Write-Info "  [OK] Migrations applied"

Write-Info "Installing dependencies..."
npm install --silent 2>&1 | Out-Null

Write-Info "Deploying worker..."
wrangler deploy

if ($LASTEXITCODE -ne 0) {
  Write-Err "Deployment failed"
  exit 1
}

Write-Info "[OK] Deployment complete!"
Write-Info ""
Write-Info "Worker URL: https://api.tarn.dev"
Write-Info "Test with: node tarn-api/test.mjs https://api.tarn.dev"
