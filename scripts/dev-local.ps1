# FINPAY SOC — run locally on Windows for development / preview.
# Needs: Node.js 22+ and Docker Desktop (running).
#   powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1
# Then open http://localhost:8080 and sign up with the BOOTSTRAP_ADMIN_EMAIL below.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Host "Missing: $cmd. $hint" -ForegroundColor Red; exit 1 }
}
Need node "Install Node.js 22 LTS from https://nodejs.org"
Need docker "Install Docker Desktop from https://www.docker.com/products/docker-desktop and start it"

# 1) PostgreSQL 16 in Docker (data kept in the finpay-db container)
$exists = docker ps -a --filter "name=^finpay-db$" --format "{{.Names}}"
if (-not $exists) {
  Write-Host "Starting PostgreSQL..." -ForegroundColor Cyan
  docker run -d --name finpay-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=soc -p 5432:5432 postgres:16 | Out-Null
} else {
  docker start finpay-db | Out-Null
}
for ($i = 0; $i -lt 40; $i++) {
  docker exec finpay-db pg_isready -U postgres -d soc *> $null
  if ($LASTEXITCODE -eq 0) { break }
  Start-Sleep -Seconds 1
}

# 2) Development settings (a random secret is generated once and kept in .dev-secret)
if (-not (Test-Path .dev-secret)) {
  $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $_.ToString("x2") }) | Set-Content .dev-secret -NoNewline
}
$env:NODE_ENV = "development"
$env:APP_URL = "http://localhost:8080"
$env:APP_SECRET = (Get-Content .dev-secret -Raw).Trim()
$env:DATABASE_URL = "postgres://soc_app:devpassword@localhost:5432/soc"
$env:MIGRATION_DATABASE_URL = "postgres://postgres:postgres@localhost:5432/soc"
$env:SOC_APP_DB_PASSWORD = "devpassword"
$env:BOOTSTRAP_ADMIN_EMAIL = "masudn058@gmail.com"
$env:REQUIRE_MFA = "false"
$env:ALLOW_SIGNUP = "true"

# 3) Install, migrate, demo data
if (-not (Test-Path node_modules)) { Write-Host "Installing packages (first run takes a few minutes)..." -ForegroundColor Cyan; npm install --no-audit --no-fund }
npm run db:migrate
npm run db:seed-demo

# 4) Worker in its own window, web app here
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PWD'; `$env:NODE_ENV='development'; `$env:APP_URL='$env:APP_URL'; `$env:APP_SECRET='$env:APP_SECRET'; `$env:DATABASE_URL='$env:DATABASE_URL'; npm run worker"
Write-Host "`nFINPAY SOC is starting on http://localhost:8080 — sign up with $env:BOOTSTRAP_ADMIN_EMAIL" -ForegroundColor Green
npm run dev
