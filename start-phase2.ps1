# Fix Docker PATH
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

Write-Host "=== Phase 2: Secure SCADA Startup ===" -ForegroundColor Cyan

# Build all images first
Write-Host "`n[Step 1] Building all images..." -ForegroundColor Yellow
docker compose -f docker-compose.secure.yaml build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed! Exiting." -ForegroundColor Red
    exit 1
}

# Start all containers
Write-Host "`n[Step 2] Starting all containers..." -ForegroundColor Yellow
docker compose -f docker-compose.secure.yaml up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "Start failed! Exiting." -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 5
Write-Host "`n=== Phase 2 Ready ===" -ForegroundColor Green
docker ps --format "table {{.Names}}\t{{.Status}}"
