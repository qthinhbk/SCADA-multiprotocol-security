param(
    [switch]$WithQoS,
    [switch]$WithQoSDemo
)

# Fix Docker PATH
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

Write-Host "=== Phase 2: Secure SCADA Startup ===" -ForegroundColor Cyan

# Build all images first
Write-Host "`n[Step 1] Building all images..." -ForegroundColor Yellow
if ($WithQoS -or $WithQoSDemo) {
    docker compose -f docker-compose.secure.yaml --profile qos build
}
else {
    docker compose -f docker-compose.secure.yaml build
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed! Exiting." -ForegroundColor Red
    exit 1
}

# Start all containers
Write-Host "`n[Step 2] Starting all containers..." -ForegroundColor Yellow
if ($WithQoSDemo) {
    docker compose -f docker-compose.secure.yaml --profile qos --profile qos-demo up -d
}
elseif ($WithQoS) {
    docker compose -f docker-compose.secure.yaml --profile qos up -d
}
else {
    docker compose -f docker-compose.secure.yaml up -d
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "Start failed! Exiting." -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 5
Write-Host "`n=== Phase 2 Ready ===" -ForegroundColor Green
if ($WithQoSDemo) {
    Write-Host "QoS mode: ENABLED (with qos-flooder demo container)" -ForegroundColor Green
}
elseif ($WithQoS) {
    Write-Host "QoS mode: ENABLED" -ForegroundColor Green
}
else {
    Write-Host "QoS mode: DISABLED (baseline)" -ForegroundColor Yellow
}
docker ps --format "table {{.Names}}\t{{.Status}}"
