# QoS proof-of-concept demo script (Windows PowerShell)
# Usage:
#   .\qos-demo.ps1 -Mode baseline
#   .\qos-demo.ps1 -Mode qos

param(
    [ValidateSet("baseline", "qos")]
    [string]$Mode = "baseline"
)

$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

Write-Host "=== SCADA QoS Demo: $Mode ===" -ForegroundColor Cyan

if ($Mode -eq "baseline") {
    Write-Host "[1/5] Start Phase 2 WITHOUT QoS" -ForegroundColor Yellow
    .\start-phase2.ps1
}
else {
    Write-Host "[1/5] Start Phase 2 WITH QoS + flooder" -ForegroundColor Yellow
    .\start-phase2.ps1 -WithQoSDemo
}

Write-Host "[2/5] Wait services stable (20s)" -ForegroundColor Yellow
Start-Sleep -Seconds 20

Write-Host "[3/5] Start congestion (hping3 flood)" -ForegroundColor Yellow
if ($Mode -eq "baseline") {
    Write-Host "Starting qos-flooder (baseline only uses it as traffic generator)..." -ForegroundColor DarkYellow
    docker compose -f docker-compose.secure.yaml --profile qos-demo up -d qos-flooder | Out-Null
}

$flooderRunning = docker ps --filter "name=^qos-flooder$" --format "{{.Names}}"
if ($flooderRunning -eq "qos-flooder") {
    $hasHping = docker exec qos-flooder sh -lc "command -v hping3 >/dev/null && echo ok"
    if ($hasHping -eq "ok") {
        docker exec qos-flooder sh -lc "pkill -f hping3 >/dev/null 2>&1 || true"
        docker exec qos-flooder sh -lc "hping3 --flood --rand-source -S -p 4840 172.20.40.10 >/tmp/hping_p2.log 2>&1 &"
    }
    else {
        Write-Host "hping3 not available in qos-flooder; cannot generate QoS flood." -ForegroundColor Red
    }
}
else {
    Write-Host "qos-flooder is not running; skipped congestion commands." -ForegroundColor Red
}

Write-Host "[4/5] Open Grafana and capture 2 minutes of metrics:" -ForegroundColor Yellow
Write-Host "  http://localhost:3000" -ForegroundColor Green
Write-Host "  - QoS Traffic Control" -ForegroundColor Green
Write-Host "  - Firewall Security Metrics (Phase 2)" -ForegroundColor Green

Write-Host "[5/5] Stop congestion after capture" -ForegroundColor Yellow
Write-Host "  docker exec qos-flooder sh -lc 'pkill hping3'" -ForegroundColor DarkGray
Write-Host "Done." -ForegroundColor Green
