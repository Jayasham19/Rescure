<#
.SYNOPSIS
    Concurrent runner script for ReSecure FastAPI Backend and React Frontend.
.DESCRIPTION
    Starts the FastAPI backend on port 8000 and the Vite React frontend on port 3000 concurrently,
    logs accessible service URLs, and provides graceful shutdown on termination.
.PARAMETER HostAddress
    Interface to bind services (default: 127.0.0.1).
.PARAMETER BackendPort
    Port for the FastAPI backend (default: 8000).
.PARAMETER FrontendPort
    Port for the frontend application (default: 3000).
.PARAMETER ProductionPreview
    Run frontend in production preview mode rather than Vite development server.
.EXAMPLE
    .\scripts\run-resecure.ps1
#>
[CmdletBinding()]
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 3000,
    [switch]$ProductionPreview
)

$ErrorActionPreference = "Stop"
$rootPath = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $rootPath

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " RESECURE MVP - CONCURRENT SERVICE LAUNCHER" -ForegroundColor Cyan
Write-Host " Tenets: Mathematical Invariance | Non-Destructive Isolation | Air-Gapped Local" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Resolve Python Executable
$venvPython = Join-Path $rootPath "resecure\backend\venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonExe = $venvPython
    Write-Host "Using virtual environment Python: $pythonExe" -ForegroundColor Gray
} else {
    $pythonExe = "python"
    Write-Host "Using system Python: $pythonExe" -ForegroundColor Gray
}

# 2. Check Port Availability
$busyPorts = @()
foreach ($p in @($BackendPort, $FrontendPort)) {
    $conn = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $busyPorts += $p
    }
}
if ($busyPorts.Count -gt 0) {
    Write-Error "Cannot start ReSecure: Port(s) $($busyPorts -join ', ') are already in use. Please free the ports or specify alternative ports."
    exit 1
}

# 3. Start Backend Process
Write-Host "Starting ReSecure FastAPI Backend on http://${HostAddress}:${BackendPort}..." -ForegroundColor Yellow
$backendArgs = @(
    "-m", "uvicorn",
    "resecure.backend.src.api.app:app",
    "--host", $HostAddress,
    "--port", "$BackendPort"
)
$backendProc = Start-Process -FilePath $pythonExe `
    -ArgumentList $backendArgs `
    -WorkingDirectory $rootPath `
    -PassThru

# 4. Start Frontend Process
$frontendDir = Join-Path $rootPath "resecure\frontend"
$npmScript = if ($ProductionPreview) { "preview" } else { "dev" }
Write-Host "Starting ReSecure Frontend ($npmScript mode) on http://localhost:${FrontendPort}..." -ForegroundColor Yellow

$frontendArgs = @(
    "run", $npmScript,
    "--",
    "--host",
    "--port", "$FrontendPort"
)

$npmCmd = "npm.cmd"
$frontendProc = Start-Process -FilePath $npmCmd `
    -ArgumentList $frontendArgs `
    -WorkingDirectory $frontendDir `
    -PassThru

# Give processes a brief moment to initialize
Start-Sleep -Seconds 2

# Verify processes are still running
if ($backendProc.HasExited) {
    Write-Error "Backend failed to start. Exit code: $($backendProc.ExitCode)"
    exit 1
}
if ($frontendProc.HasExited) {
    Write-Error "Frontend failed to start. Exit code: $($frontendProc.ExitCode)"
    Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " RESECURE SERVICES ONLINE & OPERATIONAL" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  [Backend API]      http://${HostAddress}:${BackendPort}" -ForegroundColor Green
Write-Host "  [API Interactive]  http://${HostAddress}:${BackendPort}/docs" -ForegroundColor Green
Write-Host "  [Health Endpoint]  http://${HostAddress}:${BackendPort}/api/health" -ForegroundColor Green
Write-Host "  [Frontend Web UI]  http://localhost:${FrontendPort}" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to terminate both servers gracefully." -ForegroundColor Yellow
Write-Host ""

try {
    # Keep script open and monitor process health
    while (-not $backendProc.HasExited -and -not $frontendProc.HasExited) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "`nGracefully terminating ReSecure processes..." -ForegroundColor Yellow

    if ($backendProc -and -not $backendProc.HasExited) {
        Write-Host "  Stopping Backend (PID $($backendProc.Id))..." -ForegroundColor Gray
        & taskkill /PID $backendProc.Id /T /F 2>&1 | Out-Null
    }

    if ($frontendProc -and -not $frontendProc.HasExited) {
        Write-Host "  Stopping Frontend (PID $($frontendProc.Id))..." -ForegroundColor Gray
        & taskkill /PID $frontendProc.Id /T /F 2>&1 | Out-Null
    }

    Write-Host "ReSecure services terminated cleanly." -ForegroundColor Green
}
