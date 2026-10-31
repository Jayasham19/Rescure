<#
.SYNOPSIS
    Automated, idempotent local setup script for ReSecure MVP.
.DESCRIPTION
    Configures Python virtual environment, installs backend dependencies via uv/pip,
    installs frontend dependencies, builds frontend assets, initializes SQLite database
    with test seed fixtures, and sets up environment templates.
.PARAMETER SkipFrontend
    Skip installing frontend dependencies and building assets.
.PARAMETER SkipSeeds
    Skip seeding test fixtures into the SQLite database.
.PARAMETER ForceReinstall
    Force reinstallation of dependencies and recreate virtual environment.
.EXAMPLE
    .\scripts\setup-resecure.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipFrontend,
    [switch]$SkipSeeds,
    [switch]$ForceReinstall
)

$ErrorActionPreference = "Stop"
$rootPath = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $rootPath

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " RESECURE MVP - REPRODUCIBLE LOCAL SETUP & ENVIRONMENT INITIALIZATION" -ForegroundColor Cyan
Write-Host " Tenets: Mathematical Invariance | Non-Destructive Isolation | Air-Gapped Local" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# 1. Prerequisite Validation
# ------------------------------------------------------------------------------
Write-Host "--> [1/6] Validating System Prerequisites..." -ForegroundColor Yellow

# Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Python 3 is required but was not found on PATH. Please install Python 3.11 or 3.13."
    exit 1
}
$pythonVer = & python --version 2>&1
Write-Host "    Found Python: $pythonVer ($($pythonCmd.Source))" -ForegroundColor Green

# Check Node.js
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Error "Node.js is required but was not found on PATH. Please install Node.js 20 or 22."
    exit 1
}
$nodeVer = & node --version 2>&1
Write-Host "    Found Node.js: $nodeVer ($($nodeCmd.Source))" -ForegroundColor Green

# Check uv (optional fast package installer)
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($uvCmd) {
    $uvVer = & uv --version 2>&1
    Write-Host "    Found uv (Accelerated Python Packaging): $uvVer" -ForegroundColor Green
} else {
    Write-Host "    uv not detected; falling back to standard pip." -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 2. Virtual Environment Setup
# ------------------------------------------------------------------------------
Write-Host "`n--> [2/6] Configuring Python Virtual Environment..." -ForegroundColor Yellow
$venvDir = Join-Path $rootPath "resecure\backend\venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if ($ForceReinstall -and (Test-Path $venvDir)) {
    Write-Host "    Removing existing virtual environment at $venvDir..." -ForegroundColor Gray
    Remove-Item -Recurse -Force $venvDir
}

if (-not (Test-Path $venvPython)) {
    Write-Host "    Creating new virtual environment at $venvDir..." -ForegroundColor Gray
    if ($uvCmd) {
        & uv venv "$venvDir" --python python
    } else {
        & python -m venv "$venvDir"
    }
}

if (-not (Test-Path $venvPython)) {
    Write-Host "    Warning: venv python not found, falling back to system python." -ForegroundColor Yellow
    $venvPython = "python"
} else {
    Write-Host "    Virtual environment ready: $venvPython" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 3. Python Backend Dependencies Installation
# ------------------------------------------------------------------------------
Write-Host "`n--> [3/6] Installing Backend Dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $rootPath "resecure\requirements-dev.txt"

if ($uvCmd -and ($venvPython -ne "python")) {
    Write-Host "    Installing dependencies using uv pip..." -ForegroundColor Gray
    & uv pip install --python "$venvPython" -r "$reqFile"
} else {
    Write-Host "    Upgrading pip and installing requirements..." -ForegroundColor Gray
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -r "$reqFile" --quiet
}
Write-Host "    Backend dependencies installed successfully." -ForegroundColor Green

# ------------------------------------------------------------------------------
# 4. Frontend Dependencies & Build Verification
# ------------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Host "`n--> [4/6] Setting Up Frontend Application..." -ForegroundColor Yellow
    $frontendDir = Join-Path $rootPath "resecure\frontend"
    Push-Location $frontendDir

    try {
        if ($ForceReinstall -or (-not (Test-Path "node_modules"))) {
            Write-Host "    Installing npm dependencies..." -ForegroundColor Gray
            npm install --silent
        } else {
            Write-Host "    Node modules already installed." -ForegroundColor Gray
        }

        Write-Host "    Running TypeScript type check and production build..." -ForegroundColor Gray
        npm run build

        if (Test-Path "dist\index.html") {
            Write-Host "    Frontend production build verified (dist/index.html created)." -ForegroundColor Green
        } else {
            Write-Warning "    Frontend build did not create dist/index.html"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`n--> [4/6] Skipping Frontend Setup (-SkipFrontend requested)." -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 5. SQLite Database Schema & Seed Fixtures
# ------------------------------------------------------------------------------
if (-not $SkipSeeds) {
    Write-Host "`n--> [5/6] Initializing Database Schema & Deterministic Seeds..." -ForegroundColor Yellow
    $seedScript = Join-Path $rootPath "resecure\database\seeds.py"
    & $venvPython "$seedScript"
    Write-Host "    Database initialized and seeded." -ForegroundColor Green
} else {
    Write-Host "`n--> [5/6] Skipping Database Seeding (-SkipSeeds requested)." -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 6. Environment File Configuration Templates
# ------------------------------------------------------------------------------
Write-Host "`n--> [6/6] Ensuring Environment Configuration Templates..." -ForegroundColor Yellow

$rootEnv = Join-Path $rootPath ".env"
$rootEnvExample = Join-Path $rootPath ".env.example"
if (-not (Test-Path $rootEnvExample)) {
    $rootEnvExample = Join-Path $rootPath ".env.resecure.example"
}
if (-not (Test-Path $rootEnv) -and (Test-Path $rootEnvExample)) {
    Copy-Item $rootEnvExample $rootEnv
    Write-Host "    Created root .env from $($rootEnvExample | Split-Path -Leaf)" -ForegroundColor Green
} else {
    Write-Host "    Root .env configuration already present." -ForegroundColor Gray
}

$resecureEnv = Join-Path $rootPath "resecure\.env"
$resecureEnvExample = Join-Path $rootPath "resecure\.env.example"
if (-not (Test-Path $resecureEnv) -and (Test-Path $resecureEnvExample)) {
    Copy-Item $resecureEnvExample $resecureEnv
    Write-Host "    Created resecure/.env from resecure/.env.example" -ForegroundColor Green
} else {
    Write-Host "    resecure/.env configuration already present." -ForegroundColor Gray
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " RESECURE SETUP COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host " Ready to launch via: .\scripts\run-resecure.ps1" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
exit 0
