# Install sysmon-agent into a dedicated venv under ProgramData and register the
# Windows service. Run from an elevated PowerShell:
#
#   .\scripts\install-windows.ps1
#   .\scripts\install-windows.ps1 -AgentArgs @('--endpoint','https://c:4318','--non-interactive')
#
[CmdletBinding()]
param(
    [string] $Prefix = "$env:ProgramData\sysmon-agent",
    [string[]] $AgentArgs = @()
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run from an elevated PowerShell (Run as Administrator).'
}

$sourceDir = Split-Path -Parent $PSScriptRoot

$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv) {
    foreach ($candidate in @("$env:USERPROFILE\.local\bin\uv.exe", "$env:LOCALAPPDATA\Programs\uv\uv.exe")) {
        if (Test-Path $candidate) { $uv = $candidate; break }
    }
}
if (-not $uv) {
    Write-Error @'
uv was not found. Install it first, then re-run this script:

    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
'@
    exit 1
}
Write-Host "Using uv at $uv"

$venv = Join-Path $Prefix 'venv'
Write-Host "Creating the virtual environment at $venv"
& $uv venv --python 3.11 $venv
& $uv pip install --python (Join-Path $venv 'Scripts\python.exe') $sourceDir

# pip does not run pywin32's post-install step, and without it the service
# host cannot load pywintypes. Harmless to repeat; only a warning if it fails.
$postInstall = Join-Path $venv 'Scripts\pywin32_postinstall.py'
if (Test-Path $postInstall) {
    Write-Host 'Registering pywin32 service support'
    & (Join-Path $venv 'Scripts\python.exe') $postInstall -install -quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'pywin32 post-install failed; the installer will fall back to a scheduled task.'
    }
}

$agent = Join-Path $venv 'Scripts\sysmon-agent.exe'
Write-Host "Running: $agent install $AgentArgs"
& $agent install @AgentArgs
exit $LASTEXITCODE
