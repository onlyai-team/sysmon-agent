# Install or update sysmon-agent. Run from an elevated PowerShell.
#
#   .\scripts\install-windows.ps1                 # first install, prompts for settings
#   .\scripts\install-windows.ps1 -Update         # upgrade in place, keeps the config
#   .\scripts\install-windows.ps1 -AgentArgs @('--endpoint','https://c:4318','--non-interactive')
#
[CmdletBinding()]
param(
    [string] $Prefix = "$env:ProgramData\sysmon-agent",
    [string[]] $AgentArgs = @(),
    [switch] $Update
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run from an elevated PowerShell (Run as Administrator).'
}

$sourceDir = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $Prefix 'venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
$agent = Join-Path $venv 'Scripts\sysmon-agent.exe'
$config = Join-Path $Prefix 'config.json'

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

if ($Update -and -not (Test-Path $config)) {
    throw "No configuration at $config. Run this script without -Update to install."
}

# The agent runs from inside the venv, so its files stay locked until it stops.
Write-Host 'Stopping the agent if it is running'
& sc.exe stop sysmon-agent 2>&1 | Out-Null
& schtasks /End /TN sysmon-agent 2>&1 | Out-Null
Start-Sleep -Seconds 2

if (Test-Path $venvPython) {
    Write-Host "Reusing the virtual environment at $venv"
} else {
    Write-Host "Creating the virtual environment at $venv"
    & $uv venv --python 3.11 $venv
}
& $uv pip install --python $venvPython --reinstall-package sysmon-agent $sourceDir

# A real Windows service needs pywin32. pip installs the package but never runs
# its post-install step, and without that step pywintypes cannot find its DLLs.
function Test-Pywin32 {
    & $venvPython -c "import win32serviceutil, servicemanager" 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

if (-not (Test-Pywin32)) {
    Write-Host 'Installing pywin32'
    & $uv pip install --python $venvPython pywin32
}

$postInstall = Join-Path $venv 'Scripts\pywin32_postinstall.py'
if (Test-Path $postInstall) {
    Write-Host 'Registering pywin32 service support'
    & $venvPython $postInstall -install -quiet
}

if (Test-Pywin32) {
    Write-Host 'pywin32 is ready; installing as a Windows service.'
} else {
    Write-Warning 'pywin32 is still unusable. Reason:'
    & $venvPython -c "import win32serviceutil, servicemanager"
    Write-Warning 'The agent will be installed as a SYSTEM scheduled task instead.'
}

if ($Update) {
    # Keep every stored answer; just re-register and start the new version.
    Write-Host 'Re-registering the service with the existing configuration'
    & $agent install --non-interactive --skip-check
} else {
    & $agent install @AgentArgs
}
$code = $LASTEXITCODE
& $agent --version
& $agent status
exit $code
