# Native Windows installer. No Bash, WSL, or environment activation required.
param(
    [switch]$Verbose,
    [switch]$Lab,
    [switch]$Reinstall,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output 'Usage: .\install.ps1 [-Verbose] [-Lab] [-Reinstall]'
    Write-Output 'Requires Python >= 3.10. ANTICELLS_RED_MCP_PYTHON selects an interpreter.'
    exit 0
}

$probe = 'import sys; sys.exit(10) if sys.version_info < (3, 10) else print(getattr(sys, ''_base_executable'', sys.executable))'
if ($env:ANTICELLS_RED_MCP_PYTHON) {
    $candidates = @(@{ Command = $env:ANTICELLS_RED_MCP_PYTHON; Prefix = @() })
} else {
    $candidates = @(
        @{ Command = (Join-Path $PSScriptRoot '.venv/Scripts/python.exe'); Prefix = @() },
        @{ Command = 'py'; Prefix = @('-3') },
        @{ Command = 'python3'; Prefix = @() },
        @{ Command = 'python'; Prefix = @() }
    )
}

$python = $null
foreach ($candidate in $candidates) {
    if (-not (Get-Command $candidate.Command -ErrorAction SilentlyContinue)) { continue }
    try {
        $prefix = $candidate.Prefix
        $result = & $candidate.Command @prefix -c $probe 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) {
            $python = [string]($result | Select-Object -Last 1)
            break
        }
    } catch { continue }
}
if (-not $python) {
    [Console]::Error.WriteLine('[FAIL] No Python >= 3.10 found. Install one or set ANTICELLS_RED_MCP_PYTHON.')
    exit 10
}

$installerArgs = @()
if ($Verbose) { $installerArgs += '--verbose' }
if ($Lab) { $installerArgs += '--lab' }
if ($Reinstall) { $installerArgs += '--reinstall' }
& $python (Join-Path $PSScriptRoot 'scripts/install.py') @installerArgs
exit $LASTEXITCODE
