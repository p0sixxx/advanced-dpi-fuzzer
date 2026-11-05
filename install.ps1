# Installs Advanced DPI Fuzzer for the current Windows user, without administrator rights.
#
#   irm https://raw.githubusercontent.com/p0sixxx/advanced-dpi-fuzzer/main/install.ps1 | iex
#
# Run it again to update. ADF needs only Python 3.11+ and the OpenSSH client; it installs no packages.
# ADF_INSTALL_DIR puts it elsewhere and leaves PATH alone.

$ErrorActionPreference = 'Stop'
$repo = 'p0sixxx/advanced-dpi-fuzzer'
$ref = if ($env:ADF_REF) { $env:ADF_REF } else { 'main' }
$root = if ($env:ADF_INSTALL_DIR) { $env:ADF_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'adf' }
$bin = Join-Path $root 'bin'

function Find-Python {
    # "python" may be the Microsoft Store stub, so each candidate has to prove its version
    foreach ($command in @(@('py', '-3'), @('python'), @('python3'))) {
        $tool = Get-Command $command[0] -ErrorAction SilentlyContinue
        if (-not $tool) { continue }
        $arguments = @($command | Select-Object -Skip 1) + @('-c', 'import sys; assert sys.version_info >= (3, 11); print(sys.executable)')
        try {
            $path = & $tool.Source @arguments 2>$null
            if ($LASTEXITCODE -eq 0 -and $path) { return "$path".Trim() }
        } catch { }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'Python 3.11+ was not found and winget is not available. Install Python from python.org and run this again.'
    }
    Write-Host 'Python 3.11+ was not found.'
    if ((Read-Host 'Install Python 3.12 with winget? (y/n)') -ne 'y') { throw 'Python 3.11+ is required.' }
    winget install --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $python = Find-Python
    if (-not $python) { throw 'Python was installed but cannot be found yet. Open a new window and run this again.' }
}

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Warning 'The OpenSSH client is missing. Add it in Settings > System > Optional features.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("adf-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work 'adf.zip'
    Invoke-WebRequest -UseBasicParsing "https://github.com/$repo/archive/$ref.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $work
    $source = Get-ChildItem -Path $work -Directory | Select-Object -First 1
    $app = Join-Path $root 'app'
    if (Test-Path $app) { Remove-Item -Recurse -Force $app }
    New-Item -ItemType Directory -Force -Path $root, $bin | Out-Null
    Move-Item -Path $source.FullName -Destination $app
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$shim = "@echo off`r`nset `"PYTHONPATH=$app\src`"`r`n`"$python`" -m adf %*`r`n"
[IO.File]::WriteAllText((Join-Path $bin 'adf.cmd'), $shim, [Text.Encoding]::ASCII)

if (-not $env:ADF_INSTALL_DIR) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $bin), 'User')
    }
    $env:Path += ";$bin"
}

Write-Host ''
Write-Host "Installed to $app"
Write-Host 'Start it with: adf'
