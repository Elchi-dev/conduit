<#
.SYNOPSIS
Install Conduit's daemon (conduitd) or hub (conduit-hub) on Windows.

.DESCRIPTION
Downloads the binary for this system from the GitHub release, checks it
against the release's SHA256SUMS and refuses to install on a mismatch.
Installs to %LOCALAPPDATA%\Conduit\bin and adds that folder to your PATH.

  irm https://<hub>/install.ps1 | iex
  & ([scriptblock]::Create((irm https://<hub>/install.ps1))) -Service

Docs: docs/install.md.

.PARAMETER Hub
Install the hub (conduit-hub) instead of the daemon.
.PARAMETER Version
Install this release (e.g. v0.1.0) instead of the latest.
.PARAMETER Service
Start the daemon at logon with a scheduled task (daemon only).
.PARAMETER Uninstall
Remove the binary, the PATH entry and the scheduled task; your data stays.
#>
[CmdletBinding()]
param(
    [switch]$Hub,
    [string]$Version = "latest",
    [switch]$Service,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = "Elchi-dev/conduit"
$Name = if ($Hub) { "conduit-hub" } else { "conduitd" }
$BinDir = Join-Path $env:LOCALAPPDATA "Conduit\bin"
$Target = Join-Path $BinDir "$Name.exe"
$TaskName = "Conduit daemon"

if ($Version -ne "latest" -and $Version -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "Versions look like v0.1.0." }
if ($Service -and $Hub) { throw "-Service is for the daemon; run the hub as described in docs/self-hosting." }

function Set-UserPath([string]$dir, [bool]$add) {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($current) { $parts = $current.Split(";") | Where-Object { $_ -and ($_ -ne $dir) } }
    if ($add) { $parts += $dir }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
}

if ($Uninstall) {
    if (-not $Hub -and (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed the scheduled task."
    }
    if (Test-Path $Target) {
        Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item -Force $Target
        Write-Host "Removed $Target."
    } else {
        Write-Host "$Target isn't installed."
    }
    if (-not (Get-ChildItem $BinDir -ErrorAction SilentlyContinue)) { Set-UserPath $BinDir $false }
    Write-Host "Your data was left in place."
    return
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "No release for $($env:PROCESSOR_ARCHITECTURE); build from source (see README.md)." }
}
$asset = "$Name-windows-$arch.exe"
if ($env:CONDUIT_DOWNLOAD_BASE) {
    $base = $env:CONDUIT_DOWNLOAD_BASE.TrimEnd("/")
    if ($base -notmatch '^https://' -and $base -notmatch '^http://(127\.0\.0\.1|localhost)([:/]|$)') {
        throw "CONDUIT_DOWNLOAD_BASE must be an https:// address."
    }
} elseif ($Version -eq "latest") {
    $base = "https://github.com/$Repo/releases/latest/download"
} else {
    $base = "https://github.com/$Repo/releases/download/$Version"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("conduit-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $asset ($Version)..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")

    $want = $null
    foreach ($line in Get-Content (Join-Path $tmp "SHA256SUMS")) {
        $f = $line -split '\s+', 2
        if ($f.Count -eq 2 -and $f[1].TrimStart("*") -eq $asset) { $want = $f[0].ToLower() }
    }
    if (-not $want) { throw "SHA256SUMS has no entry for $asset." }
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($want -ne $got) { throw "Checksum mismatch for $asset (expected $want, got $got); nothing was installed." }
    Write-Host "Checksum OK."

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Move-Item -Force (Join-Path $tmp $asset) $Target
    Write-Host "Installed $Target."
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Set-UserPath $BinDir $true
if (-not (($env:Path -split ";") -contains $BinDir)) { $env:Path = "$env:Path;$BinDir" }

if ($Hub) {
    Write-Host "Configure and run the hub as described in docs/self-hosting (https://github.com/$Repo/tree/main/docs/self-hosting)."
    return
}

$data = Join-Path $env:APPDATA "conduit"
if ($Service) {
    $action = New-ScheduledTaskAction -Execute $Target
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Starts conduitd at logon" -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "conduitd starts at logon (scheduled task '$TaskName')."
    Write-Host ""
    Write-Host "Open http://127.0.0.1:7600 to set it up."
} else {
    Write-Host ""
    Write-Host "Start it with: $Target"
    Write-Host "Then open http://127.0.0.1:7600 to set it up."
}
Write-Host "The first start writes a one-time setup token to:"
Write-Host "  $data\setup-token"
