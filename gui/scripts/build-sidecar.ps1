$ErrorActionPreference = "Stop"

function Get-HostTargetTriple {
  $hostLine = (& rustc -vV) `
    | ForEach-Object { $_.Trim() } `
    | Where-Object { $_.StartsWith("host:") } `
    | Select-Object -First 1
  if (-not $hostLine) {
    throw "Unable to determine host target triple from 'rustc -vV'."
  }
  $parts = $hostLine.Split(":", 2)
  if ($parts.Length -lt 2) {
    throw "Unable to parse host target triple from 'rustc -vV' output."
  }
  return $parts[1].Trim()
}

$targetTriple =
  $(if ($env:TAURI_ENV_TARGET_TRIPLE) { $env:TAURI_ENV_TARGET_TRIPLE }
    elseif ($env:TARGET) { $env:TARGET }
    elseif ($env:CARGO_BUILD_TARGET) { $env:CARGO_BUILD_TARGET }
    else { Get-HostTargetTriple })

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$guiRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$tauriRoot = Join-Path $guiRoot "src-tauri"
$binDir = Join-Path $tauriRoot "bin"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null

Write-Host "Building obsidenc sidecar for $targetTriple..."

& cargo build `
  --manifest-path (Join-Path $repoRoot "Cargo.toml") `
  --bin obsidenc `
  --release `
  --locked `
  --target $targetTriple

$isWindows = $env:OS -eq "Windows_NT"
$builtName = if ($isWindows) { "obsidenc.exe" } else { "obsidenc" }
$builtPath = Join-Path (Join-Path $repoRoot "target") (Join-Path $targetTriple (Join-Path "release" $builtName))
if (-not (Test-Path $builtPath)) {
  throw "Built obsidenc binary not found at '$builtPath'."
}

$sidecarName = if ($isWindows) { "obsidenc-$targetTriple.exe" } else { "obsidenc-$targetTriple" }
$sidecarPath = Join-Path $binDir $sidecarName

Copy-Item -Force $builtPath $sidecarPath

Write-Host "Sidecar ready: $sidecarPath"
