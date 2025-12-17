$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "build-sidecar.ps1")

# Serve the static UI for `cargo tauri dev` (must stay running).
& node (Join-Path $PSScriptRoot "dev-server.js")

