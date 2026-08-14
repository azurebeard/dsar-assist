#!/usr/bin/env pwsh
# DSAR Assist launcher — Windows.
#
# Mirrors ./dsar. Two runtimes, because Docker Desktop is frequently blocked on
# a managed Windows laptop and uv installs without admin rights.
#
#   .\dsar.ps1 up
#   $env:DSAR_RUNTIME='uv'; .\dsar.ps1 up
#
# `-p 127.0.0.1:8765:8765` is a security control. Without the address prefix,
# `-p 8765:8765` publishes on every interface of the host. A structural test
# asserts the string is present in this file.

$ErrorActionPreference = 'Stop'

$Image    = if ($env:DSAR_IMAGE)     { $env:DSAR_IMAGE }     else { 'ghcr.io/azurebeard/dsar-assist:latest' }
$Port     = if ($env:DSAR_PORT)      { $env:DSAR_PORT }      else { '8765' }
$AuditDir = if ($env:DSAR_AUDIT_DIR) { $env:DSAR_AUDIT_DIR } else { Join-Path $HOME '.dsar\audit' }
$Runtime  = if ($env:DSAR_RUNTIME)   { $env:DSAR_RUNTIME }   else { 'auto' }

function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    docker info *> $null
    return $LASTEXITCODE -eq 0
}

if ($Runtime -eq 'auto') {
    if (Test-Docker) { $Runtime = 'docker' }
    elseif (Get-Command uvx -ErrorAction SilentlyContinue) { $Runtime = 'uv' }
    else {
        Write-Error @'
Neither Docker nor uv is available on this machine.

  Docker:  https://docs.docker.com/get-started/get-docker/
  uv:      powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
           (a single static binary - no admin rights required)

Then run .\dsar.ps1 up again.
'@
        exit 127
    }
}

switch ($Runtime) {
    'docker' {
        # No browser inside the container, and the port belongs to the
        # container's network namespace, so the host side opens the page.
        if ($args.Count -gt 0 -and $args[0] -eq 'up') {
            Start-Job { Start-Sleep 1; Start-Process "http://localhost:$using:Port" } | Out-Null
        }
        New-Item -ItemType Directory -Force -Path $AuditDir | Out-Null
        # Read-only root, no setuid escalation, no capabilities. The app writes
        # only to the audit mount, so this costs nothing (WS10 SEC-M-06).
        docker run --rm -it `
            -p "127.0.0.1:${Port}:${Port}" `
            --read-only `
            --tmpfs /tmp:rw,noexec,nosuid,size=64m `
            --security-opt no-new-privileges `
            --cap-drop ALL `
            -e DSAR_CLIENT_ID -e DSAR_TENANT_ID -e DSAR_IDENTITY_EXPANSION `
            -e "DSAR_PORT=$Port" `
            -e DSAR_IN_CONTAINER=1 `
            -v "${AuditDir}:/var/lib/dsar/audit" `
            $Image @args
        exit $LASTEXITCODE
    }
    'uv' {
        uvx --from dsar-assist dsar @args
        exit $LASTEXITCODE
    }
    default {
        Write-Error "DSAR_RUNTIME must be auto, docker or uv (got: $Runtime)"
        exit 2
    }
}
