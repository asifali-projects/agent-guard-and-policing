#!/usr/bin/env pwsh
# ---------------------------------------------------------------------------
# AgentGuard task runner (Windows / PowerShell).
# Usage:  .\tasks.ps1 <task>
# Unix/CI users can use the mirrored `Makefile` instead.
# ---------------------------------------------------------------------------
param(
    [Parameter(Position = 0)]
    [string]$Task = "help"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Compose = "$Root/infra/docker-compose.yml"

function Invoke-Compose { param([string[]]$Args) & docker compose -f $Compose @Args }

switch ($Task) {
    "help" {
        Write-Host @"
AgentGuard tasks:

  infra-up        Start backing services (Postgres, Redis, Redpanda, ClickHouse, Qdrant, MinIO)
  infra-down      Stop backing services
  infra-clean     Stop backing services AND delete their volumes (wipes data)
  infra-logs      Tail backing-service logs
  infra-ps        Show backing-service status

  up              Build + run everything (backing services + api + web) in containers
  down            Stop all containers

  api-install     Create the API virtualenv and install dependencies
  api-dev         Run the API locally with reload  (http://localhost:8000)
  api-test        Run the API test suite
  api-lint        Ruff lint + format check for the API

  web-install     Install web dashboard dependencies
  web-dev         Run the web dashboard locally  (http://localhost:3000)

  fmt             Auto-format Python (ruff)
"@
    }

    "infra-up"    { Invoke-Compose @("up", "-d") }
    "infra-down"  { Invoke-Compose @("down") }
    "infra-clean" { Invoke-Compose @("down", "-v") }
    "infra-logs"  { Invoke-Compose @("logs", "-f") }
    "infra-ps"    { Invoke-Compose @("ps") }

    "up"          { Invoke-Compose @("--profile", "apps", "up", "--build", "-d") }
    "down"        { Invoke-Compose @("--profile", "apps", "down") }

    "api-install" {
        Push-Location "$Root/apps/api"
        try {
            if (-not (Test-Path ".venv")) { python -m venv .venv }
            & ".venv/Scripts/python.exe" -m pip install --upgrade pip
            & ".venv/Scripts/python.exe" -m pip install -e ".[dev]"
        } finally { Pop-Location }
    }
    "api-dev" {
        Push-Location "$Root/apps/api"
        try { & ".venv/Scripts/python.exe" -m uvicorn agentguard_api.main:app --reload --port 8000 }
        finally { Pop-Location }
    }
    "api-test" {
        Push-Location "$Root/apps/api"
        try { & ".venv/Scripts/python.exe" -m pytest }
        finally { Pop-Location }
    }
    "api-lint" {
        Push-Location "$Root/apps/api"
        try {
            & ".venv/Scripts/python.exe" -m ruff check .
            & ".venv/Scripts/python.exe" -m ruff format --check .
        } finally { Pop-Location }
    }
    "fmt" {
        Push-Location "$Root/apps/api"
        try { & ".venv/Scripts/python.exe" -m ruff format . ; & ".venv/Scripts/python.exe" -m ruff check --fix . }
        finally { Pop-Location }
    }

    "web-install" {
        Push-Location "$Root/apps/web"
        try { npm install } finally { Pop-Location }
    }
    "web-dev" {
        Push-Location "$Root/apps/web"
        try { npm run dev } finally { Pop-Location }
    }

    default {
        Write-Error "Unknown task '$Task'. Run '.\tasks.ps1 help' for the list."
        exit 1
    }
}
