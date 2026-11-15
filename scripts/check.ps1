# One command for maintainers on Windows PowerShell: format check, vet, tests,
# build, and smoke scans. Mirrors scripts/check-all.sh and `make check`.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host '== gofmt'
$unformatted = gofmt -l . | Where-Object { $_ -notlike '.tools*' }
if ($unformatted) { $unformatted; throw 'gofmt reported unformatted files' }
Write-Host '== go vet'
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
Write-Host '== go test'
go test ./...
if ($LASTEXITCODE -ne 0) { throw 'go test failed' }
Write-Host '== build'
New-Item -ItemType Directory -Force bin | Out-Null
$env:CGO_ENABLED = '0'
go build -trimpath -o bin/agentgov.exe ./cmd/agentgov
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Write-Host '== smoke: vulnerable example must exit 1'
& bin/agentgov.exe scan examples/vulnerable-agent -q
if ($LASTEXITCODE -ne 1) { throw "expected exit code 1, got $LASTEXITCODE" }
Write-Host '== smoke: safe example must exit 0'
& bin/agentgov.exe scan examples/safe-agent -q
if ($LASTEXITCODE -ne 0) { throw "expected exit code 0, got $LASTEXITCODE" }
Write-Host 'all checks passed'
