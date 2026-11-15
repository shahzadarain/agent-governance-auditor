#!/usr/bin/env bash
# One command for maintainers: format check, vet, tests, build, and smoke scans.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== gofmt"
unformatted="$(gofmt -l . | grep -v '^.tools' || true)"
if [ -n "$unformatted" ]; then echo "$unformatted"; exit 1; fi
echo "== go vet"
go vet ./...
echo "== go test"
go test ./...
echo "== build"
mkdir -p bin
ext=""
case "$(go env GOOS)" in windows) ext=".exe" ;; esac
CGO_ENABLED=0 go build -trimpath -o "bin/agentgov$ext" ./cmd/agentgov
echo "== smoke: vulnerable example must exit 1"
set +e
"bin/agentgov$ext" scan examples/vulnerable-agent -q
code=$?
set -e
if [ "$code" -ne 1 ]; then echo "expected 1, got $code"; exit 1; fi
echo "== smoke: safe example must exit 0"
"bin/agentgov$ext" scan examples/safe-agent -q
echo "all checks passed"
