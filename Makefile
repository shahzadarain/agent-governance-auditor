# Maintainer shortcuts. Users never need Make: see README for install commands.
# On Windows without Make, run: powershell -File scripts/check.ps1
GO ?= go
BIN := bin/agentgov$(shell $(GO) env GOEXE)

.PHONY: build test lint security demo check web clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) ./cmd/agentgov

test:
	$(GO) test ./...

lint:
	@test -z "$$(gofmt -l . | grep -v '^.tools')" || (gofmt -l . && exit 1)
	$(GO) vet ./...

security:
	$(GO) test ./internal/detect/... ./internal/reporting/... ./internal/server/... ./internal/policy/...
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

demo: build
	-$(BIN) scan examples/vulnerable-agent
	$(BIN) scan examples/safe-agent

web:
	cd web && npm ci && npm run check && npm run build

check:
	bash scripts/check-all.sh

clean:
	rm -rf bin dist
