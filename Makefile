BINARY     = adssh
MCP_BINARY = adssh-mcp
ADM_BINARY = adsshadm
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    = -ldflags "-X main.version=$(VERSION)"

.PHONY: build build-ee build-mcp build-adm install clean test test-e2e vet lint demo package dist

build:
	go build $(LDFLAGS) -o $(BINARY) .

build-mcp:
	go build $(LDFLAGS) -o $(MCP_BINARY) ./cmd/adssh-mcp

# Enterprise build: the core plus every *_ee.go file (ee/LICENSE).
build-ee:
	go build -tags ee $(LDFLAGS) -o $(BINARY) .

build-adm:
	go build -tags ee $(LDFLAGS) -o $(ADM_BINARY) ./ee/cmd/adsshadm

install:
	go install $(LDFLAGS) .
	go install $(LDFLAGS) ./cmd/adssh-mcp

test:
	go test ./...

# End-to-end suite: black-box tests that drive the compiled binaries.
# Guarded behind the `e2e` build tag so `make test` never runs them.
test-e2e:
	go test -tags e2e -count=1 ./e2e/...

demo:
	scripts/commercial-demo.sh

package dist:
	VERSION=$(VERSION) scripts/package-release.sh

vet:
	go vet ./...

# Prefer golangci-lint when installed; fall back to `go vet` otherwise so the
# target still does something useful on a bare checkout.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found; falling back to 'go vet ./...'"; \
		go vet ./...; \
	fi

clean:
	rm -f $(BINARY) $(MCP_BINARY)
