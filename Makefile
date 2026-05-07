BINARY     = adssh
MCP_BINARY = adssh-mcp
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    = -ldflags "-X main.version=$(VERSION)"

.PHONY: build build-mcp install clean test lint

build:
	go build $(LDFLAGS) -o $(BINARY) .

build-mcp:
	go build $(LDFLAGS) -o $(MCP_BINARY) ./cmd/adssh-mcp

install:
	go install $(LDFLAGS) .
	go install $(LDFLAGS) ./cmd/adssh-mcp

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY) $(MCP_BINARY)
