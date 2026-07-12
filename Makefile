.PHONY: build test race lint fmt check snapshot clean

APP := domainops
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/MeghdadFadaee/domainops/internal/buildinfo.Version=$(VERSION) \
	-X github.com/MeghdadFadaee/domainops/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/MeghdadFadaee/domainops/internal/buildinfo.Date=$(DATE)

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/domainops

test:
	go test ./...

race:
	go test -race ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

lint:
	go vet ./...

check:
	$(MAKE) lint
	go test ./...

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin build coverage dist
