.PHONY: build test race lint fmt fmt-check vuln licenses verify check snapshot clean

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

fmt-check:
	test -z "$$(gofmt -l cmd internal)"

lint:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

licenses:
	go run github.com/google/go-licenses@v1.6.0 save ./cmd/domainops \
		--ignore github.com/MeghdadFadaee/domainops \
		--confidence_threshold 0.7 \
		--save_path THIRD_PARTY_LICENSES \
		--force

verify: fmt-check
	go mod verify
	go test ./...
	go vet ./...

check: verify

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin build coverage dist
