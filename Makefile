APP_NAME := oidc-auth-service
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION_PKG := github.com/colzphml/pkce_istio_external/internal/version
LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).Commit=$(COMMIT) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test bench fmt tidy docker-build

build:
	go build -trimpath -ldflags="$(LDFLAGS)" ./...

test:
	go test ./...

bench:
	go test -bench=. -benchmem ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

tidy:
	go mod tidy

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t ghcr.io/colzphml/pkce_istio_external:$(VERSION) \
		.
