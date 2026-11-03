VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/elchi-dev/conduit/internal/version.Version=$(VERSION) \
	-X github.com/elchi-dev/conduit/internal/version.Commit=$(COMMIT) \
	-X github.com/elchi-dev/conduit/internal/version.Date=$(DATE)
TRIPLE  ?= $(shell rustc -vV 2>/dev/null | sed -n 's/host: //p')

.PHONY: all build daemon daemon-dev hub cli web test lint fmt dev desktop clean

all: build

build: daemon hub cli

## daemon: build bin/conduitd with the web UI embedded
daemon: web
	rm -rf internal/ui/dist && cp -r web/dist internal/ui/dist
	CGO_ENABLED=0 go build -tags ui -trimpath -ldflags "$(LDFLAGS)" -o bin/conduitd ./cmd/conduitd

## hub: build bin/conduit-hub
hub:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/conduit-hub ./cmd/conduit-hub

## cli: build bin/conduit, the command-line client
cli:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/conduit ./cmd/conduit

## web: build the app UI
web:
	cd web && pnpm install --frozen-lockfile && pnpm build

## daemon-dev: build bin/conduitd without the embedded UI (fast)
daemon-dev:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/conduitd ./cmd/conduitd

test:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

fmt:
	gofmt -w .

## dev: run the daemon; start the UI separately with `cd web && pnpm dev`
dev: daemon
	./bin/conduitd

## desktop: build the Tauri shell with the daemon as its sidecar
desktop: daemon
	mkdir -p apps/desktop/src-tauri/binaries
	cp bin/conduitd apps/desktop/src-tauri/binaries/conduitd-$(TRIPLE)
	cd apps/desktop/src-tauri && pnpm dlx @tauri-apps/cli@2 build

clean:
	rm -rf bin dist web/dist
