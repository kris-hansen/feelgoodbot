VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

.PHONY: build install clean lint test

build:
	go build -ldflags "$(LDFLAGS)" -o feelgoodbot ./cmd/feelgoodbot

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/feelgoodbot

clean:
	rm -f feelgoodbot

lint:
	gofmt -w .
	go vet ./...

test:
	go test ./...

# Build for release (stripped, optimized)
release:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o feelgoodbot ./cmd/feelgoodbot
