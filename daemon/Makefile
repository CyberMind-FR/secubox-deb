# SecuBox Mesh Daemon Makefile
# CyberMind — SecuBox-Deb — 2026

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
BUILD_DIR := build
PREFIX ?= /usr

.PHONY: all clean build test install

all: build

# Build binaries
build: build-secuboxd build-secuboxctl build-c3box

build-secuboxd:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/secuboxd ./cmd/secuboxd

build-secuboxctl:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/secuboxctl ./cmd/secuboxctl

build-c3box:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/c3box ./c3box/backend

# Cross-compile for ARM64
build-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/secuboxd-arm64 ./cmd/secuboxd
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/secuboxctl-arm64 ./cmd/secuboxctl
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/c3box-arm64 ./c3box/backend

# Run tests
test:
	go test -v ./...

# Install to system
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/secuboxd $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(BUILD_DIR)/secuboxctl $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(BUILD_DIR)/c3box $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)/lib/systemd/system
	install -m 644 systemd/secuboxd.service $(DESTDIR)/lib/systemd/system/
	install -m 644 systemd/c3box.service $(DESTDIR)/lib/systemd/system/
	install -d $(DESTDIR)/etc/secubox
	install -m 640 testdata/secuboxd.yaml $(DESTDIR)/etc/secubox/secuboxd.yaml.example
	install -d $(DESTDIR)$(PREFIX)/share/c3box/www
	cp -r c3box/frontend/* $(DESTDIR)$(PREFIX)/share/c3box/www/ 2>/dev/null || true

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run ./...

# Generate go.sum
tidy:
	go mod tidy
