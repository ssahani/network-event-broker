# SPDX-License-Identifier: Apache-2.0

# Variables for versioning and directories
HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
COMMIT_DATE := $(shell git show -s --format=%ci $(HASH) 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date '+%Y-%m-%d %H:%M:%S')
VERSION := $(HASH) ($(COMMIT_DATE))
BUILDDIR ?= bin
SRCDIR ?= .
BINARY := $(BUILDDIR)/network-broker
CONFIG_DIR := /etc/network-broker
SERVICE_DIR := /lib/systemd/system
GO := go
INSTALL := install

# Ensure Go module support
export GO111MODULE=on

.PHONY: help
help:
	@echo "make [TARGETS...]"
	@echo
	@echo "This is the maintenance Makefile for network-broker. Available targets:"
	@echo
	@echo "  help          Print this usage information"
	@echo "  build         Build the network-broker binary"
	@echo "  install       Install binary, configuration, and systemd service files"
	@echo "  clean         Remove build artifacts"
	@echo "  test          Run unit tests"
	@echo "  fmt           Format Go source files"
	@echo "  vet           Run Go vet checks"
	@echo "  lint          Run golangci-lint checks"

# Ensure build directory exists
$(BUILDDIR):
	@mkdir -p $@

# Build the network-broker binary
.PHONY: build
build: $(BUILDDIR)
	@echo "Building network-broker (version: $(VERSION), build date: $(BUILD_DATE))"
	@$(GO) build -ldflags="-X 'main.buildVersion=$(VERSION)' -X 'main.buildDate=$(BUILD_DATE)'" -o $(BINARY) $(SRCDIR)/cmd/network-broker
	@echo "Binary built at $(BINARY)"

# Install binary, configuration, and systemd service files
.PHONY: install
install: build
	@echo "Installing network-broker to $(CONFIG_DIR) and $(SERVICE_DIR)"
	@$(INSTALL) -Dm 755 $(BINARY) /usr/bin/network-broker
	@$(INSTALL) -Dm 755 -d $(CONFIG_DIR)
	@$(INSTALL) -Dm 644 distribution/network-broker.yaml $(CONFIG_DIR)/network-broker.yaml
	@$(INSTALL) -Dm 644 distribution/network-broker.service $(SERVICE_DIR)/network-broker.service
	@systemctl daemon-reload || echo "Warning: Failed to reload systemd daemon"
	@echo "Installation complete"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts"
	@$(GO) clean
	@rm -rf $(BUILDDIR)
	@echo "Clean complete"

# Run unit tests
.PHONY: test
test:
	@echo "Running unit tests"
	@$(GO) test -v ./...

# Format Go source files
.PHONY: fmt
fmt:
	@echo "Formatting Go source files"
	@$(GO) fmt ./...

# Run Go vet checks
.PHONY: vet
vet:
	@echo "Running Go vet checks"
	@$(GO) vet ./...

# Run golangci-lint checks
.PHONY: lint
lint:
	@echo "Running golangci-lint checks"
	@golangci-lint run ./... || echo "Install golangci-lint: https://golangci-lint.run/usage/install/"

# Ensure build depends on test, fmt, and vet
build: test fmt vet