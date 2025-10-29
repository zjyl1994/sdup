# Simple Makefile for sdup

GO ?= go
BINARY_NAME ?= sdup
BUILD_DIR ?= build
PREFIX ?= /usr/local
BIN_DIR := $(PREFIX)/bin

.PHONY: all build install uninstall clean test fmt vet

all: build

# Build binary to ./build
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) ./

# Install already-built binary to /usr/local/bin (or $(PREFIX)/bin)
install:
	@if [ ! -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "Binary not built. Run 'make build' first."; \
		exit 1; \
	fi
	install -d $(BIN_DIR)
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)

# Remove installed binary
uninstall:
	rm -f $(BIN_DIR)/$(BINARY_NAME)

# Clean build artifacts
clean:
	@rm -rf $(BUILD_DIR)

# Run tests
test:
	$(GO) test ./...

# Format code
fmt:
	$(GO) fmt ./...

# Vet code
vet:
	$(GO) vet ./...
