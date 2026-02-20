BINARY    := nettrap
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build release test test-v test-cover lint vet fmt fmt-check install uninstall completions clean help

## build: compile for the current platform (default target)
build:
	go build -o $(BINARY) $(LDFLAGS) ./cmd/nettrap

## release: static build with stripped symbols
release:
	CGO_ENABLED=0 go build -o $(BINARY) $(LDFLAGS) ./cmd/nettrap

## test: run unit tests
test:
	go test ./...

## test-v: run unit tests (verbose)
test-v:
	go test -v ./...

## test-cover: run tests with coverage report
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: run vet + format check
lint: vet fmt-check

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go files
fmt:
	gofmt -w .

## fmt-check: check formatting (no changes)
fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }

## install: install to /usr/local/bin (requires sudo)
install: build
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod 755 /usr/local/bin/$(BINARY)
	@echo "Installed /usr/local/bin/$(BINARY)"

## uninstall: remove from /usr/local/bin
uninstall:
	sudo rm -f /usr/local/bin/$(BINARY)

## completions: generate shell completion files
completions: build
	@mkdir -p completions
	./$(BINARY) completion bash > completions/$(BINARY).bash
	./$(BINARY) completion zsh  > completions/_$(BINARY)
	./$(BINARY) completion fish > completions/$(BINARY).fish
	@echo "Completions generated in completions/"

## clean: remove build artifacts
clean:
	rm -f $(BINARY) coverage.out coverage.html
	rm -rf completions/
	go clean

## help: show available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
