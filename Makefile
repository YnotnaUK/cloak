BINARY_NAME=cloak
BASE_VERSION ?= $(shell cat VERSION 2>/dev/null || echo "0.1")
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE         ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION      ?= v$(BASE_VERSION)-dev-$(COMMIT)
LDFLAGS = -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.Date=$(DATE)"
COVERAGE_DIR=coverage

.PHONY: all test test-coverage test-cover build clean keygen keygen-force init init-force recipient-list recipient-add recipient-remove rekey encrypt decrypt

all: build

test:
	go test -v ./...

test-cover:
	go test -cover ./...

test-coverage:
	mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage HTML generated at $(COVERAGE_DIR)/coverage.html"

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/cloak

clean:
	rm -rf bin/ $(COVERAGE_DIR)

keygen:
	go run ./cmd/cloak/ keygen

keygen-force:
	go run ./cmd/cloak/ keygen -f

init:
	go run ./cmd/cloak/ init

init-force:
	go run ./cmd/cloak/ init -f

recipient-list:
	go run ./cmd/cloak/ recipient list

recipient-add:
	@test -n "$(KEY)" || (echo "Usage: make recipient-add KEY=<public_key_hex>" && exit 1)
	go run ./cmd/cloak/ recipient add $(KEY)

recipient-remove:
	@test -n "$(KEY)" || (echo "Usage: make recipient-remove KEY=<public_key_hex>" && exit 1)
	go run ./cmd/cloak/ recipient remove $(KEY)

rekey:
	go run ./cmd/cloak/ rekey

encrypt:
	go run ./cmd/cloak/ encrypt

decrypt:
	go run ./cmd/cloak/ decrypt

version:
	go run ./cmd/cloak/ version
