BINARY_NAME=cloak
COVERAGE_DIR=coverage

.PHONY: all build clean run keygen keygen-force init init-force test test-coverage

all: build

build:
	go build -o bin/$(BINARY_NAME) ./cmd/cloak

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

test:
	go test -v ./...

test-coverage:
	mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage HTML generated at $(COVERAGE_DIR)/coverage.html"
