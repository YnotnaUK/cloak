BINARY_NAME=cloak

.PHONY: all build clean run keygen keygen-force

all: build

build:
	go build -o bin/$(BINARY_NAME) ./cmd/cloak

clean:
	rm -rf bin/

keygen:
	go run ./cmd/cloak/ keygen

keygen-force:
	go run ./cmd/cloak/ keygen -f

init:
	go run ./cmd/cloak/ init

init-force:
	go run ./cmd/cloak/ init -f