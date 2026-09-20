BINARY_NAME=cloak
VERSION=v0.1.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE=$(shell date +%Y-%m-%d)

build:
	go build -ldflags="-s -w \
		-X main.version=$(VERSION) \
		-X main.commit=$(COMMIT) \
		-X main.date=$(DATE)" \
		-o bin/$(BINARY_NAME) ./cmd/cloak

install:
	go install -ldflags="-s -w \
		-X main.version=$(VERSION) \
		-X main.commit=$(COMMIT) \
		-X main.date=$(DATE)" ./cmd/cloak

test:
	go test -v ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

coverage-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

clean:
	rm -rf bin/