BINARY := pigeon-fence
BUILD_DIR := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test e2e vet clean

build:
	mkdir -p $(BUILD_DIR)
	go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY) ./cmd/pigeon-fence

test:
	go test ./...

e2e: build
	sudo go test -tags=e2e -v -count=1 ./e2e

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
