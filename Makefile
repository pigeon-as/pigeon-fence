BINARY := pigeon-fence
BUILD_DIR := build

.PHONY: build test e2e vet clean

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/pigeon-fence

test:
	go test ./...

e2e: build
	sudo go test -tags=e2e -v -count=1 ./e2e

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
