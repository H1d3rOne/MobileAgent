.PHONY: build run clean test lint docker

APP_NAME := mobileagent-server
BUILD_DIR := build
GO := go
GOFLAGS := -v

build:
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./cmd/server/

run: build
	./$(BUILD_DIR)/$(APP_NAME) -config configs/config.yaml

clean:
	rm -rf $(BUILD_DIR)

test:
	$(GO) test ./... -v

lint:
	golangci-lint run ./...

docker:
	docker build -t mobileagent-backend:latest .

deps:
	$(GO) mod tidy
	$(GO) mod download

fmt:
	gofmt -w .
	goimports -w .
