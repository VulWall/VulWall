.PHONY: help build run test test-coverage lint vet fmt deps clean docker-build docker-up docker-down docker-logs

SRC_DIR := src
# The root docker-compose.yml runs mongo, redis, the scanner and the web app.
COMPOSE := docker compose -f ../docker-compose.yml
# Version the built image reports (About dialog), as in the root Makefile.
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
VULWALL_BUILD_VERSION ?= $(if $(GIT_COMMIT),dev ($(GIT_COMMIT)),dev)
export VULWALL_BUILD_VERSION

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the nightwatch binary into src/bin/
	@cd $(SRC_DIR) && go build -o bin/nightwatch ./cmd/nightwatch

run: ## Run the scanner locally (needs Redis + MongoDB; nuclei, testssl.sh, retire on PATH)
	@cd $(SRC_DIR) && go run ./cmd/nightwatch

test: ## Run tests
	@cd $(SRC_DIR) && go test ./...

test-coverage: ## Run tests with coverage
	@cd $(SRC_DIR) && go test -coverprofile=coverage.out ./...
	@cd $(SRC_DIR) && go tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	@cd $(SRC_DIR) && golangci-lint run

vet: ## Run go vet
	@cd $(SRC_DIR) && go vet ./...

fmt: ## Format code
	@cd $(SRC_DIR) && go fmt ./...

deps: ## Download and tidy dependencies
	@cd $(SRC_DIR) && go mod download
	@cd $(SRC_DIR) && go mod tidy

clean: ## Clean build artifacts
	@rm -rf $(SRC_DIR)/bin/
	@rm -f $(SRC_DIR)/coverage.out $(SRC_DIR)/coverage.html

docker-build: ## Build the scanner image
	@$(COMPOSE) build scanner

docker-up: ## Start the full stack (root docker-compose.yml)
	@$(COMPOSE) up -d

docker-down: ## Stop the full stack
	@$(COMPOSE) down

docker-logs: ## Follow scanner logs
	@$(COMPOSE) logs -f scanner
