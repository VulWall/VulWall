.PHONY: help build run test clean docker-build docker-up docker-down

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all services
	@echo "Building passive-recon..."
	@go build -o bin/passive-recon ./cmd/passive-recon
	@echo "Building active-recon..."
	@go build -o bin/active-recon ./cmd/active-recon
	@echo "Building attack-surface..."
	@go build -o bin/attack-surface ./cmd/attack-surface
	@echo "Build complete!"

build-passive: ## Build passive-recon service
	@go build -o bin/passive-recon ./cmd/passive-recon

build-active: ## Build active-recon service
	@go build -o bin/active-recon ./cmd/active-recon

build-attack-surface: ## Build attack-surface service
	@go build -o bin/attack-surface ./cmd/attack-surface

run-passive: ## Run passive-recon service locally
	@go run ./cmd/passive-recon/main.go

run-active: ## Run active-recon service locally
	@go run ./cmd/active-recon/main.go

run-attack-surface: ## Run attack-surface service locally
	@go run ./cmd/attack-surface/main.go

test: ## Run tests
	@go test -v ./...

test-coverage: ## Run tests with coverage
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	@golangci-lint run

clean: ## Clean build artifacts
	@rm -rf bin/
	@rm -f coverage.out coverage.html

docker-build: ## Build Docker images
	@docker-compose -f ops/docker-compose.yml build

docker-up: ## Start all services with Docker Compose
	@docker-compose -f ops/docker-compose.yml up -d

docker-down: ## Stop all services
	@docker-compose -f ops/docker-compose.yml down

docker-logs: ## View logs from all services
	@docker-compose -f ops/docker-compose.yml logs -f

docker-scale-passive: ## Scale passive-recon workers (usage: make docker-scale-passive N=5)
	@docker-compose -f ops/docker-compose.yml up -d --scale passive-recon=$(N)

docker-scale-active: ## Scale active-recon workers (usage: make docker-scale-active N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale active-recon=$(N)

docker-scale-attack-surface: ## Scale attack-surface workers (usage: make docker-scale-attack-surface N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale attack-surface=$(N)

deps: ## Download dependencies
	@go mod download
	@go mod tidy

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...
