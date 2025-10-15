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
	@echo "Building shodan-discovery..."
	@go build -o bin/shodan-discovery ./cmd/domain-discovery/shodan-discovery
	@echo "Building ingestion..."
	@go build -o bin/ingestion ./cmd/ingestion
	@echo "Build complete!"

build-passive: ## Build passive-recon service
	@go build -o bin/passive-recon ./cmd/passive-recon

build-active: ## Build active-recon service
	@go build -o bin/active-recon ./cmd/active-recon

build-shodan-discovery: ## Build shodan-discovery service
	@go build -o bin/shodan-discovery ./cmd/domain-discovery/shodan-discovery

build-ingestion: ## Build ingestion service
	@go build -o bin/ingestion ./cmd/ingestion

run-passive: ## Run passive-recon service locally
	@go run ./cmd/passive-recon/main.go

run-active: ## Run active-recon service locally
	@go run ./cmd/active-recon/main.go

run-shodan-discovery: ## Run shodan-discovery service locally
	@go run ./cmd/domain-discovery/shodan-discovery/main.go

run-ingestion: ## Run ingestion service locally
	@go run ./cmd/ingestion/main.go

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

docker-scale-shodan-discovery: ## Scale shodan-discovery workers (usage: make docker-scale-shodan-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale shodan-discovery=$(N)

docker-scale-ingestion: ## Scale ingestion workers (usage: make docker-scale-ingestion N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale ingestion=$(N)

deps: ## Download dependencies
	@go mod download
	@go mod tidy

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...
