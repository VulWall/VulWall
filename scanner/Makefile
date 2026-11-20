.PHONY: help build run test clean docker-build docker-up docker-down

SRC_DIR := src

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all services
	@echo "Building domain-discovery..."
	@cd $(SRC_DIR) && go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery
	@echo "Building port-discovery..."
	@cd $(SRC_DIR) && go build -o bin/port-discovery ./cmd/discoveries/port-discovery
	@echo "Building nuclei-scanner..."
	@cd $(SRC_DIR) && go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner
	@echo "Building testssl-scanner..."
	@cd $(SRC_DIR) && go build -o bin/testssl-scanner ./cmd/active_recon/testssl-scanner
	@echo "Building discovery-enrichment..."
	@cd $(SRC_DIR) && go build -o bin/discovery-enrichment ./cmd/active_recon/discovery-enrichment
	@echo "Building js-dependency-scanner..."
	@cd $(SRC_DIR) && go build -o bin/js-dependency-scanner ./cmd/active_recon/js-dependency-scanner
	@echo "Building http-header-scanner..."
	@cd $(SRC_DIR) && go build -o bin/http-header-scanner ./cmd/active_recon/http-header-scanner
	@echo "Building email-security-scanner..."
	@cd $(SRC_DIR) && go build -o bin/email-security-scanner ./cmd/active_recon/email-security-scanner
	@echo "Building knowledge-base-engine..."
	@cd $(SRC_DIR) && go build -o bin/knowledge-base-engine ./cmd/enrichers/knowledge-base-engine
	@echo "Building ingestion..."
	@cd $(SRC_DIR) && go build -o bin/ingestion ./cmd/ingestion
	@echo "Building scan-coordinator..."
	@cd $(SRC_DIR) && go build -o bin/scan-coordinator ./cmd/scan-coordinator
	@echo "Build complete!"

build-domain-discovery: ## Build domain-discovery service
	@cd $(SRC_DIR) && go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery

build-port-discovery: ## Build port-discovery service
	@cd $(SRC_DIR) && go build -o bin/port-discovery ./cmd/discoveries/port-discovery

build-nuclei-scanner: ## Build nuclei-scanner service
	@cd $(SRC_DIR) && go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner

build-testssl-scanner: ## Build testssl-scanner service
	@cd $(SRC_DIR) && go build -o bin/testssl-scanner ./cmd/active_recon/testssl-scanner

build-discovery-enrichment: ## Build discovery-enrichment service
	@cd $(SRC_DIR) && go build -o bin/discovery-enrichment ./cmd/active_recon/discovery-enrichment

build-js-dependency-scanner: ## Build js-dependency-scanner service
	@cd $(SRC_DIR) && go build -o bin/js-dependency-scanner ./cmd/active_recon/js-dependency-scanner

build-http-header-scanner: ## Build http-header-scanner service
	@cd $(SRC_DIR) && go build -o bin/http-header-scanner ./cmd/active_recon/http-header-scanner

build-email-security-scanner: ## Build email-security-scanner service
	@cd $(SRC_DIR) && go build -o bin/email-security-scanner ./cmd/active_recon/email-security-scanner

build-knowledge-base-engine: ## Build knowledge-base-engine service
	@cd $(SRC_DIR) && go build -o bin/knowledge-base-engine ./cmd/enrichers/knowledge-base-engine

build-ingestion: ## Build ingestion service
	@cd $(SRC_DIR) && go build -o bin/ingestion ./cmd/ingestion

build-scan-coordinator: ## Build scan-coordinator service
	@cd $(SRC_DIR) && go build -o bin/scan-coordinator ./cmd/scan-coordinator

run-domain-discovery: ## Run domain-discovery service locally
	@cd $(SRC_DIR) && go run ./cmd/discoveries/domain-discovery/main.go

run-port-discovery: ## Run port-discovery service locally
	@cd $(SRC_DIR) && go run ./cmd/discoveries/port-discovery/main.go

run-nuclei-scanner: ## Run nuclei-scanner service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/nuclei-scanner/main.go

run-testssl-scanner: ## Run testssl-scanner service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/testssl-scanner/main.go

run-discovery-enrichment: ## Run discovery-enrichment service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/discovery-enrichment/main.go

run-js-dependency-scanner: ## Run js-dependency-scanner service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/js-dependency-scanner/main.go

run-http-header-scanner: ## Run http-header-scanner service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/http-header-scanner/main.go

run-email-security-scanner: ## Run email-security-scanner service locally
	@cd $(SRC_DIR) && go run ./cmd/active_recon/email-security-scanner/main.go

run-knowledge-base-engine: ## Run knowledge-base-engine service locally
	@cd $(SRC_DIR) && go run ./cmd/enrichers/knowledge-base-engine/main.go

run-ingestion: ## Run ingestion service locally
	@cd $(SRC_DIR) && go run ./cmd/ingestion/main.go

run-scan-coordinator: ## Run scan-coordinator service locally
	@cd $(SRC_DIR) && go run ./cmd/scan-coordinator/main.go

test: ## Run tests
	@cd $(SRC_DIR) && go test -v ./...

test-coverage: ## Run tests with coverage
	@cd $(SRC_DIR) && go test -v -coverprofile=coverage.out ./...
	@cd $(SRC_DIR) && go tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	@cd $(SRC_DIR) && golangci-lint run

clean: ## Clean build artifacts
	@rm -rf $(SRC_DIR)/bin/
	@rm -f $(SRC_DIR)/coverage.out $(SRC_DIR)/coverage.html

docker-build: ## Build Docker images
	@docker-compose -f ops/docker-compose.yml build

docker-up: ## Start all services with Docker Compose
	@docker-compose -f ops/docker-compose.yml up -d

docker-down: ## Stop all services
	@docker-compose -f ops/docker-compose.yml down

docker-logs: ## View logs from all services
	@docker-compose -f ops/docker-compose.yml logs -f

docker-scale-domain-discovery: ## Scale domain-discovery workers (usage: make docker-scale-domain-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale domain-discovery=$(N)

docker-scale-port-discovery: ## Scale port-discovery workers (usage: make docker-scale-port-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale port-discovery=$(N)

docker-scale-nuclei-scanner: ## Scale nuclei-scanner workers (usage: make docker-scale-nuclei-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale nuclei-scanner=$(N)

docker-scale-testssl-scanner: ## Scale testssl-scanner workers (usage: make docker-scale-testssl-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale testssl-scanner=$(N)

docker-scale-discovery-enrichment: ## Scale discovery-enrichment workers (usage: make docker-scale-discovery-enrichment N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale discovery-enrichment=$(N)

docker-scale-js-dependency-scanner: ## Scale js-dependency-scanner workers (usage: make docker-scale-js-dependency-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale js-dependency-scanner=$(N)

docker-scale-http-header-scanner: ## Scale http-header-scanner workers (usage: make docker-scale-http-header-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale http-header-scanner=$(N)

docker-scale-email-security-scanner: ## Scale email-security-scanner workers (usage: make docker-scale-email-security-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale email-security-scanner=$(N)

docker-scale-knowledge-base-engine: ## Scale knowledge-base-engine workers (usage: make docker-scale-knowledge-base-engine N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale knowledge-base-engine=$(N)

docker-scale-ingestion: ## Scale ingestion workers (usage: make docker-scale-ingestion N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale ingestion=$(N)

deps: ## Download dependencies
	@cd $(SRC_DIR) && go mod download
	@cd $(SRC_DIR) && go mod tidy

fmt: ## Format code
	@cd $(SRC_DIR) && go fmt ./...

vet: ## Run go vet
	@cd $(SRC_DIR) && go vet ./...
