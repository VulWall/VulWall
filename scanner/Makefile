.PHONY: help build run test clean docker-build docker-up docker-down prod-setup prod-deploy-all prod-deploy-domain prod-deploy-ingestion prod-deploy-port prod-stop-all prod-stop-service prod-restart-service prod-logs prod-status

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all services
	@echo "Building passive-recon..."
	@go build -o bin/passive-recon ./cmd/active_recon/passive-recon
	@echo "Building active-recon..."
	@go build -o bin/active-recon ./cmd/active_recon/active-recon
	@echo "Building domain-discovery..."
	@go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery
	@echo "Building port-discovery..."
	@go build -o bin/port-discovery ./cmd/discoveries/port-discovery
	@echo "Building nuclei-scanner..."
	@go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner
	@echo "Building ingestion..."
	@go build -o bin/ingestion ./cmd/ingestion
	@echo "Build complete!"

build-passive: ## Build passive-recon service
	@go build -o bin/passive-recon ./cmd/active_recon/passive-recon

build-active: ## Build active-recon service
	@go build -o bin/active-recon ./cmd/active_recon/active-recon

build-domain-discovery: ## Build domain-discovery service
	@go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery

build-port-discovery: ## Build port-discovery service
	@go build -o bin/port-discovery ./cmd/discoveries/port-discovery

build-nuclei-scanner: ## Build nuclei-scanner service
	@go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner

build-ingestion: ## Build ingestion service
	@go build -o bin/ingestion ./cmd/ingestion

run-passive: ## Run passive-recon service locally
	@go run ./cmd/active_recon/passive-recon/main.go

run-active: ## Run active-recon service locally
	@go run ./cmd/active_recon/active-recon/main.go

run-domain-discovery: ## Run domain-discovery service locally
	@go run ./cmd/discoveries/domain-discovery/main.go

run-port-discovery: ## Run port-discovery service locally
	@go run ./cmd/discoveries/port-discovery/main.go

run-nuclei-scanner: ## Run nuclei-scanner service locally
	@go run ./cmd/active_recon/nuclei-scanner/main.go

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

docker-scale-domain-discovery: ## Scale domain-discovery workers (usage: make docker-scale-domain-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale domain-discovery=$(N)

docker-scale-port-discovery: ## Scale port-discovery workers (usage: make docker-scale-port-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale port-discovery=$(N)

docker-scale-nuclei-scanner: ## Scale nuclei-scanner workers (usage: make docker-scale-nuclei-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale nuclei-scanner=$(N)

docker-scale-ingestion: ## Scale ingestion workers (usage: make docker-scale-ingestion N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale ingestion=$(N)

deps: ## Download dependencies
	@go mod download
	@go mod tidy

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...

# Production Deployment Targets

prod-setup: ## Setup production environment (create network)
	@ops/scripts/setup-network.sh

prod-deploy-all: ## Deploy all services to production (usage: make prod-deploy-all [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-all.sh $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-all.sh; \
	fi

prod-deploy-domain: ## Deploy domain-discovery service (usage: make prod-deploy-domain [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh domain-discovery $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh domain-discovery; \
	fi

prod-deploy-ingestion: ## Deploy ingestion service (usage: make prod-deploy-ingestion [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh ingestion $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh ingestion; \
	fi

prod-deploy-port: ## Deploy port-discovery service (usage: make prod-deploy-port [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh port-discovery $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh port-discovery; \
	fi

prod-stop-all: ## Stop all production services
	@ops/scripts/stop-all.sh

prod-stop-service: ## Stop a specific service (usage: make prod-stop-service SERVICE=domain-discovery)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter is required"; \
		echo "Usage: make prod-stop-service SERVICE=<service-name>"; \
		echo "Available services: domain-discovery, ingestion, port-discovery"; \
		exit 1; \
	fi
	@ops/scripts/stop-service.sh $(SERVICE)

prod-restart-service: ## Restart a specific service (usage: make prod-restart-service SERVICE=domain-discovery [PROJECT=name] [CONFIG=prd])
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter is required"; \
		echo "Usage: make prod-restart-service SERVICE=<service-name>"; \
		exit 1; \
	fi
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/restart-service.sh $(SERVICE) $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/restart-service.sh $(SERVICE); \
	fi

prod-logs: ## View logs from services (usage: make prod-logs [SERVICE=name] [OPTS=-f])
	@if [ -n "$(SERVICE)" ]; then \
		ops/scripts/logs.sh $(SERVICE) $(OPTS); \
	else \
		ops/scripts/logs.sh $(OPTS); \
	fi

prod-status: ## Check status of all production services
	@ops/scripts/status.sh
