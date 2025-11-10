.PHONY: help build run test clean docker-build docker-up docker-down prod-setup prod-deploy-all prod-deploy-domain prod-deploy-ingestion prod-deploy-port prod-deploy-nuclei prod-stop-all prod-stop-service prod-restart-service prod-logs prod-status

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all services
	@echo "Building domain-discovery..."
	@go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery
	@echo "Building port-discovery..."
	@go build -o bin/port-discovery ./cmd/discoveries/port-discovery
	@echo "Building nuclei-scanner..."
	@go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner
	@echo "Building nikto-scanner..."
	@go build -o bin/nikto-scanner ./cmd/active_recon/nikto-scanner
	@echo "Building testssl-scanner..."
	@go build -o bin/testssl-scanner ./cmd/active_recon/testssl-scanner
	@echo "Building webtechprofiler..."
	@go build -o bin/webtechprofiler ./cmd/active_recon/webtechprofiler
	@echo "Building discovery-enrichment..."
	@go build -o bin/discovery-enrichment ./cmd/active_recon/discovery-enrichment
	@echo "Building ingestion..."
	@go build -o bin/ingestion ./cmd/ingestion
	@echo "Building scan-coordinator..."
	@go build -o bin/scan-coordinator ./cmd/scan-coordinator
	@echo "Build complete!"

build-domain-discovery: ## Build domain-discovery service
	@go build -o bin/domain-discovery ./cmd/discoveries/domain-discovery

build-port-discovery: ## Build port-discovery service
	@go build -o bin/port-discovery ./cmd/discoveries/port-discovery

build-nuclei-scanner: ## Build nuclei-scanner service
	@go build -o bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner

build-nikto-scanner: ## Build nikto-scanner service
	@go build -o bin/nikto-scanner ./cmd/active_recon/nikto-scanner

build-testssl-scanner: ## Build testssl-scanner service
	@go build -o bin/testssl-scanner ./cmd/active_recon/testssl-scanner

build-webtechprofiler: ## Build webtechprofiler service
	@go build -o bin/webtechprofiler ./cmd/active_recon/webtechprofiler

build-discovery-enrichment: ## Build discovery-enrichment service
	@go build -o bin/discovery-enrichment ./cmd/active_recon/discovery-enrichment

build-ingestion: ## Build ingestion service
	@go build -o bin/ingestion ./cmd/ingestion

build-scan-coordinator: ## Build scan-coordinator service
	@go build -o bin/scan-coordinator ./cmd/scan-coordinator

run-domain-discovery: ## Run domain-discovery service locally
	@go run ./cmd/discoveries/domain-discovery/main.go

run-port-discovery: ## Run port-discovery service locally
	@go run ./cmd/discoveries/port-discovery/main.go

run-nuclei-scanner: ## Run nuclei-scanner service locally
	@go run ./cmd/active_recon/nuclei-scanner/main.go

run-nikto-scanner: ## Run nikto-scanner service locally
	@go run ./cmd/active_recon/nikto-scanner/main.go

run-testssl-scanner: ## Run testssl-scanner service locally
	@go run ./cmd/active_recon/testssl-scanner/main.go

run-webtechprofiler: ## Run webtechprofiler service locally
	@go run ./cmd/active_recon/webtechprofiler/main.go

run-discovery-enrichment: ## Run discovery-enrichment service locally
	@go run ./cmd/active_recon/discovery-enrichment/main.go

run-ingestion: ## Run ingestion service locally
	@go run ./cmd/ingestion/main.go

run-scan-coordinator: ## Run scan-coordinator service locally
	@go run ./cmd/scan-coordinator/main.go

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

docker-scale-domain-discovery: ## Scale domain-discovery workers (usage: make docker-scale-domain-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale domain-discovery=$(N)

docker-scale-port-discovery: ## Scale port-discovery workers (usage: make docker-scale-port-discovery N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale port-discovery=$(N)

docker-scale-nuclei-scanner: ## Scale nuclei-scanner workers (usage: make docker-scale-nuclei-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale nuclei-scanner=$(N)

docker-scale-nikto-scanner: ## Scale nikto-scanner workers (usage: make docker-scale-nikto-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale nikto-scanner=$(N)

docker-scale-testssl-scanner: ## Scale testssl-scanner workers (usage: make docker-scale-testssl-scanner N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale testssl-scanner=$(N)

docker-scale-webtechprofiler: ## Scale webtechprofiler workers (usage: make docker-scale-webtechprofiler N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale webtechprofiler=$(N)

docker-scale-discovery-enrichment: ## Scale discovery-enrichment workers (usage: make docker-scale-discovery-enrichment N=3)
	@docker-compose -f ops/docker-compose.yml up -d --scale discovery-enrichment=$(N)

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

prod-deploy-nuclei: ## Deploy nuclei-scanner service (usage: make prod-deploy-nuclei [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh nuclei-scanner $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh nuclei-scanner; \
	fi

prod-deploy-nikto: ## Deploy nikto-scanner service (usage: make prod-deploy-nikto [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh nikto-scanner $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh nikto-scanner; \
	fi

prod-deploy-testssl: ## Deploy testssl-scanner service (usage: make prod-deploy-testssl [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh testssl-scanner $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh testssl-scanner; \
	fi

prod-deploy-webtechprofiler: ## Deploy webtechprofiler service (usage: make prod-deploy-webtechprofiler [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh webtechprofiler $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh webtechprofiler; \
	fi

prod-deploy-discovery-enrichment: ## Deploy discovery-enrichment service (usage: make prod-deploy-discovery-enrichment [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh discovery-enrichment $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh discovery-enrichment; \
	fi

prod-deploy-scan-coordinator: ## Deploy scan-coordinator service (usage: make prod-deploy-scan-coordinator [PROJECT=name] [CONFIG=prd])
	@if [ -n "$(PROJECT)" ]; then \
		ops/scripts/deploy-service.sh scan-coordinator $(PROJECT) $(CONFIG); \
	else \
		ops/scripts/deploy-service.sh scan-coordinator; \
	fi

prod-stop-all: ## Stop all production services
	@ops/scripts/stop-all.sh

prod-stop-service: ## Stop a specific service (usage: make prod-stop-service SERVICE=domain-discovery)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter is required"; \
		echo "Usage: make prod-stop-service SERVICE=<service-name>"; \
		echo "Available services: domain-discovery, ingestion, port-discovery, nuclei-scanner, nikto-scanner, testssl-scanner, webtechprofiler, discovery-enrichment"; \
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
