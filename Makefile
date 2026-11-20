# Builds and runs the stack from source with the root docker-compose.yml.
# Local images report "dev (<short commit>)" as their version in the About dialog.

.PHONY: help build up

GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
VULWALL_BUILD_VERSION ?= $(if $(GIT_COMMIT),dev ($(GIT_COMMIT)),dev)
export VULWALL_BUILD_VERSION

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the scanner and web images from source
	docker compose build

up: ## Build from source and start the stack
	docker compose up -d --build
