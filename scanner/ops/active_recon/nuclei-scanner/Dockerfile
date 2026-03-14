# Stage 1: Build Go binary
FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/nuclei-scanner ./cmd/active_recon/nuclei-scanner

# Stage 2: Use ProjectDiscovery's official Nuclei image
# TODO: Pin to a specific version when stable (e.g., projectdiscovery/nuclei:v3.x.x)
FROM projectdiscovery/nuclei:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Create templates directory for volume mount
RUN mkdir -p /root/nuclei-templates && chmod 755 /root/nuclei-templates

# Copy the Go binary from builder
COPY --from=builder /app/bin/nuclei-scanner /app/nuclei-scanner

# Nuclei base image may require root access for template management
ENTRYPOINT ["/app/nuclei-scanner"]
