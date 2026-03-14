# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Install CA certificates in builder (testssl.sh image lacks package manager)
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/testssl-scanner ./cmd/active_recon/testssl-scanner

# Stage 2: Use drwetter/testssl.sh official image as base
# TODO: Pin to a specific version when stable (e.g., drwetter/testssl.sh:3.2)
FROM drwetter/testssl.sh:latest

# testssl.sh image requires root for cert access and tool execution
USER root

WORKDIR /app

# Copy CA certificates from builder (testssl.sh image lacks package manager)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the Go binary from builder
COPY --from=builder /app/bin/testssl-scanner /app/testssl-scanner

# Make sure testssl.sh is executable and in PATH
RUN chmod +x /usr/local/bin/testssl.sh || chmod +x /home/testssl/testssl.sh

ENTRYPOINT ["/app/testssl-scanner"]
