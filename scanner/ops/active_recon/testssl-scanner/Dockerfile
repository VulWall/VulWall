# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download
# Copy source code
COPY . .
# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o testssl-scanner ./cmd/active_recon/testssl-scanner

# Stage 2: Use drwetter/testssl.sh official image as base
FROM drwetter/testssl.sh:latest

# Switch to root to install our binary
USER root

WORKDIR /root/

# Copy the Go binary from builder
COPY --from=builder /app/testssl-scanner .

# Make sure testssl.sh is executable and in PATH
# The official image should already have this, but let's be explicit
RUN chmod +x /usr/local/bin/testssl.sh || chmod +x /home/testssl/testssl.sh

# Run our scanner binary as entrypoint (not testssl.sh directly)
ENTRYPOINT ["./testssl-scanner"]
CMD []
