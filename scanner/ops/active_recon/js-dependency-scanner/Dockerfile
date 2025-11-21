# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/js-dependency-scanner ./cmd/active_recon/js-dependency-scanner

# Runtime stage - Node.js for retire.js
FROM node:18-alpine

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Install retire.js globally
RUN npm install -g retire@5.2.4

# Copy the binary from builder
COPY --from=builder /app/bin/js-dependency-scanner /app/js-dependency-scanner

# Create temp directory for JS file downloads
RUN mkdir -p /tmp/retire-scan && chmod 777 /tmp/retire-scan

# Run as non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser

USER appuser

ENTRYPOINT ["/app/js-dependency-scanner"]
