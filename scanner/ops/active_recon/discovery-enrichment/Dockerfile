# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o discovery-enrichment ./cmd/active_recon/discovery-enrichment

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/discovery-enrichment .

# Copy WAF rules JSON file
COPY --from=builder /app/internal/active_recon/discovery_enrichment/waf/patterns/waf_rules.json ./internal/active_recon/discovery_enrichment/waf/patterns/

# Create data directory for MMDB volume mount
# Mount the DBIP ISP/Country database at runtime: -v /path/to/dbip-isp-country.mmdb:/root/data/dbip-isp-country.mmdb
RUN mkdir -p ./data

# Run the binary
CMD ["./discovery-enrichment"]
