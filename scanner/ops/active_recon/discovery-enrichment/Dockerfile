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

# Copy DBIP ISP/Country database for IP geolocation enrichment
# To enable geolocation: place dbip-isp-country.mmdb in data/ directory before building
COPY --from=builder /app/data/dbip-isp-country.mmdb ./data/dbip-isp-country.mmdb

# Run the binary
CMD ["./discovery-enrichment"]
