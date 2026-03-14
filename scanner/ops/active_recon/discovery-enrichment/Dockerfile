FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/discovery-enrichment ./cmd/active_recon/discovery-enrichment

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
WORKDIR /app

# Create data directory for MMDB volume mount
# Mount the DBIP ISP/Country database at runtime: -v /path/to/dbip-isp-country.mmdb:/app/data/dbip-isp-country.mmdb
RUN mkdir -p ./data && chown appuser:appgroup ./data

COPY --from=builder /app/bin/discovery-enrichment /app/discovery-enrichment

# Copy WAF rules JSON file
COPY --from=builder /app/internal/active_recon/discovery_enrichment/waf/patterns/waf_rules.json ./internal/active_recon/discovery_enrichment/waf/patterns/

USER appuser
ENTRYPOINT ["/app/discovery-enrichment"]
