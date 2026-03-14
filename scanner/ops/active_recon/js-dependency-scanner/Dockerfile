FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/js-dependency-scanner ./cmd/active_recon/js-dependency-scanner

# Runtime stage - Node.js for retire.js
FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache ca-certificates && \
    npm install -g retire@5.4.2

# Create temp directory for JS file downloads
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser && \
    mkdir -p /tmp/retire-scan && chown appuser:appgroup /tmp/retire-scan

COPY --from=builder /app/bin/js-dependency-scanner /app/js-dependency-scanner
USER appuser
ENTRYPOINT ["/app/js-dependency-scanner"]
