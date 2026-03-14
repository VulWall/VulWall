FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/http-header-scanner ./cmd/active_recon/http-header-scanner

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
WORKDIR /app
COPY --from=builder /app/bin/http-header-scanner /app/http-header-scanner
USER appuser
ENTRYPOINT ["/app/http-header-scanner"]
