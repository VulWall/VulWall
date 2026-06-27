FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" \
    -o /app/bin/domain-discovery ./cmd/discoveries/domain-discovery

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
WORKDIR /app
COPY --from=builder /app/bin/domain-discovery /app/domain-discovery
# subfinder's runner.NewRunner writes a default provider-config under $HOME/.config/subfinder.
# The container runs as nonroot and /home/appuser may not be writable.
ENV HOME=/tmp
USER appuser
ENTRYPOINT ["/app/domain-discovery"]
