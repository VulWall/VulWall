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
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o waf-detector ./cmd/active_recon/waf-detector

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/waf-detector .

# Copy WAF rules JSON file
COPY --from=builder /app/internal/active_recon/waf_detector/patterns/waf_rules.json ./internal/active_recon/waf_detector/patterns/

# Run the binary
CMD ["./waf-detector"]
