FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ingestion ./cmd/ingestion

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/ingestion .

# Create data directory for MMDB volume mount
# Mount the DBIP ISP/Country database at runtime: -v /path/to/dbip-isp-country.mmdb:/root/data/dbip-isp-country.mmdb
RUN mkdir -p ./data

# Run the binary
CMD ["./ingestion"]
