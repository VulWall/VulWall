# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download
# Copy source code
COPY . .
# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o nuclei-scanner ./cmd/active_recon/nuclei-scanner

# Stage 2: Use ProjectDiscovery's official Nuclei image
FROM projectdiscovery/nuclei:latest

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy the Go binary from builder
COPY --from=builder /app/nuclei-scanner .

# Override the default entrypoint and run our scanner binary
ENTRYPOINT ["./nuclei-scanner"]
CMD []