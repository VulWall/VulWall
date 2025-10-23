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

# Stage 2: Install Nuclei and create final image
FROM alpine:latest

# Install ca-certificates and dependencies for Nuclei
RUN apk --no-cache add ca-certificates wget unzip curl bash

WORKDIR /root/

# Install Nuclei using the official installation script
RUN wget -qO - https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | sh -s -- -b /usr/local/bin

# Update Nuclei templates
RUN nuclei -update-templates

# Copy the Go binary from builder
COPY --from=builder /app/nuclei-scanner .

# Run the binary
CMD ["./nuclei-scanner"]
