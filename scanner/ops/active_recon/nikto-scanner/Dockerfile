# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download
# Copy source code
COPY . .
# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o nikto-scanner ./cmd/active_recon/nikto-scanner

# Stage 2: Use Alpine base with Nikto installed
FROM alpine:3.20.3

LABEL version="1.0.0" \
      author="VulWall Team" \
      description="Nikto web vulnerability scanner service"

WORKDIR /root/

# Install Nikto dependencies and CA certificates
RUN echo 'Installing packages for Nikto.' && \
    apk add --update --no-cache --virtual .build-deps \
        perl \
        perl-net-ssleay \
        git && \
    apk add --no-cache ca-certificates && \
    echo 'Installing Nikto from GitHub.' && \
    git clone https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto.pl && \
    apk del git && \
    rm -rf /var/cache/apk/*

# Copy the Go binary from builder
COPY --from=builder /app/nikto-scanner .

# Run the scanner binary (not nikto.pl directly)
ENTRYPOINT ["./nikto-scanner"]
CMD []
