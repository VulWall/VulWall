# syntax=docker/dockerfile:1
#
# VulWall scanner image: the nightwatch binary plus the external tools it runs
# (nuclei, testssl.sh, retire.js). Build context: scanner/
#
#   docker build -t ghcr.io/vulwall/scanner ./scanner
#
# Tool versions are pinned. To upgrade nuclei, change NUCLEI_VERSION and both
# checksums (from nuclei_<version>_checksums.txt on the release page).

# Base images are pinned by multi-arch index digest; Dependabot bumps tag and digest together.
ARG GO_IMAGE=golang:1.26.10-alpine3.24@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696
ARG RUNTIME_IMAGE=alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# Tool versions are declared once here and redeclared in each stage that uses them.
# The runtime stage exports them so the scanner can report them (system_info).
ARG NUCLEI_VERSION=3.11.1
ARG TESTSSL_TAG=v3.2.5
# Release builds pass the tag (release.yml).
ARG VULWALL_VERSION=dev

# ---------------------------------------------------------------------------
# Go binary (cross-compiled on the build platform for multi-arch builds)
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY src/ ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nightwatch ./cmd/nightwatch

# ---------------------------------------------------------------------------
# Third-party tools, downloaded and verified
FROM ${RUNTIME_IMAGE} AS tools
ARG TARGETARCH
ARG NUCLEI_VERSION
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG TESTSSL_TAG
ARG TESTSSL_COMMIT=4f17be931a9d60f3f987975aea8221f1a8eaf7aa
RUN apk add --no-cache curl unzip git
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sha="$NUCLEI_SHA256_AMD64" ;; \
      arm64) sha="$NUCLEI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    zip="nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSL -o "/tmp/$zip" "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/$zip"; \
    echo "$sha  /tmp/$zip" | sha256sum -c -; \
    mkdir -p /out/bin; \
    unzip -o "/tmp/$zip" nuclei -d /out/bin; \
    chmod 0755 /out/bin/nuclei
RUN set -eu; \
    git clone --quiet --depth 1 --branch "$TESTSSL_TAG" https://github.com/testssl/testssl.sh.git /tmp/testssl; \
    test "$(git -C /tmp/testssl rev-parse HEAD)" = "$TESTSSL_COMMIT"; \
    mkdir -p /out/testssl; \
    cp -r /tmp/testssl/testssl.sh /tmp/testssl/etc /tmp/testssl/LICENSE /out/testssl/

# ---------------------------------------------------------------------------
# Runtime
FROM ${RUNTIME_IMAGE}
ARG NUCLEI_VERSION
ARG TESTSSL_TAG
ARG VULWALL_VERSION

# retire.js and its whole dependency tree are pinned with integrity hashes in
# docker/retire/package-lock.json (Dependabot updates it); npm ci installs exactly that.
COPY docker/retire/package.json docker/retire/package-lock.json /opt/retire/

# testssl.sh needs bash, coreutils, procps, openssl, a DNS tool and xxd.
# retire.js needs node. ca-certificates for every outbound TLS call.
RUN set -eu; \
    apk add --no-cache ca-certificates tzdata curl bash coreutils procps openssl \
        bind-tools libidn socat xxd nodejs npm; \
    npm ci --prefix /opt/retire --omit=dev --ignore-scripts --no-audit --no-fund; \
    ln -s /opt/retire/node_modules/.bin/retire /usr/local/bin/retire; \
    npm cache clean --force; \
    apk del npm; \
    addgroup -S -g 10001 vulwall; \
    adduser -S -D -u 10001 -G vulwall -h /home/vulwall vulwall; \
    mkdir -p /data/nuclei-templates /data/geo/cloud; \
    chown -R vulwall:vulwall /data

COPY --from=tools /out/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /out/testssl /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
COPY --from=build /out/nightwatch /usr/local/bin/nightwatch
COPY src/internal/active_recon/discovery_enrichment/waf/patterns/waf_rules.json /etc/vulwall/waf_rules.json
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV ENVIRONMENT=production \
    HOME=/home/vulwall \
    NUCLEI_TEMPLATES_DIR=/data/nuclei-templates \
    GEO_DATA_DIR=/data/geo \
    IP_ENRICHMENT_DB_PATH=/data/geo/dbip-country-lite.mmdb \
    IP_ASN_DB_PATH=/data/geo/dbip-asn-lite.mmdb \
    CLOUD_DATA_DIR=/data/geo/cloud \
    WAF_RULES_PATH=/etc/vulwall/waf_rules.json \
    VULWALL_VERSION=$VULWALL_VERSION \
    NUCLEI_VERSION=$NUCLEI_VERSION \
    TESTSSL_VERSION=$TESTSSL_TAG

USER vulwall
WORKDIR /home/vulwall
VOLUME ["/data/nuclei-templates", "/data/geo"]

HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD ["nightwatch", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
