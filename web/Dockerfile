# Build context: web/  (docker build -t vulwall-web web/)

# The SDK stage runs on the build machine's own architecture and cross-compiles for the target,
# so a multi-arch build does not run the SDK under QEMU emulation.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

# Restore first so the package layer is cached across source changes
COPY src/VulWall.Dashboard.csproj src/
RUN dotnet restore src/VulWall.Dashboard.csproj -a "$TARGETARCH"

COPY src/ src/
RUN dotnet publish src/VulWall.Dashboard.csproj -c Release -a "$TARGETARCH" -o /app/out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

# curl is only used by the container healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/out .

# Data-protection keys (auth cookies) live on a web-only volume, not in the shared database.
# Created here so the mounted named volume inherits the non-root owner.
RUN mkdir -p /data/keys && chown "$APP_UID" /data/keys

ENV PORT=8080
ENV DATA_PROTECTION_KEYS_DIR=/data/keys
EXPOSE 8080

# Built-in non-root user of the official .NET images
USER $APP_UID

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["dotnet", "VulWall.Dashboard.dll"]
