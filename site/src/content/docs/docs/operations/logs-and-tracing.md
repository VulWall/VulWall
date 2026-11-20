---
title: Logs and tracing
description: Read VulWall's logs and turn on OpenTelemetry tracing with Jaeger.
---

## Logs

Each container logs to standard output. With the `vulwall` command:

```sh
vulwall logs                      # everything
vulwall logs scanner              # scan progress and scanner errors
vulwall status                    # container status and health
vulwall doctor                    # health, and whether the scanner can reach the internet
```

Or with Docker Compose, from the install directory:

```sh
docker compose logs -f            # everything
docker compose logs -f scanner    # scan progress and scanner errors
docker compose logs -f web        # web app, including the first-run setup link
docker compose ps                 # container status and health
```

The scanner runs all of its components in one process. Each log line has a `component` field,
for example `nuclei-scanner` or `scan-coordinator`, so you can filter by it:

```sh
docker compose logs scanner | grep nuclei-scanner
```

## Tracing

The scanner can export OpenTelemetry traces. Tracing is off by default. The compose file has a
`tracing` profile that runs Jaeger next to VulWall:

```sh
echo "OTEL_ENABLED=true" >> .env
docker compose --profile tracing up -d
```

Open the Jaeger UI at http://localhost:16686 and select the `vulwall-scanner` service. A trace
follows a scan through the pipeline, across the Redis streams between the components.

The Jaeger UI is bound to `127.0.0.1` (port `JAEGER_UI_PORT`). Traces include your host names and
findings, so do not publish it.

### Other backends

Any OTLP/HTTP backend works: Grafana Tempo, an OpenTelemetry Collector or a hosted service.

```sh
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.example.com
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <token>
```

The scanner also reads the standard `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` and
`OTEL_RESOURCE_ATTRIBUTES` variables. To use them, add them to the scanner's `environment` in a
`docker-compose.override.yml`.
