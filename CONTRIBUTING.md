# Contributing to VulWall

Thanks for your interest in contributing.

## Development setup

Requirements: Docker with Compose v2, Go (version in `scanner/src/go.mod`)
and the .NET 10 SDK.

Run the whole stack from source:

```bash
cp .env.example .env
make up                    # docker compose up -d --build
```

`make build` builds the images without starting them. Both targets set
`VULWALL_BUILD_VERSION` to `dev (<short commit>)`, so the About dialog shows
which commit you run. A plain `docker compose build` shows `dev`; to set the
version yourself:

```bash
VULWALL_BUILD_VERSION="dev ($(git rev-parse --short HEAD))" docker compose build
```

Work on the scanner:

```bash
cd scanner
make build test vet        # src/bin/nightwatch, go test, go vet
```

Some scanner tests need a real MongoDB and Redis and skip without them. Run
them against throwaway containers, one package at a time (`-p 1`): tests in
different packages share streams such as `security_findings`, so parallel
packages read each other's messages. CI runs them the same way.

```bash
docker run -d --rm --name vw-test-mongo -p 127.0.0.1:27018:27017 mongo:7
docker run -d --rm --name vw-test-redis -p 127.0.0.1:6380:6379 redis:7-alpine
cd scanner/src
VULWALL_TEST_MONGO_URI=mongodb://127.0.0.1:27018 \
VULWALL_TEST_REDIS_URI=redis://127.0.0.1:6380/0 \
  go test -race -count=1 -p 1 ./...
docker rm -f vw-test-mongo vw-test-redis
```

`make run` starts the scanner on your machine. It needs Redis and MongoDB
(for example the compose services with their ports published through a
`docker-compose.override.yml`) and, for full scans, `nuclei`, `testssl.sh` and
`retire` on `PATH`. See [scanner/CLAUDE.md](scanner/CLAUDE.md) and
`scanner/docs/` for the architecture.

Work on the web app:

```bash
cd web/src && dotnet build VulWall.Dashboard.csproj
cd web/tests/VulWall.Dashboard.Tests && dotnet test
```

AI coding agents: `.claude/skills/vulwall-design/` holds the VulWall design
system (tokens, components, brand rules). Use it for any UI change in `web/`.

## Workflow

1. Open an issue that describes the bug or feature.
2. Fork https://github.com/VulWall/VulWall and create a branch from `main`.
3. Keep changes focused. Add tests for what you change.
4. Make sure the builds and tests pass:
   - `cd scanner && make build && make test`
   - `cd web/src && dotnet build VulWall.Dashboard.csproj`
   - `cd web/tests/VulWall.Dashboard.Tests && dotnet test`
   - `docker compose config -q`
5. Open a pull request that references the issue.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security
issues privately as described in [SECURITY.md](SECURITY.md), not in a public
issue.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), the same license as the rest of VulWall.
