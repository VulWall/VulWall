# Contributing to VulWall

Thanks for your interest in contributing.

## Contributor License Agreement (CLA)

A signed Contributor License Agreement is **required** before any
contribution can be merged. The CLA lets the project maintainer distribute
VulWall under the AGPL-3.0 and under other licenses. You keep the copyright to
your contribution.

Details on how to sign the CLA will be published in this file. Until then,
please open an issue before you start work on a pull request.

## Development setup

Requirements: Docker with Compose v2, Go (version in `scanner/src/go.mod`)
and the .NET 10 SDK.

Run the whole stack from source:

```bash
cp .env.example .env
docker compose up -d --build
```

Work on the scanner:

```bash
cd scanner
make build test vet        # src/bin/nightwatch, go test, go vet
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
GNU Affero General Public License v3.0 (see [LICENSE](LICENSE)) and under the
terms of the CLA.
