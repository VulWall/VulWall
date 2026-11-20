---
title: Contributing
description: Set up a development environment and send changes to VulWall.
---

Contributions are welcome: bug reports, fixes, new scanners and documentation.

## License of contributions

VulWall accepts contributions under the
[MIT License](https://github.com/VulWall/VulWall/blob/main/LICENSE), the license of the project.
You keep the copyright to your contribution.

## Development setup

You need Docker with Compose v2, Go (the version in `scanner/src/go.mod`) and the .NET 10 SDK.
For this website you also need Node.js.

Run the whole stack from source:

```sh
git clone https://github.com/VulWall/VulWall.git && cd VulWall
cp .env.example .env
docker compose up -d --build
```

### Scanner (Go)

```sh
cd scanner
make build test vet        # builds src/bin/nightwatch, runs go test and go vet
```

`make run` starts the scanner on your machine. It needs Redis and MongoDB (for example the
compose services, with their ports published through a `docker-compose.override.yml`) and, for
full scans, `nuclei`, `testssl.sh` and `retire` on your `PATH`.

### Web app (.NET)

```sh
cd web/src && dotnet build VulWall.Dashboard.csproj
cd web/tests/VulWall.Dashboard.Tests && dotnet test
```

The tests start a temporary MongoDB, which downloads a `mongod` binary on the first run.

### Website

This site is in `site/` and is built with [Astro Starlight](https://starlight.astro.build):

```sh
cd site
npm ci
npm run dev
```

## Workflow

1. Open an issue that describes the bug or the feature.
2. Fork [VulWall/VulWall](https://github.com/VulWall/VulWall) and create a branch from `main`.
3. Keep changes focused, and add tests for what you change.
4. Check that the builds and tests pass:
   - `cd scanner && make build && make test`
   - `cd web/src && dotnet build VulWall.Dashboard.csproj`
   - `cd web/tests/VulWall.Dashboard.Tests && dotnet test`
   - `docker compose config -q`
5. Open a pull request that refers to the issue.

Follow the [Code of Conduct](https://github.com/VulWall/VulWall/blob/main/CODE_OF_CONDUCT.md).
Report security issues privately, as described in [Security](/docs/security/).
