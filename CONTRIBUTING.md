# Contributing to VulWall

Thanks for your interest in contributing.

## Contributor License Agreement (CLA)

A signed Contributor License Agreement is **required** before any
contribution can be merged. You keep the copyright to your contribution. The
CLA gives the maintainer a licence to use it, including under licences other
than the AGPL-3.0 (for example in a hosted or proprietary version).

Read the CLA:
https://gist.github.com/MojtabaTajik/ce612d57278e3c98020a652120244dc6

You sign it once, on your first pull request: the CLA Assistant bot posts a
comment with a link, and you accept with your GitHub account. The check on
the pull request turns green after you sign.

**CLA privacy note.** To manage the CLA we use CLA Assistant
(cla-assistant.io), operated by SAP. When you sign, CLA Assistant records your
GitHub username and user ID, the CLA version, and the date and time of
signing. The controller is Moji Tajik, legal@example.com. We use this data
only to prove that the CLA covers your contribution (legal basis: GDPR
Art. 6(1)(b) and (f), our legitimate interest in proving that we have the
right to use contributions). We keep it for as long as your contribution can
be used in VulWall, because the licence is permanent. You can ask for access
to the data and use your other rights under GDPR Arts. 15–21 (including the
right to object), and you can complain to your data protection authority. We
will not delete a signature while it is needed to prove the licence.

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
GNU Affero General Public License v3.0 only (`AGPL-3.0-only`, see
[LICENSE](LICENSE)) and under the terms of the CLA.
