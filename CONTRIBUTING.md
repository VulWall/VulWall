# Contributing to VulWall

Thanks for your interest in contributing.

## Contributor License Agreement (CLA)

A signed Contributor License Agreement is **required** before any
contribution can be merged. The CLA lets the project maintainer distribute
VulWall under the AGPL-3.0 and under other licenses. You keep the copyright to
your contribution.

Details on how to sign the CLA will be published in this file. Until then,
please open an issue before you start work on a pull request.

## Workflow

1. Open an issue that describes the bug or feature.
2. Fork https://github.com/VulWall/VulWall and create a branch from `main`.
3. Keep changes focused. Add tests for what you change.
4. Make sure the builds and tests pass:
   - `cd scanner && make build && make test`
   - `cd web/src && dotnet build VulWall.Dashboard.csproj`
   - `cd web/tests/VulWall.Dashboard.Tests && dotnet test`
5. Open a pull request that references the issue.

## License

By contributing, you agree that your contributions are licensed under the
GNU Affero General Public License v3.0 (see [LICENSE](LICENSE)) and under the
terms of the CLA.
