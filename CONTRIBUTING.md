# Contributing to VulWall

Thanks for your interest in contributing.

## Development setup

Requirements: Docker with Compose v2, Go (version in `scanner/src/go.mod`)
and the .NET 11 SDK.

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
docker run -d --rm --name vw-test-redis -p 127.0.0.1:6380:6379 redis:8-alpine
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

Demo data and screenshots: `make demo` starts the stack without the scanner and
loads the sample data (see "Demo data" in [README.md](README.md)). The data is
built in `scanner/src/internal/demoseed`; its finding texts are copied from the
scanners, so update them there when a scanner's text changes. Take product
screenshots from this data at 1440x900, device scale 2, in light and dark
mode, and compress them with `pngquant` and `oxipng`.

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

Pull requests are squash-merged, so the PR title becomes the commit message
on `main` and the changelog entry. Use a
[conventional commit](https://www.conventionalcommits.org/) title, for
example `fix(web): keep the asset list sorted after a scan`:

| Prefix | Changelog section | Version bump before 1.0 |
|--------|-------------------|-------------------------|
| `feat:` | Added | minor (0.1.x to 0.2.0) |
| `fix:`, `revert:` | Fixed | patch |
| `perf:` | Changed | patch |
| `docs:`, `ci:`, `chore:`, `test:`, `build:`, `refactor:`, `style:` | not shown | none |

A `!` after the type (`feat!:`) or a `BREAKING CHANGE:` footer marks a
breaking change. Before 1.0 it bumps the minor version, not the major.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security
issues privately as described in [SECURITY.md](SECURITY.md), not in a public
issue.

## Releases

Maintainers release with
[release-please](https://github.com/googleapis/release-please), from
`.github/workflows/release.yml`:

1. Every push to `main` updates one open pull request, "chore: release
   vX.Y.Z". It adds the changelog entry to `CHANGELOG.md` and the version to
   `.release-please-manifest.json`, from the PR titles merged since the last
   release. To change the text, edit `CHANGELOG.md` on the release branch
   (the changelog) and the PR description (the GitHub Release notes).
   release-please rewrites both on every push to `main`, so make the edits
   just before you merge.
2. Merging the release PR creates the tag `vX.Y.Z` and a draft GitHub
   Release with the changelog entry as notes.
3. The same workflow run builds and pushes the multi-arch images to
   `ghcr.io/vulwall/{scanner,web}`, attests their build provenance, attaches
   `docker-compose.yml`, `env.example`, `vulwall` and `SHA256SUMS` to the
   release and publishes it. The installer downloads from the latest
   release, so the release stays a draft until its files are attached.
   Only the highest stable version gets the `latest` image tag and the
   "Latest" release mark; the `X.Y` image tag goes to the highest patch of
   that line. A fix released for an older line does not move them.

The release PR is opened with the workflow's `GITHUB_TOKEN`, and pull
requests opened that way do not start CI. The PR has no required checks, so
merge it with the admin bypass. It changes only `CHANGELOG.md` and
`.release-please-manifest.json`. Before you merge, read the `CHANGELOG.md`
diff: the text comes from PR titles and descriptions, so look for HTML or
other markup and for a version bump you did not expect.

To run CI on the release PR instead, store a GitHub App or fine-grained
token with contents, pull requests and issues write access as the
`RELEASE_PLEASE_TOKEN` secret; the workflow uses it when it exists.

The repository setting "Allow GitHub Actions to create and approve pull
requests" (Settings > Actions > General) must be on, or release-please
cannot open the PR.

If the image or release job fails, use "Re-run failed jobs" on that run.
"Re-run all jobs" does not work: release-please has already created the
release, so it finds nothing new and the later jobs are skipped. In that
case, or to build and publish any existing tag by hand, run the workflow
with the tag:

```bash
gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z
```

It completes the draft release for that tag, or creates a release when none
exists. `--ref` runs the workflow file from that tag, so the build
provenance records the tag and its commit; this works for tags created
after release-please was set up (v0.1.1 and older have no manual trigger).
Tags pushed by hand do not start a release on their own.

To release a specific version, for example 1.0.0, add a `Release-As: 1.0.0`
footer to the squash commit message of a PR.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), the same license as the rest of VulWall.
