#!/bin/sh
# Builds the files that install.sh downloads from a GitHub Release:
#
#   docker-compose.yml  root compose file without build: sections, with the
#                       scanner and web images pinned to VERSION
#   env.example         copy of .env.example (GitHub renames release assets
#                       that start with a period, so the asset has none)
#   SHA256SUMS          checksums of the two files above
#
# Usage: scripts/release-assets.sh VERSION OUTDIR [IMAGE_PREFIX]
#   VERSION       image tag, e.g. 0.1.0 (a leading "v" is removed)
#   OUTDIR        directory for the output files (created if missing)
#   IMAGE_PREFIX  registry and namespace of the images (default ghcr.io/vulwall)
#
# Needs mikefarah yq v4 (preinstalled on GitHub's Ubuntu runners).
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 VERSION OUTDIR [IMAGE_PREFIX]" >&2
    exit 2
fi

version=${1#v}
outdir=$2
prefix=${3:-ghcr.io/vulwall}
root=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$outdir"

VERSION=$version PREFIX=$prefix yq '
    del(.services[].build) |
    .services.scanner.image = strenv(PREFIX) + "/scanner:" + strenv(VERSION) |
    .services.web.image = strenv(PREFIX) + "/web:" + strenv(VERSION) |
    . head_comment = "VulWall " + strenv(VERSION) + " release compose file, generated from docker-compose.yml.\nThe installer (https://vulwall.com/install.sh) replaces this file on every run;\nput your own changes in docker-compose.override.yml.\n\n" + (. | head_comment)
' "$root/docker-compose.yml" > "$outdir/docker-compose.yml"

cp "$root/.env.example" "$outdir/env.example"

cd "$outdir"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum docker-compose.yml env.example > SHA256SUMS
else
    shasum -a 256 docker-compose.yml env.example > SHA256SUMS
fi
