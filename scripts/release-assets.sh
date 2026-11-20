#!/bin/sh
# Builds the files that install.sh downloads from a GitHub Release:
#
#   docker-compose.yml  root compose file without build: sections, with the
#                       scanner and web images pinned to VERSION (and to their
#                       digests when SCANNER_DIGEST and WEB_DIGEST are set)
#   env.example         copy of .env.example (GitHub renames release assets
#                       that start with a period, so the asset has none)
#   vulwall             the helper command (copy of scripts/vulwall), which
#                       install.sh puts in the install directory
#   SHA256SUMS          checksums of the three files above
#
# Usage: scripts/release-assets.sh VERSION OUTDIR [IMAGE_PREFIX]
#   VERSION       image tag, e.g. 0.1.0 (a leading "v" is removed)
#   OUTDIR        directory for the output files (created if missing)
#   IMAGE_PREFIX  registry and namespace of the images (default ghcr.io/vulwall)
#
# Environment:
#   SCANNER_DIGEST, WEB_DIGEST  image digests (sha256:<64 hex>). Set both or
#                               neither; the release workflow always sets them.
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

scanner_digest=${SCANNER_DIGEST:-}
web_digest=${WEB_DIGEST:-}
if [ -n "$scanner_digest$web_digest" ]; then
    for d in "$scanner_digest" "$web_digest"; do
        if ! printf '%s\n' "$d" | grep -Eqx 'sha256:[0-9a-f]{64}'; then
            echo "SCANNER_DIGEST and WEB_DIGEST must both be sha256:<64 hex>" >&2
            exit 2
        fi
    done
    scanner_digest=@$scanner_digest
    web_digest=@$web_digest
fi

mkdir -p "$outdir"

VERSION=$version PREFIX=$prefix SCANNER_PIN=$scanner_digest WEB_PIN=$web_digest yq '
    del(.services[].build) |
    .services.scanner.image = strenv(PREFIX) + "/scanner:" + strenv(VERSION) + strenv(SCANNER_PIN) |
    .services.web.image = strenv(PREFIX) + "/web:" + strenv(VERSION) + strenv(WEB_PIN) |
    . head_comment = "VulWall " + strenv(VERSION) + " release compose file, generated from docker-compose.yml.\nThe installer (https://vulwall.com/install.sh) replaces this file on every run;\nput your own changes in docker-compose.override.yml.\n\n" + (. | head_comment)
' "$root/docker-compose.yml" > "$outdir/docker-compose.yml"

cp "$root/.env.example" "$outdir/env.example"
cp "$root/scripts/vulwall" "$outdir/vulwall"
chmod 755 "$outdir/vulwall"

cd "$outdir"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum docker-compose.yml env.example vulwall > SHA256SUMS
else
    shasum -a 256 docker-compose.yml env.example vulwall > SHA256SUMS
fi
