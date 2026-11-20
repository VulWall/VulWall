#!/bin/sh
# VulWall installer: https://vulwall.com/install.sh
#
#   curl -fsSL https://vulwall.com/install.sh | sh
#
# Downloads the compose file of a VulWall release into $VULWALL_DIR (default
# ~/vulwall), creates .env on the first run, and starts the stack with Docker
# Compose. Run it again to upgrade. It never uses sudo and never deletes data.
#
# Environment:
#   VULWALL_DIR       install directory (default: $HOME/vulwall)
#   VULWALL_VERSION   release to install, e.g. 0.1.0 (default: the latest release)
#   VULWALL_BASE_URL  download the release files from this URL instead of GitHub
#
# Source: https://github.com/VulWall/VulWall/blob/main/install.sh (MIT)

set -eu

REPO_URL=https://github.com/VulWall/VulWall

say() { printf '%s\n' "$*"; }
err() { printf 'Error: %s\n' "$*" >&2; }
die() { err "$@"; exit 1; }

check_docker() {
    command -v docker >/dev/null 2>&1 ||
        die "Docker is not installed. Install Docker Engine or Docker Desktop first: https://docs.docker.com/get-docker/"
    docker compose version >/dev/null 2>&1 </dev/null ||
        die "Docker Compose v2 ('docker compose') is not available. Install the Compose plugin: https://docs.docker.com/compose/install/"
    docker info >/dev/null 2>&1 </dev/null ||
        die "Cannot reach the Docker daemon. Start Docker, and make sure your user may use it (for example, add it to the 'docker' group on Linux)."
}

download() { # url file
    curl -fsSL --proto '=https,http' --retry 3 -o "$2" "$1" ||
        die "Download failed: $1"
}

sha256_check() { # run in the directory that holds SHA256SUMS
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c SHA256SUMS >/dev/null 2>&1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c SHA256SUMS >/dev/null 2>&1
    else
        die "Neither sha256sum nor shasum is installed; cannot verify the download."
    fi
}

compose() {
    docker compose "$@" </dev/null
}

wait_for_web() {
    i=0
    while [ "$i" -lt 60 ]; do
        id=$(compose ps -q web 2>/dev/null || true)
        if [ -n "$id" ]; then
            status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null </dev/null || true)
            [ "$status" = healthy ] && return 0
        fi
        i=$((i + 1))
        sleep 5
    done
    return 1
}

main() {
    command -v curl >/dev/null 2>&1 || die "curl is not installed."
    check_docker

    dir=${VULWALL_DIR:-$HOME/vulwall}
    version=${VULWALL_VERSION:-}
    version=${version#v}
    if [ -n "${VULWALL_BASE_URL:-}" ]; then
        base=${VULWALL_BASE_URL%/}
    elif [ -n "$version" ]; then
        base=$REPO_URL/releases/download/v$version
    else
        base=$REPO_URL/releases/latest/download
    fi

    mkdir -p "$dir"
    cd "$dir"

    # Download into a temporary directory and verify before anything in $dir
    # changes, so a failed or tampered download leaves an existing install as it was.
    tmp=$(mktemp -d "$dir/.download.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    trap 'exit 130' INT TERM
    say "Downloading VulWall ${version:-(latest release)} from $base"
    download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
    download "$base/docker-compose.yml" "$tmp/docker-compose.yml"
    download "$base/env.example" "$tmp/env.example"
    (cd "$tmp" && sha256_check) ||
        die "Checksum verification failed. Nothing was changed in $dir."

    mv "$tmp/docker-compose.yml" docker-compose.yml
    mv "$tmp/env.example" .env.example
    if [ -f .env ]; then
        say "Keeping your existing $dir/.env"
    else
        (umask 077 && cp .env.example .env)
        say "Created $dir/.env (edit it to change settings)"
    fi

    say "Pulling images (the first time this takes a few minutes)..."
    compose pull --quiet || die "docker compose pull failed."
    compose up -d --remove-orphans || die "docker compose up failed. See: cd $dir && docker compose logs"

    say "Waiting for the web app to become healthy..."
    wait_for_web ||
        die "The web app did not become healthy within 5 minutes. See: cd $dir && docker compose logs web"

    hostport=$(compose port web 8080 2>/dev/null || true)
    port=${hostport##*:}
    port=${port:-8080}

    admins=$(compose exec -T mongo mongosh vulwall --quiet --eval 'db.users.countDocuments({_id:"admin"})' 2>/dev/null || true)
    say ""
    if [ "$admins" = 1 ]; then
        say "VulWall is running. Log in at http://localhost:$port/login"
    else
        id=$(compose ps -q web)
        started=$(docker inspect -f '{{.State.StartedAt}}' "$id" </dev/null)
        link=$(compose logs --no-color --no-log-prefix --since "$started" web 2>/dev/null |
            grep 'First-run setup' | tail -n 1 |
            sed -n 's|.*\(http://localhost:[0-9]*/setup?token=[^ ]*\).*|\1|p' || true)
        if [ -n "$link" ]; then
            link=$(printf '%s' "$link" | sed "s|^http://localhost:[0-9]*|http://localhost:$port|")
            say "VulWall is running. Open this link to create the admin account:"
            say ""
            say "  $link"
            say ""
            say "The link works only until the web container restarts. To print a new one:"
            say "  cd $dir && docker compose logs web | grep 'First-run setup' | tail -1"
        else
            say "VulWall is running, but the setup link was not found in the log. Print it with:"
            say "  cd $dir && docker compose logs web | grep 'First-run setup' | tail -1"
        fi
    fi

    say ""
    say "The web UI listens on 127.0.0.1:$port only. To reach it from other machines,"
    say "put a TLS reverse proxy in front: https://vulwall.com/docs/configuration/reverse-proxy/"
    say ""
    say "Next steps:"
    say "  Settings:   edit $dir/.env, then: cd $dir && docker compose up -d"
    say "  Upgrade:    run this installer again"
    say "  Logs:       cd $dir && docker compose logs -f"
    say "  Stop:       cd $dir && docker compose down     (keeps your data)"
    say "  Uninstall:  cd $dir && docker compose down -v && cd && rm -rf $dir"
    say "              (deletes all VulWall data)"
    say "Docs: https://vulwall.com/docs/"
}

# Everything runs from here, so a partly downloaded script does nothing.
main "$@"
