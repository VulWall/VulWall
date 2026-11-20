#!/bin/sh
# VulWall installer: https://vulwall.com/install.sh
#
#   curl -fsSL https://vulwall.com/install.sh | sh
#
# Checks that this host can run VulWall (CPU, memory, disk space, a free port),
# downloads the files of a VulWall release into $VULWALL_DIR (default ~/vulwall)
# and verifies them, creates .env on the first run, adds a random first-run
# setup token to .env if it has none, starts the stack with Docker Compose and
# installs the `vulwall` helper command. Run it again to upgrade. It never
# deletes data. It uses sudo only to install or start Docker, and only after you
# agree.
#
# Environment:
#   VULWALL_DIR             install directory (default: $HOME/vulwall)
#   VULWALL_VERSION         release to install, e.g. 0.1.0 (default: the latest release)
#   VULWALL_PORT            host port of the web UI (default: 8080, or the first
#                           free port from 8081 to 8099 when 8080 is in use)
#   VULWALL_INSTALL_DOCKER  set to 1 to install or start Docker on Linux without asking
#   VULWALL_SKIP_CPU_CHECK  set to 1 to skip the CPU check
#   VULWALL_BASE_URL        download the release files from this https:// URL instead of GitHub
#   VULWALL_ALLOW_HTTP      set to 1 to allow an http:// VULWALL_BASE_URL (local testing only)
#
# Source: https://github.com/VulWall/VulWall/blob/main/install.sh (MIT)

set -eu

REPO_URL=https://github.com/VulWall/VulWall
DOCS_URL=https://vulwall.com/docs

say() { printf '%s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
err() { printf 'Error: %s\n' "$*" >&2; }
die() { err "$@"; exit 1; }

# --- Platform and CPU ---------------------------------------------------------

check_platform() { # os machine; sets $arch
    case $1 in
        MINGW* | MSYS* | CYGWIN*)
            die "This installer does not run in Git Bash, MSYS2 or Cygwin. On Windows, use WSL 2: install it (https://learn.microsoft.com/windows/wsl/install) and Docker, then run the installer in your WSL 2 Linux shell." ;;
        Linux | Darwin) ;;
        *) die "Unsupported operating system: $1. VulWall runs on Linux, on macOS, and on Windows in WSL 2." ;;
    esac
    case $2 in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) die "Unsupported CPU architecture: $2. VulWall runs on 64-bit x86 (amd64) and 64-bit ARM (arm64) only." ;;
    esac
}

# MongoDB 5.0 and later needs AVX on x86-64 and ARMv8.2-A on ARM. These are the
# tests of the official mongo image's docker-entrypoint.sh: on ARM, any of these
# ARMv8.2-A features. Succeeds when the CPU in cpuinfo file $2 qualifies, or
# when the file cannot be read.
cpu_supported() { # arch cpuinfo_file
    [ -r "$2" ] || return 0
    case $1 in
        amd64) grep -qE '^flags.* avx( .*|$)' "$2" ;;
        arm64) grep -qE '^Features.* (fphp|dcpop|sha3|sm3|sm4|asimddp|sha512|sve)( .*|$)' "$2" ;;
    esac
}

cpu_help() { # arch
    case $1 in
        amd64)
            say "This CPU does not support AVX, which MongoDB, VulWall's database, needs."
            say "  - Proxmox VM: set the VM's CPU type to 'host' (Hardware > Processors), then"
            say "    stop and start the VM."
            say "  - VirtualBox, Hyper-V, VMware or another hypervisor: pass the host CPU's AVX"
            say "    instructions through to the VM (for example, CPU model 'host')."
            say "  - A physical CPU without AVX (some Celeron, Pentium and Atom models) cannot"
            say "    run VulWall."
            ;;
        arm64)
            say "This CPU does not implement ARMv8.2-A, which MongoDB, VulWall's database, needs."
            say "  - Raspberry Pi 4 and older (Cortex-A72 and earlier) are not supported."
            say "    A Raspberry Pi 5 works."
            say "  - In a VM, give the VM the host CPU model."
            ;;
    esac
    say "To install anyway, run the installer with VULWALL_SKIP_CPU_CHECK=1."
}

check_cpu() { # cpuinfo_file
    # On macOS, Docker Desktop runs the containers in a VM that MongoDB supports.
    [ "$os" = Linux ] || return 0
    if [ "${VULWALL_SKIP_CPU_CHECK:-}" = 1 ]; then
        warn "Skipping the CPU check (VULWALL_SKIP_CPU_CHECK=1)."
        return 0
    fi
    cpu_supported "$arch" "$1" && return 0
    cpu_help "$arch" >&2
    exit 1
}

# --- Questions ------------------------------------------------------------------

# The script usually runs as "curl ... | sh", so its stdin is the script itself.
# Questions go to the terminal instead.
have_tty() { (: </dev/tty) 2>/dev/null; }

ask_yes() { # question; succeeds on yes. No terminal means no.
    have_tty || return 1
    printf '%s [y/N] ' "$1" >/dev/tty
    read -r reply </dev/tty || return 1
    case $reply in [yY] | [yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# Consent to install or start Docker with sudo.
docker_consent() { # question
    [ "${VULWALL_INSTALL_DOCKER:-}" = 1 ] && return 0
    ask_yes "$1"
}

# --- Docker ---------------------------------------------------------------------

# 1 after this script installed Docker for a user that is not yet in the docker
# group in this session: Docker then runs through sudo until the script ends.
docker_sudo=0

dk() {
    if [ "$docker_sudo" = 1 ]; then
        # sudo resets the environment: pass on what Docker Compose reads from it.
        sudo env ${SETUP_TOKEN+"SETUP_TOKEN=$SETUP_TOKEN"} \
            ${VULWALL_PORT+"VULWALL_PORT=$VULWALL_PORT"} \
            ${COMPOSE_PROJECT_NAME+"COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME"} \
            docker "$@"
    else
        docker "$@"
    fi
}

compose() {
    dk compose "$@" </dev/null
}

# Sets $sudo to the command that runs a command as root ("" for root).
need_root() {
    if [ "$(id -u)" = 0 ]; then
        sudo=
    elif command -v sudo >/dev/null 2>&1; then
        sudo=sudo
    else
        die "This needs root, and sudo is not installed. Run the installer as root, or install Docker yourself: https://docs.docker.com/engine/install/"
    fi
}

as_root() {
    if [ -n "$sudo" ]; then sudo "$@"; else "$@"; fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

start_docker_service() {
    if has_systemd; then
        as_root systemctl enable --now docker </dev/null
    elif command -v service >/dev/null 2>&1; then
        as_root service docker start </dev/null
    else
        return 1
    fi
}

install_docker() {
    need_root
    getdocker=$(mktemp "${TMPDIR:-/tmp}/get-docker.XXXXXX")
    say "Downloading Docker's install script from https://get.docker.com"
    curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 -o "$getdocker" https://get.docker.com ||
        die "Download failed: https://get.docker.com"
    say "Installing Docker Engine with Docker's official script..."
    as_root sh "$getdocker" </dev/null ||
        die "Docker's install script failed. See https://docs.docker.com/engine/install/"
    start_docker_service || warn "Could not start the Docker service. Start it, then run the installer again."
    if [ -n "$sudo" ]; then
        user=$(id -un)
        sudo usermod -aG docker "$user" </dev/null ||
            warn "Could not add $user to the docker group."
        # The new group applies only to new logins.
        docker_sudo=1
    fi
}

compose_help() {
    if [ "$os" = Darwin ]; then
        say "Update Docker Desktop, which includes Docker Compose v2: https://docs.docker.com/desktop/"
    else
        say "Install the Compose plugin: https://docs.docker.com/compose/install/linux/"
    fi
}

ensure_compose() {
    dk compose version >/dev/null 2>&1 </dev/null && return 0
    msg="Docker Compose v2 ('docker compose') is not installed."
    if command -v docker-compose >/dev/null 2>&1; then
        msg="$msg You have the old docker-compose v1, which VulWall does not support."
    fi
    # The docker-compose-plugin package comes from Docker's own package
    # repository, which Docker's install script sets up.
    if [ "$os" = Linux ] && command -v apt-get >/dev/null 2>&1 &&
        apt-cache show docker-compose-plugin >/dev/null 2>&1 </dev/null &&
        docker_consent "$msg Install the docker-compose-plugin package from Docker's repository now (needs sudo)?"; then
        need_root
        as_root apt-get install -y docker-compose-plugin </dev/null ||
            die "Could not install docker-compose-plugin. $(compose_help)"
    elif [ "$os" = Linux ] && command -v dnf >/dev/null 2>&1 &&
        dnf -q list docker-compose-plugin >/dev/null 2>&1 </dev/null &&
        docker_consent "$msg Install the docker-compose-plugin package from Docker's repository now (needs sudo)?"; then
        need_root
        as_root dnf install -y docker-compose-plugin </dev/null ||
            die "Could not install docker-compose-plugin. $(compose_help)"
    else
        die "$msg $(compose_help)"
    fi
    dk compose version >/dev/null 2>&1 </dev/null || die "$msg $(compose_help)"
}

group_help() {
    say "Your user may not use Docker. Add it to the docker group, then log out and back in,"
    say "and run the installer again:"
    say "  sudo usermod -aG docker $(id -un)"
}

ensure_daemon() {
    out=$(dk info 2>&1 </dev/null) && return 0
    case $out in
        *"permission denied"*) die "$(group_help)" ;;
    esac
    if [ "$os" = Darwin ]; then
        die "Cannot reach the Docker daemon. Start Docker Desktop, wait until it is running, and run the installer again."
    fi
    if has_systemd &&
        docker_consent "Docker is installed but not running. Start it now with 'sudo systemctl start docker'?"; then
        need_root
        as_root systemctl start docker </dev/null || die "Could not start Docker."
        out=$(dk info 2>&1 </dev/null) && return 0
        case $out in
            *"permission denied"*) die "$(group_help)" ;;
        esac
    fi
    die "Cannot reach the Docker daemon. Start Docker (for example: sudo systemctl start docker), or run the installer with VULWALL_INSTALL_DOCKER=1 to let it start Docker."
}

ensure_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        if [ "$os" = Darwin ]; then
            die "Docker is not installed. Install Docker Desktop (https://docs.docker.com/desktop/setup/install/mac-install/, or: brew install --cask docker), start it, and run the installer again."
        fi
        if docker_consent "Docker is not installed. Install Docker Engine now using Docker's official script (needs sudo)?"; then
            install_docker
        else
            die "Docker is not installed. Install Docker Engine (https://docs.docker.com/engine/install/) and run the installer again, or run it with VULWALL_INSTALL_DOCKER=1 to let it install Docker with Docker's official script."
        fi
    fi
    ensure_compose
    ensure_daemon
}

# --- Memory and disk ----------------------------------------------------------------

# Prints the free KiB and the mount point of the filesystem that holds path $1,
# or of its nearest existing parent.
disk_free() {
    p=$1
    while [ ! -e "$p" ]; do p=$(dirname "$p"); done
    df -Pk "$p" 2>/dev/null </dev/null | awk 'NR == 2 { print $4, $6 }'
}

check_disk() { # paths...
    seen=
    for p in "$@"; do
        info=$(disk_free "$p") || continue
        kb=${info%% *}
        mnt=${info#* }
        case $kb in '' | *[!0-9]*) continue ;; esac
        case " $seen " in *" $mnt "*) continue ;; esac
        seen="$seen $mnt"
        [ "$kb" -ge $((5 * 1024 * 1024)) ] ||
            warn "Only $((kb / 1024)) MB of disk space is free on $mnt (for $p). VulWall's images and data need at least 5 GB."
    done
}

check_memory() { # bytes
    case $1 in '' | *[!0-9]*) return 0 ;; esac
    mb=$(($1 / 1048576))
    # A machine with 2 GB of RAM shows a bit less to programs.
    [ "$mb" -ge 1800 ] ||
        warn "Docker has $mb MB of memory. VulWall needs at least 2 GB and works best with 4 GB; with less, scans can fail."
}

check_resources() {
    check_memory "$(dk info -f '{{.MemTotal}}' 2>/dev/null </dev/null || true)"
    docker_root=
    # Docker Desktop keeps its data in a VM disk, not on this host's filesystems.
    if [ "$os" = Linux ]; then
        docker_root=$(dk info -f '{{.DockerRootDir}}' 2>/dev/null </dev/null || true)
    fi
    check_disk "$dir" ${docker_root:+"$docker_root"}
}

# --- Downloads ----------------------------------------------------------------------

# Shell-quotes $1 for the commands this script prints.
shquote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Protocols curl may use, also after a redirect. main() widens it only for an
# explicit http:// VULWALL_BASE_URL with VULWALL_ALLOW_HTTP=1.
proto='=https'

download() { # url file
    curl -fsSL --proto "$proto" --proto-redir "$proto" --retry 3 -o "$2" "$1" ||
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

# Saves a docker-compose.yml that was changed after it was installed, before the
# release's file replaces it. .docker-compose.release.yml is the copy of the file
# as installed. Without that copy (an install from before it existed), any
# difference from the new release's file counts as a change.
backup_compose() { # new_compose_file
    [ -f docker-compose.yml ] || return 0
    cmp -s docker-compose.yml "$1" && return 0
    if [ -f .docker-compose.release.yml ] && cmp -s docker-compose.yml .docker-compose.release.yml; then
        return 0
    fi
    bak=docker-compose.yml.bak.$(date +%Y%m%d-%H%M%S)
    [ ! -e "$bak" ] || bak=$bak.$$
    cp -p docker-compose.yml "$bak"
    warn "Your docker-compose.yml was changed after it was installed. It is saved as"
    warn "  $dir/$bak"
    warn "and replaced with the release's file. Put your own changes in"
    warn "  $dir/docker-compose.override.yml"
    warn "which Docker Compose reads automatically and the installer never changes."
}

# --- .env -----------------------------------------------------------------------------

# Prints the value of variable $1 set in .env (the last one wins, as in Docker
# Compose), without surrounding spaces or quotes. Prints nothing if unset.
env_value() {
    [ -f .env ] || return 0
    sed -n "s/^[[:space:]]*\\(export[[:space:]][[:space:]]*\\)\\{0,1\\}$1[[:space:]]*=//p" .env |
        tail -n 1 | tr -d '\r' |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
            -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}

env_setup_token() { env_value SETUP_TOKEN; }

# Appends "name=value" with comment line $3 to .env.
env_append() { # name value comment
    (
        umask 077
        if [ -s .env ] && [ -n "$(tail -c 1 .env)" ]; then
            printf '\n' >> .env
        fi
        printf '\n# %s\n%s=%s\n' "$3" "$1" "$2" >> .env
    ) || die "Could not write $1 to $dir/.env."
}

is_hex32() {
    [ "${#1}" -eq 32 ] || return 1
    case $1 in *[!0-9a-f]*) return 1 ;; esac
}

# Makes sure the web app gets a setup token that this script knows, so it can
# print the setup link without reading the container log. Sets $token.
ensure_setup_token() {
    if [ -n "${SETUP_TOKEN:-}" ]; then
        # Docker Compose prefers the shell's variable over .env.
        token=$SETUP_TOKEN
        say "Using SETUP_TOKEN from your environment"
        return
    fi
    unset SETUP_TOKEN
    token=$(env_setup_token)
    [ -z "$token" ] || return 0

    token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    is_hex32 "$token" || die "Could not generate a setup token from /dev/urandom."
    env_append SETUP_TOKEN "$token" "First-run setup token, generated by install.sh."
    say "Added a first-run setup token to $dir/.env"
}

# --- Port -----------------------------------------------------------------------------

# Succeeds if a program accepts connections on 127.0.0.1:$1. curl exits with 7
# when nothing listens; any other result means that something does.
port_in_use() {
    rc=0
    curl -s -o /dev/null --noproxy '*' --max-time 2 "http://127.0.0.1:$1/" </dev/null || rc=$?
    [ "$rc" -ne 7 ]
}

# Succeeds if this install's web container publishes port $1.
port_is_ours() {
    hostport=$(compose port web 8080 2>/dev/null || true)
    [ "${hostport##*:}" = "$1" ]
}

# Picks the host port of the web UI. A port that you set must be free or ours.
# Without one, 8080 is used if it is free or ours, else the first free port from
# 8081 to 8099, which is then saved in .env.
choose_port() {
    p=${VULWALL_PORT:-}
    from="your environment"
    if [ -z "$p" ]; then
        p=$(env_value VULWALL_PORT)
        from="$dir/.env"
    fi
    if [ -n "$p" ]; then
        case $p in *[!0-9]* | 0*) die "VULWALL_PORT in $from is not a port number: $p" ;; esac
        [ "$p" -le 65535 ] || die "VULWALL_PORT in $from is not a port number: $p"
        if port_in_use "$p" && ! port_is_ours "$p"; then
            die "Port $p (VULWALL_PORT in $from) is in use by another program. Stop that program, or set VULWALL_PORT to a free port in $from, and run the installer again."
        fi
        return 0
    fi
    if ! port_in_use 8080 || port_is_ours 8080; then
        return 0
    fi
    p=8081
    while [ "$p" -le 8099 ]; do
        if ! port_in_use "$p"; then
            env_append VULWALL_PORT "$p" "Web UI port, picked by install.sh because 8080 was in use."
            say "Port 8080 is in use by another program, so VulWall uses port $p."
            say "It is saved as VULWALL_PORT in $dir/.env."
            return 0
        fi
        p=$((p + 1))
    done
    die "Ports 8080 to 8099 are all in use. Set VULWALL_PORT to a free port in $dir/.env and run the installer again."
}

# --- Startup --------------------------------------------------------------------------

# Prints "<status> <exit code> <restart count> <health>" of service $1's container.
svc_state() {
    id=$(compose ps -a -q "$1" 2>/dev/null | head -n 1 || true)
    [ -n "$id" ] || return 1
    dk inspect -f '{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null </dev/null
}

# Finds the first service whose container keeps crashing: it restarted more
# than twice, or it stopped with an error. Sets $crash_svc and $crash_code.
crashed_service() {
    for s in mongo redis scanner web; do
        st=$(svc_state "$s") || continue
        read -r status code restarts _ <<EOF
$st
EOF
        case $status in
            restarting | exited | dead)
                if [ "$restarts" -gt 2 ] || { [ "$status" != restarting ] && [ "$code" -ne 0 ]; }; then
                    crash_svc=$s
                    crash_code=$code
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

# Prints the last lines of service $1's log without control characters.
log_tail() {
    compose logs --no-color --no-log-prefix --tail 30 "$1" 2>&1 | LC_ALL=C tr -cd '[:print:]\n\t' || true
}

report_crash() { # service exit_code
    logs=$(log_tail "$1")
    if [ "$2" = 0 ]; then
        err "The $1 container keeps stopping. Its last log lines:"
    else
        err "The $1 container keeps stopping (exit code $2). Its last log lines:"
    fi
    printf '%s\n' "$logs" >&2
    # On macOS, Docker Desktop's VM has a CPU that MongoDB supports.
    if [ "$1" = mongo ] && [ "$os" = Linux ]; then
        case "$2 $logs" in
            132* | *[Ii]llegal\ instruction* | *"requires a CPU with AVX"* | *ARMv8.2-A*)
                say "" >&2
                cpu_help "$arch" >&2
                ;;
        esac
    fi
    die "VulWall did not start. See: cd $qdir && docker compose logs $1"
}

# Waits up to $2 seconds until service $1 is healthy. Stops with the log of a
# service that keeps crashing. Fails on timeout.
wait_healthy() {
    waited=0
    while [ "$waited" -lt "$2" ]; do
        if crashed_service; then
            report_crash "$crash_svc" "$crash_code"
        fi
        st=$(svc_state "$1" || true)
        [ "${st##* }" = healthy ] && return 0
        waited=$((waited + 5))
        sleep 5
    done
    return 1
}

start_stack() {
    if compose up -d --remove-orphans; then
        return 0
    fi
    # The scanner and the web app wait for a healthy MongoDB, so a crashing
    # database makes "up" fail. Look for the cause for a short time.
    waited=0
    while [ "$waited" -lt 30 ]; do
        if crashed_service; then
            report_crash "$crash_svc" "$crash_code"
        fi
        waited=$((waited + 5))
        sleep 5
    done
    die "docker compose up failed. See: cd $qdir && docker compose logs"
}

scanner_help() {
    warn "The scanner did not become healthy within 4 minutes. Its last log lines:"
    log_tail scanner >&2
    warn "The scanner needs outbound internet access: DNS, HTTPS to github.com (nuclei"
    warn "templates) and to download.db-ip.com (geolocation data). Check them with: $helper doctor"
    warn "The web app works; scans start when the scanner is healthy."
}

# --- Output ---------------------------------------------------------------------------

ssh_hint() { # port
    [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ] || return 0
    server=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{ print $3 }')
    case $server in '' | *[!0-9A-Fa-f.:]*) server='<server-ip>' ;; esac
    user=$(id -un 2>/dev/null || true)
    case $user in '' | -* | *[!A-Za-z0-9._-]*) user='<user>' ;; esac
    say ""
    say "You are connected over SSH. To open the link from your own computer, run this"
    say "there first, and keep it running:"
    say ""
    say "  ssh -L $1:localhost:$1 $user@$server"
    say ""
    say "To reach VulWall without a tunnel, put a TLS reverse proxy in front:"
    say "  $DOCS_URL/configuration/reverse-proxy/"
}

# Offers to link the helper into ~/.local/bin when that is on PATH. Sets $helper
# to the command that runs the helper.
link_helper() {
    helper="$qdir/vulwall"
    bin=$HOME/.local/bin
    case ":$PATH:" in *":$bin:"*) ;; *) return 0 ;; esac
    [ -d "$bin" ] || return 0
    if [ -L "$bin/vulwall" ] && [ "$(readlink "$bin/vulwall")" = "$dir/vulwall" ]; then
        helper=vulwall
        return 0
    fi
    [ ! -e "$bin/vulwall" ] && [ ! -L "$bin/vulwall" ] || return 0
    if ask_yes "Add the 'vulwall' command to $bin?"; then
        ln -s "$dir/vulwall" "$bin/vulwall" && helper=vulwall
    fi
}

# --- Main -----------------------------------------------------------------------------

tmp=
getdocker=
cleanup() {
    [ -z "$tmp" ] || rm -rf "$tmp"
    [ -z "$getdocker" ] || rm -f "$getdocker"
}

main() {
    # Every check that can stop the install runs before anything changes.
    os=$(uname -s)
    check_platform "$os" "$(uname -m)"
    check_cpu /proc/cpuinfo
    command -v curl >/dev/null 2>&1 || die "curl is not installed."

    dir=${VULWALL_DIR:-$HOME/vulwall}
    version=${VULWALL_VERSION:-}
    version=${version#v}
    if [ -n "${VULWALL_BASE_URL:-}" ]; then
        base=${VULWALL_BASE_URL%/}
        case $base in
            https://*) ;;
            http://*)
                [ "${VULWALL_ALLOW_HTTP:-}" = 1 ] ||
                    die "VULWALL_BASE_URL uses http://, which lets anyone on the network change the download. Use https://, or set VULWALL_ALLOW_HTTP=1 for local testing."
                proto='=http,https'
                ;;
            *) die "VULWALL_BASE_URL must start with https://" ;;
        esac
    elif [ -n "$version" ]; then
        base=$REPO_URL/releases/download/v$version
    else
        base=$REPO_URL/releases/latest/download
    fi

    trap cleanup EXIT
    trap 'exit 130' INT TERM

    ensure_docker
    check_resources

    mkdir -p "$dir"
    cd "$dir"
    dir=$(pwd)
    qdir=$(shquote "$dir")
    helper="$qdir/vulwall"

    # Download into a temporary directory and verify before anything in $dir
    # changes, so a failed or tampered download leaves an existing install as it was.
    tmp=$(mktemp -d "$dir/.download.XXXXXX")
    say "Downloading VulWall ${version:-(latest release)} from $base"
    download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
    download "$base/docker-compose.yml" "$tmp/docker-compose.yml"
    download "$base/env.example" "$tmp/env.example"
    download "$base/vulwall" "$tmp/vulwall"
    (cd "$tmp" && sha256_check) ||
        die "Checksum verification failed. Nothing was changed in $dir."

    backup_compose "$tmp/docker-compose.yml"
    mv "$tmp/docker-compose.yml" docker-compose.yml
    cp docker-compose.yml .docker-compose.release.yml
    mv "$tmp/env.example" .env.example
    chmod 755 "$tmp/vulwall"
    mv "$tmp/vulwall" vulwall
    if [ -f .env ]; then
        say "Keeping your existing $dir/.env"
    else
        (umask 077 && cp .env.example .env)
        say "Created $dir/.env (edit it to change settings)"
    fi
    ensure_setup_token
    choose_port

    say "Pulling images (the first time this takes a few minutes)..."
    compose pull --quiet || die "docker compose pull failed."
    start_stack

    say "Waiting for the web app to become healthy..."
    wait_healthy web 300 ||
        die "The web app did not become healthy within 5 minutes. See: cd $qdir && docker compose logs web"
    say "Waiting for the scanner to become healthy..."
    wait_healthy scanner 240 || scanner_help

    hostport=$(compose port web 8080 2>/dev/null || true)
    port=${hostport##*:}
    case $port in '' | *[!0-9]*) port=8080 ;; esac

    admins=$(compose exec -T mongo mongosh vulwall --quiet --eval 'db.users.countDocuments({_id:"admin"})' 2>/dev/null || true)
    say ""
    if [ "$admins" = 1 ]; then
        say "VulWall is running. Log in at http://localhost:$port/login"
    elif is_hex32 "$token"; then
        say "VulWall is running. Open this link to create the admin account:"
        say ""
        say "  http://localhost:$port/setup?token=$token"
        say ""
        say "The link works until the admin account exists."
        if [ "$token" = "$(env_setup_token)" ]; then
            say "To see the token again: grep SETUP_TOKEN $qdir/.env"
        fi
    else
        say "VulWall is running. To create the admin account, open"
        say "  http://localhost:$port/setup?token=<your SETUP_TOKEN>"
        say "with the SETUP_TOKEN you set in $qdir/.env or in your environment."
    fi
    ssh_hint "$port"
    if [ -z "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ]; then
        say ""
        say "The web UI listens on 127.0.0.1:$port only. To reach it from other machines,"
        say "put a TLS reverse proxy in front: $DOCS_URL/configuration/reverse-proxy/"
    fi
    say ""
    link_helper
    say "Manage VulWall with the vulwall command:"
    say "  vulwall status       containers, health and URL"
    say "  vulwall logs         follow the logs"
    say "  vulwall backup       back up the database and .env"
    say "  vulwall upgrade      upgrade to the latest release"
    say "  vulwall doctor       check the host and the scanner's internet access"
    say "  vulwall help         all commands, including uninstall"
    [ "$helper" = vulwall ] || say "It is not on your PATH; run it as: $helper"
    say "Settings: edit $qdir/.env, then: cd $qdir && docker compose up -d"
    if [ "$docker_sudo" = 1 ]; then
        say ""
        say "Docker was installed and your user was added to the docker group. Log out and"
        say "back in to use docker and the vulwall command without sudo."
    fi
    say "Docs: $DOCS_URL/"
}

# Everything runs from here, so a partly downloaded script does nothing.
main "$@"
