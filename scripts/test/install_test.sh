#!/bin/sh
# Tests for install.sh and scripts/vulwall with stubbed commands. Needs no
# Docker and changes nothing outside a temporary directory.
#
#   sh scripts/test/install_test.sh      (or: dash scripts/test/install_test.sh)
#
# Each test runs in a subshell that loads the functions of install.sh (all of it
# but the last line, which runs main). Stubs are shell functions, which win over
# commands, or scripts in $work/bin for "command -v" checks.
#
# Stubs are defined inside test functions and set variables that the loaded
# functions read, which shellcheck cannot follow:
# shellcheck disable=SC2034,SC2329,SC2016,SC2154,SC2012
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/vulwall-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
# The helper prints physical paths; macOS's temporary directory is a symlink.
work=$(cd "$work" && pwd -P)
unset SETUP_TOKEN VULWALL_PORT VULWALL_DIR VULWALL_INSTALL_DOCKER VULWALL_SKIP_CPU_CHECK \
    COMPOSE_PROJECT_NAME SSH_CONNECTION SSH_CLIENT

# shellcheck disable=SC2016
[ "$(tail -n 1 "$root/install.sh")" = 'main "$@"' ] || {
    echo "install.sh must end with: main \"\$@\""
    exit 1
}
sed '$d' "$root/install.sh" >"$work/lib.sh"

# A PATH with the basic tools only, so tests decide which other commands exist.
mkdir -p "$work/core" "$work/bin"
for c in sh env cat rm mkdir mktemp grep sed tr od awk dirname head tail date cmp cp mv chmod \
    df ls ln readlink pwd sleep printf tee touch wc id uname cut; do
    p=$(command -v "$c") || continue
    case $p in /*) ln -s "$p" "$work/core/$c" ;; esac
done
CLEAN_PATH=$work/bin:$work/core

passed=0
failed=0

# t NAME WANT_STATUS FUNCTION: runs FUNCTION in a fresh test directory in a
# subshell with install.sh loaded. Its output is in $work/out.
t() {
    name=$1
    want=$2
    shift 2
    rm -rf "${work:?}/case" "${work:?}/bin" "${work:?}/log"
    mkdir -p "$work/case" "$work/bin"
    : >"$work/log"
    got=0
    (
        cd "$work/case" || exit 99
        # shellcheck disable=SC1091
        . "$work/lib.sh"
        "$@"
    ) >"$work/out" 2>&1 </dev/null || got=$?
    if [ "$got" = "$want" ]; then
        passed=$((passed + 1))
        return 0
    fi
    failed=$((failed + 1))
    printf 'FAIL %s: exit status %s, want %s\n' "$name" "$got" "$want"
    sed 's/^/    | /' "$work/out"
    return 1
}

# expect FILE PATTERN: the last test passes only if FILE has a line matching PATTERN.
expect() {
    grep -q -- "$2" "$1" && return 0
    failed=$((failed + 1))
    passed=$((passed - 1))
    printf 'FAIL %s: %s has no line matching: %s\n' "$name" "$1" "$2"
    sed 's/^/    | /' "$1"
}

expect_not() {
    grep -q -- "$2" "$1" || return 0
    failed=$((failed + 1))
    passed=$((passed - 1))
    printf 'FAIL %s: %s has a line matching: %s\n' "$name" "$1" "$2"
    sed 's/^/    | /' "$1"
}

# holds TEST...: the last test passes only if TEST succeeds.
holds() {
    "$@" && return 0
    failed=$((failed + 1))
    passed=$((passed - 1))
    printf 'FAIL %s: does not hold: %s\n' "$name" "$*"
}

log() { printf '%s\n' "$*" >>"$work/log"; }

# Writes an executable stub $work/bin/$1 with body $2.
stub_bin() {
    printf '#!/bin/sh\n%s\n' "$2" >"$work/bin/$1"
    chmod +x "$work/bin/$1"
}

fx=$here/cpuinfo

# --- Platform and CPU --------------------------------------------------------------

t "cpu: x86-64 with AVX" 0 cpu_supported amd64 "$fx/x86-avx.txt"
t "cpu: x86-64 without AVX" 1 cpu_supported amd64 "$fx/x86-no-avx.txt"
t "cpu: Raspberry Pi 4 (Cortex-A72)" 1 cpu_supported arm64 "$fx/pi4-cortex-a72.txt"
t "cpu: Raspberry Pi 5 (Cortex-A76)" 0 cpu_supported arm64 "$fx/pi5-cortex-a76.txt"
t "cpu: Graviton2 (Neoverse N1)" 0 cpu_supported arm64 "$fx/graviton2-neoverse-n1.txt"
t "cpu: unreadable cpuinfo is not a failure" 0 cpu_supported amd64 "$work/none"

no_avx() { os=Linux arch=amd64 check_cpu "$fx/x86-no-avx.txt"; }
t "check_cpu: no AVX stops with the Proxmox hint" 1 no_avx &&
    expect "$work/out" "CPU type to 'host'" && expect "$work/out" VULWALL_SKIP_CPU_CHECK=1

pi4() { os=Linux arch=arm64 check_cpu "$fx/pi4-cortex-a72.txt"; }
t "check_cpu: Raspberry Pi 4 is rejected" 1 pi4 && expect "$work/out" "Raspberry Pi 4 and older"

skip_cpu() { os=Linux arch=amd64 VULWALL_SKIP_CPU_CHECK=1 check_cpu "$fx/x86-no-avx.txt"; }
t "check_cpu: VULWALL_SKIP_CPU_CHECK=1 skips it" 0 skip_cpu && expect "$work/out" "Skipping the CPU check"

mac_cpu() { os=Darwin arch=amd64 check_cpu "$fx/x86-no-avx.txt"; }
t "check_cpu: skipped on macOS" 0 mac_cpu

t "platform: Git Bash" 1 check_platform MINGW64_NT-10.0-19045 x86_64 && expect "$work/out" "use WSL 2"
t "platform: MSYS2" 1 check_platform MSYS_NT-10.0 x86_64 && expect "$work/out" "WSL 2"
t "platform: Cygwin" 1 check_platform CYGWIN_NT-10.0 x86_64 && expect "$work/out" "WSL 2"
t "platform: armv7l" 1 check_platform Linux armv7l && expect "$work/out" "Unsupported CPU architecture: armv7l"
t "platform: i686" 1 check_platform Linux i686 && expect "$work/out" "amd64) and 64-bit ARM (arm64) only"
arm_ok() { check_platform Linux aarch64 && [ "$arch" = arm64 ]; }
t "platform: Linux aarch64" 0 arm_ok
mac_ok() { check_platform Darwin arm64 && [ "$arch" = arm64 ]; }
t "platform: macOS arm64" 0 mac_ok

# --- Port ---------------------------------------------------------------------------------

# curl stub: ports in $busy accept connections, others refuse (curl exit code 7).
# compose stub: the web container publishes $ours.
port_stubs() {
    curl() {
        for a; do url=$a; done
        p=${url#http://127.0.0.1:}
        p=${p%/}
        case " $busy " in *" $p "*) return 0 ;; esac
        return 7
    }
    compose() {
        [ "$1" = port ] || return 1
        [ -z "$ours" ] || echo "127.0.0.1:$ours"
    }
    dir=$work/case
    ours=
}

port_free() { port_stubs; busy=; choose_port; }
t "port: 8080 free, nothing written" 0 port_free &&
    expect_not "$work/out" . && holds [ ! -e "$work/case/.env" ]

port_pick() {
    port_stubs
    busy="8080 8081"
    printf 'ANTHROPIC_API_KEY=\n' >.env
    choose_port
    cp .env "$work/env"
}
t "port: 8080 and 8081 busy, picks 8082 and saves it" 0 port_pick &&
    expect "$work/out" "VulWall uses port 8082" && expect "$work/env" '^VULWALL_PORT=8082$' &&
    expect "$work/env" '^ANTHROPIC_API_KEY=$'

port_ours() { port_stubs; busy=8080; ours=8080; choose_port; }
t "port: 8080 busy with our own web container (rerun)" 0 port_ours &&
    holds [ ! -e "$work/case/.env" ]

port_all_busy() {
    port_stubs
    busy=$(i=8080; while [ $i -le 8099 ]; do printf '%s ' $i; i=$((i + 1)); done)
    choose_port
}
t "port: 8080-8099 all busy" 1 port_all_busy && expect "$work/out" "8080 to 8099 are all in use"

port_env_busy() { port_stubs; busy=9000; VULWALL_PORT=9000; choose_port; }
t "port: VULWALL_PORT from the environment busy, not ours" 1 port_env_busy &&
    expect "$work/out" "Port 9000 (VULWALL_PORT in your environment) is in use by another program"

port_dotenv_busy() { port_stubs; busy=9000; printf 'VULWALL_PORT="9000"\n' >.env; choose_port; }
t "port: VULWALL_PORT from .env busy, not ours" 1 port_dotenv_busy &&
    expect "$work/out" "VULWALL_PORT in .*/.env) is in use"

port_dotenv_ours() { port_stubs; busy=9000; ours=9000; printf 'VULWALL_PORT=9000\n' >.env; choose_port; }
t "port: VULWALL_PORT busy with our own web container" 0 port_dotenv_ours

port_set_free() { port_stubs; busy=8080; VULWALL_PORT=9001; choose_port; }
t "port: VULWALL_PORT free, 8080 busy: no auto-pick" 0 port_set_free && expect_not "$work/out" "uses port"

port_bad() { port_stubs; VULWALL_PORT=80a; choose_port; }
t "port: VULWALL_PORT not a number" 1 port_bad && expect "$work/out" "not a port number"

if command -v python3 >/dev/null 2>&1; then
    real_probe() {
        p=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
        python3 -m http.server "$p" --bind 127.0.0.1 >/dev/null 2>&1 &
        pid=$!
        i=0
        until port_in_use "$p"; do
            i=$((i + 1))
            [ "$i" -lt 50 ] || { kill "$pid"; echo "server did not start"; exit 1; }
            sleep 0.1
        done
        kill "$pid"
        wait "$pid" 2>/dev/null
        if port_in_use "$p"; then echo "port $p still in use after the server stopped"; exit 1; fi
    }
    t "port: real probe with curl sees a listener come and go" 0 real_probe
fi

# --- SSH hint -------------------------------------------------------------------------------

ssh_conn() {
    id() { echo alice; }
    SSH_CONNECTION="203.0.113.9 51234 198.51.100.7 22"
    ssh_hint 8081
}
t "ssh: tunnel command from SSH_CONNECTION" 0 ssh_conn &&
    expect "$work/out" "^  ssh -L 8081:localhost:8081 alice@198.51.100.7$" &&
    expect "$work/out" "configuration/reverse-proxy/"

ssh_client_only() { id() { echo bob; }; unset SSH_CONNECTION; SSH_CLIENT="203.0.113.9 51234 22"; ssh_hint 8080; }
t "ssh: SSH_CLIENT only gives a placeholder" 0 ssh_client_only &&
    expect "$work/out" "ssh -L 8080:localhost:8080 bob@<server-ip>$"

ssh_weird() { id() { echo 'x;rm'; }; SSH_CONNECTION="1 2 \$(evil) 22"; ssh_hint 8080; }
t "ssh: odd values become placeholders" 0 ssh_weird &&
    expect "$work/out" "ssh -L 8080:localhost:8080 <user>@<server-ip>$"

no_ssh() { unset SSH_CONNECTION SSH_CLIENT; ssh_hint 8080; }
t "ssh: no hint without SSH" 0 no_ssh && expect_not "$work/out" .

# --- Compose backup on upgrade ----------------------------------------------------------------

compose_case() { # current pristine(-|text) new
    dir=$work/case
    printf '%s\n' "$1" >docker-compose.yml
    [ "$2" = - ] || printf '%s\n' "$2" >.docker-compose.release.yml
    printf '%s\n' "$3" >"$work/new.yml"
    backup_compose "$work/new.yml"
    ls -a >"$work/ls"
}
t "compose: unchanged release file, no backup" 0 compose_case old old new &&
    expect_not "$work/ls" '\.bak\.' && expect_not "$work/out" .
t "compose: same as the new release, no backup" 0 compose_case new old new &&
    expect_not "$work/ls" '\.bak\.'
t "compose: edited file is backed up" 0 compose_case edited old new &&
    expect "$work/ls" '^docker-compose\.yml\.bak\.[0-9]\{8\}-[0-9]\{6\}$' &&
    expect "$work/out" "docker-compose.override.yml"
t "compose: no pristine copy and a different file is backed up" 0 compose_case old - new &&
    expect "$work/ls" '^docker-compose\.yml\.bak\.'
t "compose: first install, nothing to back up" 0 backup_compose "$work/none"

# --- Crash loops and health ------------------------------------------------------------------

# State of each service as "status exit_code restart_count health".
crash_stubs() {
    st_mongo="running 0 0 healthy"
    st_redis="running 0 0 healthy"
    st_scanner="running 0 0 starting"
    st_web="running 0 0 healthy"
    compose() {
        case $1 in
            ps) for a; do s=$a; done; echo "id-$s" ;;
            logs) log "logs $*"; printf 'line one\n\033[31mWARNING\033[0m bell\007\nIllegal instruction (core dumped)\n' ;;
        esac
    }
    dk() {
        [ "$1" = inspect ] || return 1
        for a; do id=$a; done
        eval "echo \"\$st_${id#id-}\""
    }
    sleep() { :; }
    os=Linux arch=amd64 qdir=/srv/vulwall
}

no_crash() { crash_stubs; ! crashed_service; }
t "crash: all running is no crash" 0 no_crash

mongo_loop() { crash_stubs; st_mongo="restarting 132 3 none"; crashed_service && echo "$crash_svc $crash_code"; }
t "crash: mongo restarting 3 times" 0 mongo_loop && expect "$work/out" "^mongo 132$"

web_exit() { crash_stubs; st_web="exited 3 0 none"; crashed_service && echo "$crash_svc $crash_code"; }
t "crash: web exited with an error" 0 web_exit && expect "$work/out" "^web 3$"

scanner_one_restart() { crash_stubs; st_scanner="restarting 1 1 none"; ! crashed_service; }
t "crash: one restart is not a loop yet" 0 scanner_one_restart

mongo_report() { crash_stubs; report_crash mongo 132; }
t "crash: mongo report has the log tail and the CPU hint" 1 mongo_report &&
    expect "$work/out" "The mongo container keeps stopping (exit code 132)" &&
    expect "$work/out" "Illegal instruction" && expect "$work/out" "does not support AVX" &&
    expect "$work/out" "docker compose logs mongo" && expect "$work/log" "--tail 30 mongo"
# The log tail has no escape or bell characters.
esc=$(printf '\033')
bel=$(printf '\007')
expect_not "$work/out" "$esc"
expect_not "$work/out" "$bel"

web_report() { crash_stubs; report_crash web 3; }
t "crash: web report has no CPU hint" 1 web_report && expect_not "$work/out" "AVX"

wait_crash() { crash_stubs; st_redis="exited 1 0 none"; wait_healthy web 300; }
t "wait: stops at once on a crash" 1 wait_crash && expect "$work/out" "The redis container keeps stopping"

wait_ok() { crash_stubs; wait_healthy web 300; }
t "wait: web healthy" 0 wait_ok

wait_timeout() { crash_stubs; wait_healthy scanner 20; }
t "wait: scanner not healthy in time" 1 wait_timeout && expect_not "$work/out" .

scanner_warn() { crash_stubs; helper=vulwall; scanner_help; }
t "wait: scanner warning names the outbound hosts" 0 scanner_warn &&
    expect "$work/out" "github.com" && expect "$work/out" "download.db-ip.com" &&
    expect "$work/out" "vulwall doctor"

up_fails_mongo() {
    crash_stubs
    compose() {
        case $1 in
            up) return 1 ;;
            ps) for a; do s=$a; done; echo "id-$s" ;;
            logs) echo "Illegal instruction" ;;
        esac
    }
    st_mongo="restarting 132 4 none"
    start_stack
}
t "up: failing up with a crashing mongo shows the cause" 1 up_fails_mongo &&
    expect "$work/out" "mongo container keeps stopping" && expect "$work/out" "AVX"

# --- Docker install (Linux) ----------------------------------------------------------------------

# Stubs for a Linux host without Docker. The fake get.docker.com script installs
# a docker stub that works only through sudo.
docker_stubs() {
    PATH=$CLEAN_PATH
    os=Linux
    stub_bin sudo 'exit 0'
    id() { case $1 in -u) echo "${uid:-1000}" ;; -un) echo alice ;; esac; }
    sudo() { log "sudo $*"; "$@"; }
    has_systemd() { true; }
    systemctl() { log "systemctl $*"; }
    usermod() { log "usermod $*"; }
    curl() {
        out=
        while [ "$#" -gt 0 ]; do
            case $1 in -o) out=$2; shift ;; https://*) log "curl $1" ;; esac
            shift
        done
        printf '%s\n' "echo get-docker-ran >>'$work/log'" \
            "printf '#!/bin/sh\necho \"docker \$*\" >>$work/log\n' >'$work/bin/docker'" \
            "chmod +x '$work/bin/docker'" >"$out"
    }
}

install_optin() { docker_stubs; VULWALL_INSTALL_DOCKER=1; ensure_docker; echo "docker_sudo=$docker_sudo"; }
t "docker: VULWALL_INSTALL_DOCKER=1 installs Docker" 0 install_optin &&
    expect "$work/log" "^curl https://get.docker.com$" &&
    expect "$work/log" "^sudo sh .*get-docker\." &&
    expect "$work/log" "^get-docker-ran$" &&
    expect "$work/log" "^sudo systemctl enable --now docker$" &&
    expect "$work/log" "^sudo usermod -aG docker alice$" &&
    expect "$work/log" "^sudo env docker compose version$" &&
    expect "$work/log" "^sudo env docker info$" &&
    expect "$work/out" "^docker_sudo=1$"

install_root() { docker_stubs; uid=0; VULWALL_INSTALL_DOCKER=1; ensure_docker; echo "docker_sudo=$docker_sudo"; }
t "docker: as root, no sudo and no group change" 0 install_root &&
    expect_not "$work/log" "^sudo" && expect_not "$work/log" usermod &&
    expect "$work/log" "^systemctl enable --now docker$" &&
    expect "$work/log" "^docker info$" && expect "$work/out" "^docker_sudo=0$"

install_no_tty() { docker_stubs; have_tty() { false; }; ensure_docker; }
t "docker: no terminal and no opt-in stops with instructions" 1 install_no_tty &&
    expect "$work/out" "Docker is not installed" && expect "$work/out" "VULWALL_INSTALL_DOCKER=1" &&
    expect_not "$work/log" "curl"

install_asked() { docker_stubs; ask_yes() { log "ask: $1"; [ "$answer" = y ]; }; answer=$1; ensure_docker; }
t "docker: asks first, and no means no" 1 install_asked n &&
    expect "$work/log" "^ask: Docker is not installed. Install Docker Engine now using Docker's official script (needs sudo)?$" &&
    expect_not "$work/log" "curl"
t "docker: asks first, and yes installs" 0 install_asked y && expect "$work/log" "^get-docker-ran$"

install_no_sudo() { docker_stubs; rm "$work/bin/sudo"; unset -f sudo; VULWALL_INSTALL_DOCKER=1; ensure_docker; }
t "docker: no sudo and not root" 1 install_no_sudo && expect "$work/out" "sudo is not installed"

daemon_stopped() {
    docker_stubs
    stub_bin docker "case \$1 in
        info) [ -e '$work/started' ] || { echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.' >&2; exit 1; } ;;
    esac"
    systemctl() { log "systemctl $*"; touch "$work/started"; }
    VULWALL_INSTALL_DOCKER=1
    ensure_docker
}
t "docker: daemon not running is started with consent" 0 daemon_stopped &&
    expect "$work/log" "^sudo systemctl start docker$"

daemon_stopped_no() { docker_stubs; stub_bin docker '[ "$1" != info ] || exit 1'; have_tty() { false; }; ensure_docker; }
t "docker: daemon not running, no consent" 1 daemon_stopped_no &&
    expect "$work/out" "Cannot reach the Docker daemon" && expect_not "$work/log" systemctl

daemon_denied() { docker_stubs; stub_bin docker '[ "$1" != info ] || { echo "permission denied while trying to connect" >&2; exit 1; }'; ensure_docker; }
t "docker: permission denied names the docker group" 1 daemon_denied &&
    expect "$work/out" "sudo usermod -aG docker alice"

compose_v1() { docker_stubs; stub_bin docker '[ "$1" != compose ] || exit 1'; stub_bin docker-compose 'exit 0'; ensure_docker; }
t "docker: only docker-compose v1" 1 compose_v1 &&
    expect "$work/out" "old docker-compose v1" && expect "$work/out" "docs.docker.com/compose/install/linux/"

compose_apt() {
    docker_stubs
    stub_bin docker "[ \"\$1\" != compose ] || [ -e '$work/plugin' ]"
    stub_bin apt-get 'exit 0'
    stub_bin apt-cache 'exit 0'
    stub_bin apt-get "echo \"apt-get \$*\" >>'$work/log'; touch '$work/plugin'"
    VULWALL_INSTALL_DOCKER=1
    ensure_docker
}
t "docker: missing Compose plugin installed from Docker's repository" 0 compose_apt &&
    expect "$work/log" "^sudo apt-get install -y docker-compose-plugin$"

mac_no_docker() { docker_stubs; os=Darwin; ensure_docker; }
t "docker: macOS without Docker points to Docker Desktop" 1 mac_no_docker &&
    expect "$work/out" "Docker Desktop" && expect "$work/out" "brew install --cask docker" &&
    expect_not "$work/log" curl

sudo_env() {
    docker_stubs
    stub_bin docker 'exit 0'
    sudo() { log "sudo $*"; }
    docker_sudo=1 SETUP_TOKEN=abc COMPOSE_PROJECT_NAME=p
    unset VULWALL_PORT
    dk compose ps
}
t "docker: sudo passes the Compose variables on" 0 sudo_env &&
    expect "$work/log" "^sudo env SETUP_TOKEN=abc COMPOSE_PROJECT_NAME=p docker compose ps$"

# --- Memory and disk ---------------------------------------------------------------------------

t "memory: 1 GB warns" 0 check_memory 1073741824 && expect "$work/out" "Docker has 1024 MB of memory"
t "memory: 2 GB machine does not warn" 0 check_memory 2012000000 && expect_not "$work/out" .
t "memory: unknown does not warn" 0 check_memory "" && expect_not "$work/out" .

disk_low() { df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 90 1048576 90%% /\n'; }; check_disk "$work/case/new/dir" /var/lib/docker; }
t "disk: low space warns once per filesystem" 0 disk_low &&
    expect "$work/out" "Only 1024 MB of disk space is free on /" &&
    holds [ "$(grep -c 'disk space' "$work/out")" = 1 ]

disk_ok() { df() { printf 'h\n/dev/sda1 100 90 99999999 1%% /\n'; }; check_disk /tmp; }
t "disk: enough space is quiet" 0 disk_ok && expect_not "$work/out" .

# --- .env --------------------------------------------------------------------------------------

env_vals() {
    printf 'VULWALL_PORT=1\nexport VULWALL_PORT = "8085"\n# VULWALL_PORT=9\nSETUP_TOKEN=abc\n' >.env
    [ "$(env_value VULWALL_PORT)" = 8085 ] && [ "$(env_setup_token)" = abc ]
}
t "env: last value wins, comments are ignored" 0 env_vals

env_mode() {
    dir=$work/case
    (umask 022 && : >.env)
    chmod 600 .env
    env_append VULWALL_PORT 8081 "test"
    ls -l .env | cut -c1-10
}
t "env: appending keeps .env private" 0 env_mode && expect "$work/out" "^-rw-------$"

# --- vulwall helper -------------------------------------------------------------------------------

# Install dir with a docker stub that logs its directory and arguments.
helper_setup() {
    PATH=$CLEAN_PATH
    inst=$work/case/inst
    mkdir -p "$inst" "$work/case/home/.local/bin" "$work/case/elsewhere"
    cp "$root/scripts/vulwall" "$inst/vulwall"
    printf '# VulWall 1.2.3 release compose file, generated from docker-compose.yml.\nservices: {}\n' >"$inst/docker-compose.yml"
    printf 'ANTHROPIC_API_KEY=k\n\n# First-run setup token, generated by install.sh.\nSETUP_TOKEN=0123456789abcdef0123456789abcdef\nSETUP_TOKEN=dup\n' >"$inst/.env"
    chmod 600 "$inst/.env"
    ln -s "$inst/vulwall" "$work/case/home/.local/bin/vulwall"
    stub_bin docker "echo \"\$PWD: docker \$*\" >>'$work/log'
case \"\$*\" in
    'compose port web 8080') echo 127.0.0.1:8085 ;;
    'compose ps -q web') echo id-web ;;
    inspect*) echo healthy ;;
    *mongodump*) printf 'ARCHIVE' ;;
    *mongorestore*) cat >>'$work/log' ;;
esac"
}

helper_symlink() {
    helper_setup
    cd "$work/case/elsewhere" && HOME=$work/case/home sh "$work/case/home/.local/bin/vulwall" status
}
t "helper: works through the ~/.local/bin symlink" 0 helper_symlink &&
    expect "$work/log" "^$work/case/inst: docker compose ps -a$" &&
    expect "$work/out" "Release: 1.2.3" && expect "$work/out" "URL:     http://localhost:8085"

helper_backup() {
    helper_setup
    cd "$work/case/elsewhere" && sh "$inst/vulwall" backup b.archive.gz &&
        ls -l b.archive.gz b.env | cut -c1-10 && cat b.archive.gz
}
t "helper: backup writes a private archive and .env copy where you are" 0 helper_backup &&
    expect "$work/out" "^-rw-------$" && expect "$work/out" "ARCHIVE" &&
    expect "$work/log" "docker compose exec -T mongo mongodump --db vulwall --archive --gzip$"

helper_backup_exists() { helper_setup; cd "$work/case/elsewhere" && touch b.archive.gz && sh "$inst/vulwall" backup b.archive.gz; }
t "helper: backup never overwrites a file" 1 helper_backup_exists && expect "$work/out" "already exists"

helper_restore() {
    helper_setup
    printf 'RESTOREDATA' >"$work/case/elsewhere/b.archive.gz"
    cd "$work/case/elsewhere" && sh "$inst/vulwall" -y restore b.archive.gz
}
t "helper: restore feeds the archive to mongorestore" 0 helper_restore &&
    expect "$work/log" "docker compose exec -T mongo mongorestore --drop --archive --gzip$" &&
    expect "$work/log" "RESTOREDATA"

# Only without a terminal: with one, the helper would ask.
if ! (: </dev/tty) 2>/dev/null; then
    helper_restore_notty() { helper_setup; printf x >"$work/case/b"; sh "$inst/vulwall" restore "$work/case/b"; }
    t "helper: restore without -y and without a terminal does nothing" 1 helper_restore_notty &&
        expect_not "$work/log" mongorestore
fi

helper_reset() {
    helper_setup
    sh "$inst/vulwall" -y reset-admin && cp "$inst/.env" "$work/env" && ls -l "$inst/.env" | cut -c1-10
}
t "helper: reset-admin replaces the setup token" 0 helper_reset &&
    expect "$work/log" "docker compose stop web$" &&
    expect "$work/log" "deleteOne({_id:\"admin\"})" &&
    expect "$work/log" "docker compose up -d web$" &&
    expect "$work/out" "http://localhost:8085/setup?token=[0-9a-f]\{32\}$" &&
    expect "$work/env" "^ANTHROPIC_API_KEY=k$" &&
    holds [ "$(grep -c '^SETUP_TOKEN=' "$work/env")" = 1 ] &&
    expect "$work/env" "^SETUP_TOKEN=[0-9a-f]\{32\}$" && expect "$work/out" "^-rw-------$"

helper_uninstall() {
    helper_setup
    HOME=$work/case/home sh "$inst/vulwall" -y uninstall
    [ ! -e "$inst" ] && [ ! -L "$work/case/home/.local/bin/vulwall" ]
}
t "helper: uninstall removes the stack, the directory and our symlink" 0 helper_uninstall &&
    expect "$work/log" "docker compose down -v --remove-orphans$"

helper_wrong_dir() { helper_setup; VULWALL_DIR=$work/case/elsewhere sh "$inst/vulwall" -y uninstall; }
t "helper: refuses a directory without docker-compose.yml" 1 helper_wrong_dir &&
    expect "$work/out" "has no docker-compose.yml" && holds [ -d "$work/case/elsewhere" ]

helper_unknown() { helper_setup; sh "$inst/vulwall" frobnicate; }
t "helper: unknown command" 1 helper_unknown && expect "$work/out" "Unknown command: frobnicate"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
