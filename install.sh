#!/bin/sh
# QuietNet installer for a Raspberry Pi, or any Debian or Ubuntu style Linux computer.
#
# Run it with:
#   curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh
# and, to pair with your relay in the same step (the relay's home page shows this line):
#   curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh -s -- --relay https://RELAY --code A1B2-C3D4
#
# What it does: checks for Docker (and offers to install it), downloads QuietNet into
# /opt/quietnet, frees DNS port 53 if this computer's own name service holds it, switches on
# packet forwarding and lets that traffic through Docker's firewall (both needed only for "Cut live
# connections"), then builds and starts QuietNet's container. Running it again updates QuietNet in
# place. Your history and rules live in a Docker volume, not in /opt/quietnet, so an update or an
# uninstall keeps them.
#
# Run "sh install.sh --help" to see every option.
#
# Notes for editors:
# - Plain POSIX sh only. It must run under dash (Debian's sh), busybox ash and bash.
# - Everything is inside functions, and the only line that does anything is the last one, which
#   calls main. A download cut off half-way therefore does nothing at all.
# - Every value from the command line is checked before it is used anywhere.
# - When piped from curl, standard input is this script itself, so questions are read from the
#   terminal (/dev/tty) and the commands run here are given /dev/null as their input.
# - tests/test_installer.py runs this file against stand-in commands. QUIETNET_SYSROOT and
#   QUIETNET_TTY exist only for those tests: they move /etc and the terminal into a test folder.

set -eu

# Settings. Each can be changed from the environment; the options below override them.
QUIETNET_DIR="${QUIETNET_DIR:-/opt/quietnet}"
QUIETNET_REPO="${QUIETNET_REPO:-lpobjoy/QuietNet}"
REF="${QUIETNET_REF:-main}"
SYSROOT="${QUIETNET_SYSROOT:-}"
TTY="${QUIETNET_TTY:-/dev/tty}"

PROJECT="quietnet"          # the Docker Compose project name; the data volume is quietnet_quietnet-data
CONTAINER="quietnet"        # the container name set in docker-compose.yml
VOLUME="quietnet_quietnet-data"

RELAY=""
CODE=""
YES=""
UNINSTALL=""
SUDO=""
WORK=""                     # temporary download folder, removed on exit
STAGE=""                    # half-installed copy of the program folder, removed on exit if left over

LOWER="abcdefghijklmnopqrstuvwxyz"
UPPER="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS="0123456789"


# Print a progress message.
say() {
    printf '%s\n' "$*"
}

# Print a step heading, so the person can see how far the installer has got.
step() {
    printf '\n==> %s\n' "$*"
}

# Print a warning that does not stop the installer.
warn() {
    printf 'Note: %s\n' "$*" >&2
}

# Print what went wrong and what to do about it, then stop.
die() {
    printf '\nQuietNet was not installed: %s\n' "$*" >&2
    exit 1
}

# Print the list of options.
usage() {
    cat <<'EOF'
QuietNet installer

  curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh -s -- --relay https://RELAY --code A1B2-C3D4

Options:
  --relay URL    Your relay's web address, to reach this QuietNet from anywhere.
  --code CODE    The pairing code your relay shows (like A1B2-C3D4). Needs --relay.
  --yes          Answer yes to every question (for unattended installs).
  --ref NAME     The branch or tag to install (default: main).
  --uninstall    Stop QuietNet and remove its program folder. Your history and rules are kept.
  --help         Show this help.

Settings from the environment:
  QUIETNET_DIR   Where the program files go (default: /opt/quietnet).
  QUIETNET_REPO  The GitHub repository to download from (default: lpobjoy/QuietNet).
  QUIETNET_REF   The default for --ref.

Running it again updates QuietNet and keeps your history and rules.
EOF
}

# Print the usage text with a reason, then stop with exit code 2 (a mistake in the command).
usage_error() {
    printf 'install.sh: %s\n\n' "$*" >&2
    usage >&2
    exit 2
}

# Print what is wrong with a value given on the command line, then stop with exit code 2.
bad_value() {
    printf 'install.sh: %s\n(Run with --help to see the options.)\n' "$*" >&2
    exit 2
}

# Read the command-line options into RELAY, CODE, YES, REF and UNINSTALL.
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --relay) [ $# -ge 2 ] || usage_error "--relay needs your relay's web address after it."
                     RELAY="$2"; shift 2 ;;
            --relay=*) RELAY="${1#--relay=}"; shift ;;
            --code) [ $# -ge 2 ] || usage_error "--code needs the pairing code after it."
                    CODE="$2"; shift 2 ;;
            --code=*) CODE="${1#--code=}"; shift ;;
            --ref) [ $# -ge 2 ] || usage_error "--ref needs a branch or tag name after it."
                   REF="$2"; shift 2 ;;
            --ref=*) REF="${1#--ref=}"; shift ;;
            --yes|-y) YES=1; shift ;;
            --uninstall) UNINSTALL=1; shift ;;
            --help|-h) usage; exit 0 ;;
            *) usage_error "unknown option: $1" ;;
        esac
    done
}

# Upper-case a value using fixed letter lists, so the result does not depend on the language setting.
to_upper() {
    printf '%s' "$1" | tr "$LOWER" "$UPPER"
}

# Check and tidy the relay address. It must be https:// (or http:// to this same computer, for
# testing, as the Pi's own remote link insists) and may hold only ordinary address characters,
# so nothing in it can be read by the shell or by Docker as anything but an address.
check_relay() {
    r="$RELAY"
    case "$r" in
        "") bad_value "--relay needs your relay's web address." ;;
        *[!"$LOWER$UPPER$DIGITS"./:_-]*)
            bad_value "that relay address holds characters a web address does not need: $r
Copy the address from your relay's page, for example https://my-relay.up.railway.app" ;;
    esac
    case "$r" in
        *://*) ;;
        *) r="https://$r" ;;
    esac
    while :; do
        case "$r" in
            */) r="${r%/}" ;;
            *) break ;;
        esac
    done
    case "$r" in
        https://[$LOWER$UPPER$DIGITS]*) ;;
        http://localhost|http://localhost:*|http://localhost/*) ;;
        http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*) ;;
        http://*) bad_value "the relay address starts with http://, which would send this Pi's key unprotected.
Use the https:// address your relay's page shows." ;;
        *) bad_value "the relay address must start with https:// (got: $r)." ;;
    esac
    RELAY="$r"
}

# Check the pairing code: four letters or digits, a dash, four more. Small letters are accepted.
check_code() {
    a="[$UPPER$DIGITS]"
    c="$(to_upper "$CODE")"
    # shellcheck disable=SC2254
    case "$c" in
        $a$a$a$a-$a$a$a$a) CODE="$c" ;;
        *) bad_value "the pairing code should look like A1B2-C3D4 (four letters or digits, a dash, four more)." ;;
    esac
}

# Check the branch or tag name, which goes into the download address.
check_ref() {
    case "$REF" in
        ""|-*|/*|*..*|*//*) bad_value "--ref must be a branch or tag name, like main." ;;
        *[!"$LOWER$UPPER$DIGITS"._/-]*) bad_value "--ref may hold only letters, digits, dots, dashes, underscores and slashes." ;;
    esac
}

# Check the repository name (owner/name), which goes into the download address.
check_repo() {
    case "$QUIETNET_REPO" in
        */*/*|/*|*/|""|*..*) die "QUIETNET_REPO should look like owner/name, for example lpobjoy/QuietNet." ;;
        */*) ;;
        *) die "QUIETNET_REPO should look like owner/name, for example lpobjoy/QuietNet." ;;
    esac
    case "$QUIETNET_REPO" in
        *[!"$LOWER$UPPER$DIGITS"._/-]*) die "QUIETNET_REPO may hold only letters, digits, dots, dashes and underscores." ;;
    esac
}

# Check the install folder. It is replaced on every update, so it must be a folder of its own:
# never the top of the disk, a top-level system folder, or a folder holding anything else.
check_dir() {
    d="$QUIETNET_DIR"
    while :; do
        case "$d" in
            ?*/) d="${d%/}" ;;
            *) break ;;
        esac
    done
    case "$d" in
        ""|/) die "QUIETNET_DIR must be a folder of QuietNet's own, like /opt/quietnet, not the top of the disk." ;;
        /*) ;;
        *) die "QUIETNET_DIR must be a full path starting with /, like /opt/quietnet." ;;
    esac
    case "$d" in
        *[!"$LOWER$UPPER$DIGITS"._/-]*|*/../*|*/..|*/./*|*/.|*//*)
            die "QUIETNET_DIR may hold only letters, digits, dots, dashes, underscores and slashes: $d" ;;
        /*/*) ;;
        *) die "QUIETNET_DIR is a top-level system folder ($d). Use a folder inside it, like /opt/quietnet." ;;
    esac
    QUIETNET_DIR="$d"
}

# True when the install folder is missing, empty, or already holds an installed QuietNet, so it is
# safe to replace. The checks run with administrator rights, because the folder is later replaced
# with them: a folder the person cannot read must not look empty. A folder that cannot be listed,
# or a working copy with its own data/ folder or git history, is never treated as ours.
dir_is_ours() {
    as_root test -e "$QUIETNET_DIR" </dev/null || return 0
    as_root test -d "$QUIETNET_DIR" </dev/null || return 1
    if as_root test -e "$QUIETNET_DIR/data" </dev/null || as_root test -e "$QUIETNET_DIR/.git" </dev/null; then
        return 1
    fi
    if as_root test -f "$QUIETNET_DIR/server.py" </dev/null && as_root test -f "$QUIETNET_DIR/docker-compose.yml" </dev/null; then
        return 0
    fi
    listing="$(as_root ls -A "$QUIETNET_DIR" 2>/dev/null </dev/null)" || return 1
    [ -z "$listing" ]
}

# True when a command is available.
have() {
    command -v "$1" >/dev/null 2>&1
}

# Run a command as the administrator (root): directly if we are root, otherwise through sudo.
as_root() {
    if [ -n "$SUDO" ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# Write text to a file that needs administrator rights, creating its folder if needed.
write_root_file() {
    as_root mkdir -p "$(dirname "$1")"
    printf '%s\n' "$2" | as_root tee "$1" >/dev/null
}

# Ask a yes-or-no question on the terminal. Returns 0 for yes, 1 for no, and 2 when there is no
# terminal to ask on (and --yes was not given). The answer comes from the terminal because,
# when this script is piped from curl, its standard input is the script itself.
ask() {
    if [ -n "$YES" ]; then
        say "$1 Yes (--yes was given)."
        return 0
    fi
    if ! ( : <"$TTY" ) 2>/dev/null; then
        return 2
    fi
    printf '%s [y/N] ' "$1" >&2
    answer=""
    read -r answer <"$TTY" || true
    case "$answer" in
        y|Y|yes|Yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

# Refuse to run anywhere but Linux: QuietNet's container needs Linux's host networking.
check_linux() {
    os="$(uname -s 2>/dev/null || echo unknown)"
    case "$os" in
        Linux) ;;
        Darwin) die "this installer is for a Raspberry Pi or another Linux computer.
On a Mac, double-click \"Start QuietNet.command\" in the QuietNet folder instead." ;;
        *) die "this installer is for a Raspberry Pi or another Linux computer, and this one runs $os." ;;
    esac
    case "$(uname -m 2>/dev/null || echo unknown)" in
        armv6*) warn "this looks like an original Raspberry Pi Zero or Pi 1. Docker barely supports these,
and QuietNet may not build. A Pi Zero 2, Pi 3 or newer is recommended." ;;
    esac
}

# Decide how to get administrator rights: none needed as root, sudo otherwise.
check_root() {
    if [ "$(id -u)" = "0" ]; then
        SUDO=""
    elif have sudo; then
        SUDO="sudo"
        say "Some steps need administrator rights, so sudo may ask for your password."
        # Ask once, now, with sudo's own messages showing, so a later failure can only mean that
        # command failed, not that sudo did.
        sudo true </dev/null || die "administrator rights could not be obtained through sudo (the reason is shown above).
Run this again as root, or as a user who is allowed to use sudo. When running it over ssh,
add -t (ssh -t ...) so sudo can ask for your password."
    else
        die "this needs administrator rights, and sudo is not installed.
Log in as root (or run: su -) and run the same command again."
    fi
}

# Download a web address to a file, with curl or, failing that, wget.
fetch() {
    if have curl; then
        curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1" </dev/null
    elif have wget; then
        wget -q -O "$2" "$1" </dev/null
    else
        die "neither curl nor wget is installed, so nothing can be downloaded.
Install one with: sudo apt-get install curl"
    fi
}

# Make the temporary folder that downloads go into. It is removed when the script ends.
make_work_folder() {
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/quietnet-install.XXXXXX")" || die "could not make a temporary folder in ${TMPDIR:-/tmp}."
}

# Remove the temporary folder, and any half-made copy of the program folder, when the script ends.
cleanup() {
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        rm -rf "$WORK"
    fi
    if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
        as_root rm -rf "$STAGE" || true
    fi
}

# Make sure Docker is installed, offering to install it with Docker's own script if it is not.
ensure_docker() {
    step "Checking for Docker"
    if have docker; then
        say "Docker is installed."
        return 0
    fi
    say "Docker is not installed. QuietNet runs inside Docker, which keeps it apart from the rest of this computer."
    rc=0
    ask "Install Docker now, using Docker's official script from https://get.docker.com?" || rc=$?
    case "$rc" in
        0) ;;
        2) die "Docker is needed, and there is no terminal here to ask whether to install it.
Run the same command again with --yes added at the end to install it, or install Docker first:
https://docs.docker.com/engine/install/" ;;
        *) die "Docker is needed. Install it (https://docs.docker.com/engine/install/), then run this again." ;;
    esac
    say "Downloading Docker's install script..."
    fetch "https://get.docker.com" "$WORK/get-docker.sh" || die "could not download Docker's install script from https://get.docker.com.
Check this computer's internet connection and run this again."
    say "Installing Docker. This can take several minutes on a Raspberry Pi."
    as_root sh "$WORK/get-docker.sh" </dev/null || die "Docker's install script stopped with an error (shown above).
Install Docker and its Compose plugin by hand with Docker's own guide for this system:
  https://docs.docker.com/engine/install/debian/   (Debian and Raspberry Pi OS)
  https://docs.docker.com/engine/install/ubuntu/   (Ubuntu)
then run this again."
    have docker || die "Docker's install script finished, but the docker command still cannot be found.
Open a new terminal and run this again."
}

# Make sure "docker compose" works, which QuietNet uses to build and start its container.
ensure_compose() {
    if as_root docker compose version >/dev/null 2>&1 </dev/null; then
        return 0
    fi
    die "Docker is installed, but its Compose plugin (the \"docker compose\" command) is missing.
Install it with one of these, then run this again:
  sudo apt-get install docker-compose-plugin   (when Docker came from Docker's own packages)
  sudo apt-get install docker-compose-v2       (when Docker came from Ubuntu's own packages)
If Docker came from Debian's or Raspberry Pi OS's own packages (docker.io), those do not include
the plugin: install Docker from Docker's own packages instead, following
  https://docs.docker.com/engine/install/debian/"
}

# Make sure the Docker service is running, starting it once if it is not.
ensure_daemon() {
    if as_root docker info >/dev/null 2>&1 </dev/null; then
        return 0
    fi
    if have systemctl; then
        say "The Docker service is not running. Starting it..."
        as_root systemctl start docker </dev/null >/dev/null 2>&1 || true
        if as_root docker info >/dev/null 2>&1 </dev/null; then
            return 0
        fi
    fi
    die "Docker is installed but its service is not running or cannot be reached.
Start it with: sudo systemctl start docker
then run this again. If that fails, \"sudo journalctl -u docker\" shows why."
}

# True when a container called "quietnet" exists, running or not.
container_exists() {
    as_root docker inspect --format '{{.Id}}' "$CONTAINER" >/dev/null 2>&1 </dev/null
}

# Print the Compose project name of the existing "quietnet" container. It prints nothing both when
# there is no such container and when the container has no project label, so check
# container_exists first.
container_project() {
    as_root docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$CONTAINER" 2>/dev/null </dev/null || true
}

# True when the "quietnet" container exists and is running.
container_running() {
    [ "$(as_root docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null </dev/null || true)" = "true" ]
}

# Stop if a container called "quietnet" exists that this installer did not make, rather than fight
# over the name. A container started with "docker compose up" in a folder called QuietNet has the
# same project name as this installer uses, so it is simply taken over, data and all.
check_container_owner() {
    container_exists || return 0
    proj="$(container_project)"
    if [ "$proj" = "$PROJECT" ]; then
        return 0
    fi
    where="$(as_root docker inspect --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' "$CONTAINER" 2>/dev/null </dev/null || true)"
    case "$where" in
        "") hint="Remove it with: sudo docker rm -f $CONTAINER" ;;
        *) hint="It was started from the folder $where. Stop it there with: cd $where && sudo docker compose down" ;;
    esac
    die "a container called \"$CONTAINER\" already exists, and it was not started by this installer.
$hint
(Stopping it does not delete its data.) Then run this again. Note that its history and rules are kept
in its own Docker volume, so the new install starts with empty ones."
}

# Download the chosen version of QuietNet from GitHub and unpack it. Sets SOURCE to the unpacked folder.
download_source() {
    step "Downloading QuietNet ($QUIETNET_REPO, $REF)"
    url="https://codeload.github.com/$QUIETNET_REPO/tar.gz/$REF"
    fetch "$url" "$WORK/quietnet.tar.gz" || die "could not download $url
Check this computer's internet connection, and that \"$REF\" is a real branch or tag, then run this again."
    mkdir "$WORK/src"
    tar -xzf "$WORK/quietnet.tar.gz" -C "$WORK/src" || die "the download was damaged and could not be unpacked. Run this again."
    set -- "$WORK/src"/*
    if [ $# -ne 1 ] || [ ! -d "$1" ]; then
        die "the download did not hold the expected single QuietNet folder. Run this again."
    fi
    SOURCE="$1"
    for f in server.py Dockerfile docker-compose.yml; do
        [ -f "$SOURCE/$f" ] || die "the download is missing $f, so it is not a complete copy of QuietNet.
Check the --ref name and the QUIETNET_REPO setting, then run this again."
    done
}

# Put the downloaded files into the install folder, replacing the old ones in one move so an
# update never leaves a mixture. Only QuietNet's own folder is ever removed.
install_files() {
    step "Installing the program files in $QUIETNET_DIR"
    dir_is_ours || die "$QUIETNET_DIR already holds other files, and this installer replaces that folder.
(A copy of QuietNet with its own data folder or git history counts as other files, so its history
and rules are not lost; nor does a folder this installer cannot read.)
Move them somewhere else, or choose another folder with QUIETNET_DIR=/some/folder, then run this again."
    as_root mkdir -p "$(dirname "$QUIETNET_DIR")"
    STAGE="$(as_root mktemp -d "$QUIETNET_DIR.new.XXXXXX")" || die "could not make a folder next to $QUIETNET_DIR."
    as_root cp -R "$SOURCE/." "$STAGE/" || die "could not copy the program files into $STAGE."
    as_root chmod 755 "$STAGE"
    if as_root test -d "$QUIETNET_DIR" </dev/null; then
        old="$STAGE.old"
        as_root mv "$QUIETNET_DIR" "$old" || die "could not move the old program files out of the way."
        if ! as_root mv "$STAGE" "$QUIETNET_DIR"; then
            as_root mv "$old" "$QUIETNET_DIR" || true
            die "could not put the new program files in place. The old ones were left as they were."
        fi
        as_root rm -rf "$old"
    else
        as_root mv "$STAGE" "$QUIETNET_DIR" || die "could not put the program files in $QUIETNET_DIR."
    fi
    STAGE=""
    say "Done. (Your history and rules are kept in Docker's \"$VOLUME\" volume, not in this folder.)"
}

# List what is listening on port 53, one per line: "resolved" for this computer's own name
# service (systemd-resolved), "ours" for a running QuietNet, or "other NAME" for anything else.
port_53_users() {
    ours="no"
    if container_running; then ours="yes"; fi
    as_root ss -lntup 2>/dev/null </dev/null | awk -v ours="$ours" '
        $5 ~ /:53$/ {
            if ($0 ~ /systemd-resolve/ || $5 ~ /^127\.0\.0\.5[34]/) { print "resolved" }
            else if (ours == "yes" && $0 ~ /python/) { print "ours" }
            else {
                n = "an unknown program"
                if (match($0, /users:\(\("[^"]*"/)) { n = substr($0, RSTART + 9, RLENGTH - 10) }
                print "other " n
            }
        }' | sort -u
}

# Make sure DNS port 53 is free for QuietNet, offering to switch off systemd-resolved's own
# listener (common on Ubuntu) since devices will be asking QuietNet instead.
check_port_53() {
    step "Checking that DNS port 53 is free"
    if ! have ss; then
        warn "the ss command is missing, so port 53 could not be checked. If QuietNet's page says the
filter could not start, something else is using port 53."
        return 0
    fi
    users="$(port_53_users)"
    others="$(printf '%s\n' "$users" | sed -n 's/^other //p' | tr '\n' ' ')"
    if [ -n "$others" ]; then
        die "another program is already answering on DNS port 53: $others
QuietNet needs that port, because it is how devices send it their lookups. If this computer runs
another DNS filter (such as Pi-hole or dnsmasq), stop and disable it first, for example:
  sudo systemctl disable --now dnsmasq
then run this again."
    fi
    if printf '%s\n' "$users" | grep -q '^resolved$'; then
        say "This computer's own name service (systemd-resolved) is listening on port 53."
        say "It can be told to stop listening there; this computer then asks its usual DNS servers directly."
        rc=0
        ask "Switch off systemd-resolved's port 53 listener?" || rc=$?
        case "$rc" in
            0) free_resolved_port ;;
            2) die "port 53 is held by systemd-resolved, and there is no terminal here to ask about it.
Run the same command again with --yes added at the end, or switch it off yourself:
  add \"DNSStubListener=no\" under [Resolve] in /etc/systemd/resolved.conf, then
  sudo systemctl restart systemd-resolved" ;;
            *) die "QuietNet needs port 53. To free it, add \"DNSStubListener=no\" under [Resolve] in
/etc/systemd/resolved.conf, run: sudo systemctl restart systemd-resolved, then run this again." ;;
        esac
    else
        say "Port 53 is free."
    fi
}

# Turn off systemd-resolved's listener on port 53 with a settings file of our own, and point this
# computer's own lookups at the real DNS servers instead of that listener.
free_resolved_port() {
    write_root_file "$SYSROOT/etc/systemd/resolved.conf.d/quietnet.conf" "# Added by the QuietNet installer: QuietNet answers DNS on port 53.
# Delete this file and run \"sudo systemctl restart systemd-resolved\" to undo it.
[Resolve]
DNSStubListener=no"
    conf="$SYSROOT/etc/resolv.conf"
    if [ -L "$conf" ]; then
        case "$(readlink "$conf" 2>/dev/null || true)" in
            *stub-resolv.conf)
                # It points at the listener being switched off; point it at the real servers.
                as_root ln -sf /run/systemd/resolve/resolv.conf "$conf" ;;
        esac
    fi
    as_root systemctl restart systemd-resolved </dev/null || die "could not restart systemd-resolved.
Run: sudo systemctl restart systemd-resolved, then run this again."
    say "Switched off. (To undo: delete /etc/systemd/resolved.conf.d/quietnet.conf and restart systemd-resolved.)"
}

# Let this computer pass traffic on for other devices, which "Cut live connections" needs.
enable_forwarding() {
    step "Allowing this computer to pass traffic on (needed only for \"Cut live connections\")"
    file="$SYSROOT/etc/sysctl.d/90-quietnet.conf"
    if grep -qs '^net\.ipv4\.ip_forward *= *1' "$file"; then
        say "Already set."
        return 0
    fi
    write_root_file "$file" "net.ipv4.ip_forward=1"
    if ! as_root sysctl --system >/dev/null 2>&1 </dev/null; then
        as_root sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 </dev/null || warn "could not switch it on now; it will be on after the next restart."
    fi
    say "Done."
}

# Print the name of the network connection this computer reaches its router on (like eth0 or
# wlan0), from its default route, or nothing if it has none. It is checked by check_iface before use.
default_iface() {
    if have ip; then
        ip -4 route show default 2>/dev/null </dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1
    fi
}

# True when a network connection's name is safe to put in a firewall rule: 1 to 15 letters,
# digits, dots, dashes or underscores (Linux's own limit), not starting with a dash or a dot.
check_iface() {
    case "$1" in
        ""|-*|.*|*[!"$LOWER$UPPER$DIGITS"._-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ]
}

# True when iptables can be run as the administrator. It usually lives in /usr/sbin, which an
# ordinary user's search path may leave out but root's (and sudo's) includes.
have_iptables() {
    have iptables || as_root sh -c 'command -v iptables' >/dev/null 2>&1 </dev/null
}

# The text of the systemd unit that lets traffic in and out on one network connection pass
# through Docker's firewall. It adds its rule only when the rule is not there already, so starting
# it again (or after a rule added by hand) never adds a second copy.
forward_unit_text() {
    rule="DOCKER-USER -i $1 -o $1 -j ACCEPT"
    printf '%s\n' "# Written by the QuietNet installer. It lets devices that QuietNet steers through this computer
# (for \"Cut live connections\") pass on through Docker's firewall, and only traffic that comes in
# on $1 and goes straight back out on $1. To remove it:
#   sudo systemctl disable --now quietnet-forward && sudo rm /etc/systemd/system/quietnet-forward.service
[Unit]
Description=Let QuietNet pass on traffic on $1 through Docker's firewall
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -C $rule 2>/dev/null || iptables -I $rule'

[Install]
WantedBy=docker.service"
}

# Docker's firewall drops traffic this computer passes on for other devices, which "Cut live
# connections" relies on. Offer to add a small systemd service that lets through only traffic that
# comes in and goes back out on the connection to the router, and adds that rule again after every
# restart (a rule added by hand is lost when the computer restarts). It never stops the install:
# anything missing or refused is skipped with a note.
allow_forwarding_through_docker() {
    step "Letting passed-on traffic through Docker's firewall (needed only for \"Cut live connections\")"
    unit="$SYSROOT/etc/systemd/system/quietnet-forward.service"
    if ! have systemctl; then
        warn "skipped: this computer does not use systemd, so the setting could not be made to last.
If \"Cut live connections\" says another firewall blocks passed-on traffic, run the command it shows."
        return 0
    fi
    if ! have_iptables; then
        warn "skipped: the iptables command is not installed, so Docker's firewall cannot be changed.
If \"Cut live connections\" says another firewall blocks passed-on traffic, install iptables and run this again."
        return 0
    fi
    iface="$(default_iface)"
    if [ -z "$iface" ]; then
        warn "skipped: could not tell which network connection this computer reaches its router on."
        return 0
    fi
    if ! check_iface "$iface"; then
        warn "skipped: the network connection's name ($iface) is not one that is safe to put in a firewall rule."
        return 0
    fi
    text="$(forward_unit_text "$iface")"
    if as_root test -e "$unit" </dev/null; then
        old="$(as_root cat "$unit" 2>/dev/null </dev/null || true)"
        if [ "$old" = "$text" ]; then
            as_root systemctl enable --now quietnet-forward.service </dev/null >/dev/null 2>&1 \
                || warn "the setting is in place but could not be switched on. See why with: sudo systemctl status quietnet-forward"
            say "Already set up."
            return 0
        fi
        case "$old" in
            "# Written by the QuietNet installer."*) ;;
            *) say "A quietnet-forward service that this installer did not write is already here, so it was left alone.
(To let the installer manage it instead, delete /etc/systemd/system/quietnet-forward.service and run this again.)"
               return 0 ;;
        esac
    fi
    say "Docker's firewall stops this computer passing traffic on for other devices, which"
    say "\"Cut live connections\" needs. A small service can let through only traffic that comes in"
    say "on this computer's network connection ($iface) and goes straight back out on it, and set"
    say "that up again after every restart. It does not open anything to the internet or to"
    say "QuietNet's container."
    rc=0
    ask "Add that service?" || rc=$?
    case "$rc" in
        0) ;;
        2) say "Skipped, as there is no terminal here to ask on. Run the install command again with --yes to add it."
           return 0 ;;
        *) say "Skipped. \"Cut live connections\" will say what to run if it needs it."
           return 0 ;;
    esac
    write_root_file "$unit" "$text"
    as_root systemctl daemon-reload </dev/null >/dev/null 2>&1 || true
    if as_root systemctl enable --now quietnet-forward.service </dev/null >/dev/null 2>&1; then
        say "Done. (To undo: sudo systemctl disable --now quietnet-forward && sudo rm /etc/systemd/system/quietnet-forward.service)"
    else
        warn "the service was added but could not be started. See why with: sudo systemctl status quietnet-forward"
    fi
}

# Build and start QuietNet's container. The relay address and pairing code, when given, are
# passed only in the environment of this one command and are never written to a file.
start_quietnet() {
    step "Building and starting QuietNet (the first time can take several minutes on a Raspberry Pi)"
    cd "$QUIETNET_DIR" || die "could not open $QUIETNET_DIR."
    if [ -n "$RELAY" ]; then
        as_root env QUIETNET_CLOUD="$RELAY" QUIETNET_PAIR="$CODE" docker compose -p "$PROJECT" up -d --build </dev/null \
            || die "Docker could not build or start QuietNet (the reason is shown above). Fix that, then run this again."
    else
        as_root docker compose -p "$PROJECT" up -d --build </dev/null \
            || die "Docker could not build or start QuietNet (the reason is shown above). Fix that, then run this again."
    fi
    cd / || true
}

# Wait up to about 30 seconds for the container to be running.
wait_until_running() {
    n=0
    while [ "$n" -lt 30 ]; do
        if container_running; then
            return 0
        fi
        n=$((n + 1))
        sleep 1
    done
    die "QuietNet's container did not stay running. See why with: sudo docker logs $CONTAINER"
}

# Print this computer's address on the home network: the one it uses to reach the internet.
home_address() {
    a=""
    if have ip; then
        a="$(ip -4 route get 1.1.1.1 2>/dev/null </dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)"
    fi
    if [ -z "$a" ] && have hostname; then
        for x in $(hostname -I 2>/dev/null </dev/null || true); do
            case "$x" in
                *:*|127.*|172.17.*) ;;
                *.*.*.*) a="$x"; break ;;
            esac
        done
    fi
    printf '%s' "$a"
}

# Tell the person what to do next: point their router's DNS at this computer.
finish_message() {
    addr="$(home_address)"
    step "QuietNet is running"
    if [ -n "$addr" ]; then
        say "This computer's address on your home network is: $addr"
        say ""
        say "Next, in your router's settings, set the DNS server to $addr"
        say "(or set it on each device you want QuietNet to look after)."
        say "It is best to have the router always give this computer the same address,"
        say "usually called a \"DHCP reservation\" or \"fixed address\" in the router's settings."
    else
        say "Next, find this computer's address on your home network and set it as the DNS server"
        say "in your router's settings (or on each device you want QuietNet to look after)."
    fi
    say ""
    say "The dashboard opens only on this computer, at http://localhost:8377"
    if [ -n "$addr" ]; then
        say "From another computer at home, open a tunnel with: ssh -L 8377:localhost:8377 $(id -un 2>/dev/null || echo pi)@$addr"
        say "then open http://localhost:8377 on that computer. Or pair with your relay to reach it from anywhere."
    fi
    if [ -n "$RELAY" ]; then
        say ""
        say "Pairing with $RELAY: this QuietNet should appear on your relay's page within a minute."
        say "If it does not, see why with: sudo docker logs $CONTAINER"
        say "(A QuietNet that was already paired keeps its pairing and ignores the code.)"
    fi
    say ""
    say "To update QuietNet later, run the same install command again; your history and rules are kept."
    say "QuietNet is proprietary software; see the LICENSE file in $QUIETNET_DIR."
}

# Stop and remove QuietNet's container and program folder, keeping the household's data volume.
uninstall() {
    check_linux
    check_root
    step "Removing QuietNet"
    if have docker && as_root docker info >/dev/null 2>&1 </dev/null; then
        proj=""
        exists=""
        if container_exists; then
            exists=1
            proj="$(container_project)"
        fi
        if [ "$proj" = "$PROJECT" ]; then
            if [ -f "$QUIETNET_DIR/docker-compose.yml" ] && (cd "$QUIETNET_DIR" && as_root docker compose -p "$PROJECT" down --rmi local </dev/null); then
                say "Stopped and removed QuietNet's container."
            else
                as_root docker rm -f "$CONTAINER" </dev/null >/dev/null || die "could not remove the \"$CONTAINER\" container."
                say "Stopped and removed QuietNet's container."
            fi
        elif [ -n "$exists" ]; then
            warn "the \"$CONTAINER\" container was not started by this installer, so it was left alone.
Stop it where it was started (for a Compose project: sudo docker compose down in its folder)."
        else
            say "No QuietNet container was found."
        fi
    else
        warn "Docker is not installed or not running, so no container was stopped."
    fi
    if as_root test -e "$QUIETNET_DIR" </dev/null; then
        if dir_is_ours; then
            as_root rm -rf "$QUIETNET_DIR"
            say "Removed $QUIETNET_DIR."
        else
            warn "$QUIETNET_DIR holds files that are not QuietNet's, so it was left alone."
        fi
    fi
    say ""
    say "Your history and rules are kept in Docker's \"$VOLUME\" volume, so installing again picks them up."
    say "To delete them for good: sudo docker volume rm $VOLUME"
    if [ -f "$SYSROOT/etc/sysctl.d/90-quietnet.conf" ]; then
        say "Traffic forwarding was left on. To undo it: sudo rm /etc/sysctl.d/90-quietnet.conf (it goes off at the next restart)."
    fi
    if [ -f "$SYSROOT/etc/systemd/system/quietnet-forward.service" ]; then
        say "Docker's firewall still lets passed-on traffic through. To undo it: sudo systemctl disable --now quietnet-forward && sudo rm /etc/systemd/system/quietnet-forward.service (the rule it added goes at the next restart)."
    fi
    if [ -f "$SYSROOT/etc/systemd/resolved.conf.d/quietnet.conf" ]; then
        say "To give port 53 back to systemd-resolved: sudo rm /etc/systemd/resolved.conf.d/quietnet.conf && sudo systemctl restart systemd-resolved"
    fi
}

# Install or update QuietNet: check everything given, then do each step in turn.
main() {
    parse_args "$@"
    check_ref
    check_repo
    check_dir
    if [ -n "$UNINSTALL" ]; then
        [ -z "$RELAY$CODE" ] || bad_value "--uninstall cannot be combined with --relay or --code."
        uninstall
        return 0
    fi
    if [ -n "$RELAY" ] && [ -z "$CODE" ]; then
        bad_value "--relay needs --code too: the pairing code your relay's page shows."
    fi
    if [ -n "$CODE" ] && [ -z "$RELAY" ]; then
        bad_value "--code needs --relay too: your relay's web address."
    fi
    if [ -n "$RELAY" ]; then
        check_relay
        check_code
    fi

    say "Installing QuietNet into $QUIETNET_DIR"
    check_linux
    check_root
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM
    make_work_folder
    ensure_docker
    ensure_compose
    ensure_daemon
    check_container_owner
    download_source
    install_files
    check_port_53
    enable_forwarding
    allow_forwarding_through_docker
    start_quietnet
    wait_until_running
    finish_message
}

# The only line that does anything. Inside braces, so a copy cut off before the end does nothing.
{ main "$@"; exit $?; }
