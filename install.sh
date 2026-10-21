#!/bin/sh
# Lync quick installer for Linux.
#
# Detects the distro, installs build dependencies (Go, git, make), fetches
# the source, builds the binaries, installs to /usr/sbin and /etc/lync, and
# (when systemd is present) enables the lync service.
#
# Usage from a fresh host:
#   curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh
#
# Or from a clone:
#   sudo ./install.sh
#
# Environment overrides:
#   LYNC_REPO        git URL to clone        (default: https://github.com/ryan785/lync.git)
#   LYNC_REF         branch/tag/commit       (default: main)
#   LYNC_WORKDIR     build directory         (default: /tmp/lync-install)
#   LYNC_START       1 to start the service  (default: 1; set 0 to install only)
#   LYNC_NO_COLOR    1 to disable ANSI       (default: empty)

set -eu

REPO="${LYNC_REPO:-https://github.com/ryan785/lync.git}"
REF="${LYNC_REF:-main}"
WORKDIR="${LYNC_WORKDIR:-/tmp/lync-install}"
START_NOW="${LYNC_START:-1}"

# ---- output -----------------------------------------------------------------
if [ -t 1 ] && [ -z "${LYNC_NO_COLOR:-}" ]; then
  C_INFO='\033[1;36m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_OK='\033[1;32m'; C_RESET='\033[0m'
else
  C_INFO=''; C_WARN=''; C_ERR=''; C_OK=''; C_RESET=''
fi
log()  { printf "${C_INFO}[lync]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_WARN}[lync]${C_RESET} %s\n" "$*" >&2; }
err()  { printf "${C_ERR}[lync]${C_RESET} %s\n" "$*" >&2; }
ok()   { printf "${C_OK}[lync]${C_RESET} %s\n" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---- preflight --------------------------------------------------------------
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "installer must run as root (use sudo)"
    exit 1
  fi
}

detect_distro() {
  if [ ! -r /etc/os-release ]; then
    err "/etc/os-release not readable; cannot detect distro"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
  DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
}

distro_family() {
  case "$DISTRO_ID" in
    rhel|rocky|almalinux|centos|fedora|amzn|ol|oracle) echo "rhel" ;;
    debian|ubuntu|linuxmint|pop|raspbian|kali) echo "debian" ;;
    alpine) echo "alpine" ;;
    opensuse-leap|opensuse-tumbleweed|sles|suse) echo "suse" ;;
    *)
      case "$DISTRO_LIKE" in
        *rhel*|*fedora*) echo "rhel" ;;
        *debian*) echo "debian" ;;
        *suse*) echo "suse" ;;
        *) echo "unknown" ;;
      esac
      ;;
  esac
}

# ---- package installation ---------------------------------------------------
install_build_deps() {
  fam="$(distro_family)"
  case "$fam" in
    rhel)   dnf install -y golang git make ;;
    debian) apt-get update -qq && apt-get install -y golang-go git make ;;
    alpine) apk add --no-cache go git make ;;
    suse)   zypper --non-interactive install -y go git make ;;
    *)
      err "unsupported distro: $DISTRO_PRETTY"
      err "install Go (>= 1.23), git, and make manually, then re-run."
      exit 1
      ;;
  esac
}

# Returns 0 if Go >= 1.23 is available, 1 otherwise.
go_version_ok() {
  have go || return 1
  v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  major=$(echo "$v" | cut -d. -f1)
  minor=$(echo "$v" | cut -d. -f2)
  [ -n "$major" ] && [ -n "$minor" ] || return 1
  if [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 23 ]; }; then
    return 0
  fi
  return 1
}

ensure_deps() {
  if have go && have git && have make && go_version_ok; then
    log "build tools present (go $(go version | awk '{print $3}'))"
    return
  fi
  log "installing build dependencies via $(distro_family) package manager"
  install_build_deps
  if ! go_version_ok; then
    warn "Go from the distro repo is older than 1.23 (lync needs 1.23+)."
    warn "Install a newer Go from https://go.dev/dl/ and re-run this script."
    exit 1
  fi
}

# ---- source -----------------------------------------------------------------
fetch_source() {
  # If the script is run from a clone (go.mod present + module name matches),
  # build in place rather than re-cloning.
  if [ -f ./go.mod ] && grep -q "github.com/ryan785/lync" ./go.mod 2>/dev/null; then
    SOURCE_DIR="$(pwd)"
    log "using local source tree: $SOURCE_DIR"
    return
  fi
  SOURCE_DIR="$WORKDIR"
  if [ -d "$SOURCE_DIR/.git" ]; then
    log "updating existing clone at $SOURCE_DIR"
    git -C "$SOURCE_DIR" fetch --quiet --tags origin
    git -C "$SOURCE_DIR" checkout --quiet "$REF"
    git -C "$SOURCE_DIR" pull --quiet --ff-only origin "$REF" || true
  else
    log "cloning $REPO -> $SOURCE_DIR (ref $REF)"
    rm -rf "$SOURCE_DIR"
    if ! git clone --quiet --depth 1 --branch "$REF" "$REPO" "$SOURCE_DIR" 2>/dev/null; then
      # Fallback if REF is a non-branch (commit SHA, tag not as branch).
      git clone --quiet "$REPO" "$SOURCE_DIR"
      git -C "$SOURCE_DIR" checkout --quiet "$REF"
    fi
  fi
}

# ---- build / install --------------------------------------------------------
build_and_install() {
  log "building (cd $SOURCE_DIR && make build)"
  ( cd "$SOURCE_DIR" && make build )
  log "installing to /usr/sbin, /usr/bin, /etc/lync"
  ( cd "$SOURCE_DIR" && make install )
}

# ---- service ----------------------------------------------------------------
setup_service() {
  if ! have systemctl; then
    case "$DISTRO_ID" in
      alpine)
        warn "Alpine uses OpenRC. The shipped systemd unit will not be honored."
        warn "See docs/INSTALL.md for an OpenRC init script template."
        ;;
      *)
        warn "systemctl not found. Start lyncd manually: /usr/sbin/lyncd &"
        ;;
    esac
    return
  fi
  log "reloading systemd"
  systemctl daemon-reload
  if [ "$START_NOW" = "1" ]; then
    log "enabling and starting lync"
    systemctl enable --now lync
    sleep 2
    if systemctl is-active --quiet lync; then
      ok "lync is running"
    else
      warn "lync failed to start; see: journalctl -u lync --no-pager -n 50"
    fi
  else
    systemctl enable lync
    log "lync enabled but not started (LYNC_START=0). Start when ready: systemctl start lync"
  fi
}

# ---- final notes ------------------------------------------------------------
print_done() {
  echo
  ok "installation complete on $DISTRO_PRETTY"
  cat <<'EOF'

  Daemon status     :  lync status
  Trigger scan      :  lync scan
  Scope a scan      :  lync scan -package openssh   /   -service sshd   /   -kernel
  Past reports      :  lync reports
  Daemon logs       :  journalctl -u lync -f
  Config            :  /etc/lync/lync.yaml         (restart lync after edits)
  Reports written to:  /var/lib/lync/reports/

The first feed sync takes ~2 minutes with the default 30-day NVD window.
Set feed.sources[name=nvd].api_key in /etc/lync/lync.yaml (free key from
https://nvd.nist.gov/developers/request-an-api-key) for the full 120-day
window in seconds.

EOF
}

# ---- main -------------------------------------------------------------------
main() {
  require_root
  detect_distro
  log "detected: $DISTRO_PRETTY  (ID=$DISTRO_ID, family=$(distro_family))"
  ensure_deps
  fetch_source
  build_and_install
  setup_service
  print_done
}

main "$@"
