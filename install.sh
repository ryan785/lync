#!/bin/sh
# install.sh - install Lync from a GitHub Release package.
#
#   curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh -s -- --version v0.2.0
#
# Downloads the .deb / .rpm / .apk for this machine's architecture
# (amd64, arm64) plus SHA256SUMS, verifies the checksum and installs the
# package with the native tool (apt-get, dnf, yum, zypper, apk). The package
# enables and starts lync.service when systemd is running. Nothing is
# compiled and no build tools are installed. On other distros the static
# binaries, config and systemd unit are installed by hand under the same
# paths. The temporary download directory is removed on exit.
#
# Options / environment:
#   --version vX.Y.Z   release to install (LYNC_VERSION; default: latest)
#   --base-url URL     directory holding the release assets (LYNC_BASE_URL;
#                      a mirror, or file:///path/to/dist for local testing)
#   LYNC_REPO          GitHub repository (default: ryan785/lync)

set -eu

REPO=${LYNC_REPO:-ryan785/lync}
VERSION=${LYNC_VERSION:-latest}
BASE_URL=${LYNC_BASE_URL:-}
TMP=""

say() { printf '[lync] %s\n' "$*"; }
die() {
	printf '[lync] error: %s\n' "$*" >&2
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() { [ -z "$TMP" ] || rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
	cat <<'EOF'
usage: install.sh [--version vX.Y.Z] [--base-url URL]
  --version vX.Y.Z   release to install (default: latest)
  --base-url URL     directory holding the release assets (mirror, or file:///path)
Installs the lync .deb/.rpm/.apk for this machine and starts lync.service.
EOF
	exit "$1"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		[ $# -ge 2 ] || die "--version needs a value (e.g. v0.2.0)"
		VERSION=$2
		shift 2
		;;
	--version=*)
		VERSION=${1#*=}
		shift
		;;
	--base-url)
		[ $# -ge 2 ] || die "--base-url needs a value"
		BASE_URL=$2
		shift 2
		;;
	--base-url=*)
		BASE_URL=${1#*=}
		shift
		;;
	-h | --help) usage 0 ;;
	*) die "unknown option: $1 (try --help)" ;;
	esac
done
case "$VERSION" in
latest | v[0-9]*) ;;
[0-9]*) VERSION="v$VERSION" ;;
*) die "bad version '$VERSION' (expected latest or vX.Y.Z)" ;;
esac

[ "$(id -u)" -eq 0 ] || die "run as root (pipe into 'sudo sh')"

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m) (packages exist for amd64 and arm64)" ;;
esac

# Package tools and systemctl get </dev/null: under `curl | sh` stdin is
# the rest of this script.

# Package family, by the package manager that is actually present.
if have apk; then
	FAMILY=apk
elif have apt-get && have dpkg; then
	FAMILY=deb
elif have dnf; then
	FAMILY=rpm PKGTOOL=dnf
elif have yum; then
	FAMILY=rpm PKGTOOL=yum
elif have zypper; then
	FAMILY=rpm PKGTOOL=zypper
else
	FAMILY=manual
fi

# --- download + verify -------------------------------------------------------
url_for() {
	if [ -n "$BASE_URL" ]; then
		echo "${BASE_URL%/}/$1"
	elif [ "$VERSION" = latest ]; then
		echo "https://github.com/$REPO/releases/latest/download/$1"
	else
		echo "https://github.com/$REPO/releases/download/$VERSION/$1"
	fi
}

fetch() { # NAME
	u=$(url_for "$1")
	if [ "${u#file://}" != "$u" ] && ! have curl; then
		cp "${u#file://}" "$TMP/$1"
	elif have curl; then
		curl -fsSL --retry 3 -o "$TMP/$1" "$u"
	elif have wget; then
		wget -q -O "$TMP/$1" "$u"
	else
		die "need curl or wget to download $u"
	fi || die "download failed: $u"
}

sha256() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		die "need sha256sum, shasum or openssl to verify downloads"
	fi
}

verify() { # NAME
	want=$(awk -v n="$1" '$2 == n || $2 == "*"n {print $1; exit}' "$TMP/SHA256SUMS")
	[ -n "$want" ] || die "$1 is not listed in SHA256SUMS"
	got=$(sha256 "$TMP/$1")
	[ "$got" = "$want" ] || die "checksum mismatch for $1 (expected $want, got $got)"
}

get() { # NAME
	say "downloading $1"
	fetch "$1"
	verify "$1"
}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/lync-install.XXXXXX") || die "mktemp failed"
# apt drops privileges to _apt when reading local .deb files.
chmod 755 "$TMP"

say "release: ${BASE_URL:-$VERSION ($REPO)}, arch: $ARCH, installer: $FAMILY"
fetch SHA256SUMS

# --- install -----------------------------------------------------------------
install_manual() {
	f=lync-linux-$ARCH.tar.gz
	get "$f"
	mkdir "$TMP/x"
	tar -xzf "$TMP/$f" -C "$TMP/x"
	install -d -m 0755 /usr/sbin /usr/bin /etc/lync /var/lib/lync/feeds /var/lib/lync/reports
	install -m 0755 "$TMP/x/usr/sbin/lyncd" /usr/sbin/lyncd
	install -m 0755 "$TMP/x/usr/bin/lync" /usr/bin/lync
	if [ -e /etc/lync/lync.yaml ]; then
		install -m 0644 "$TMP/x/etc/lync/lync.yaml" /etc/lync/lync.yaml.new
		say "kept existing /etc/lync/lync.yaml (new default saved as lync.yaml.new)"
	else
		install -m 0644 "$TMP/x/etc/lync/lync.yaml" /etc/lync/lync.yaml
	fi
	if [ -d /run/systemd/system ] || have systemctl; then
		install -d -m 0755 /usr/lib/systemd/system
		install -m 0644 "$TMP/x/usr/lib/systemd/system/lync.service" /usr/lib/systemd/system/lync.service
	fi
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload
		systemctl enable lync.service >/dev/null 2>&1 || true
		systemctl restart lync.service </dev/null || say "the service did not start; see: journalctl -u lync -n 50 --no-pager"
	fi
}

case "$FAMILY" in
deb)
	f=lync-linux-$ARCH.deb
	get "$f"
	DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$TMP/$f" </dev/null
	UNINSTALL="sudo apt-get remove lync   (purge also deletes /etc/lync and /var/lib/lync)"
	;;
rpm)
	f=lync-linux-$ARCH.rpm
	get "$f"
	case "$PKGTOOL" in
	dnf) dnf install -y "$TMP/$f" </dev/null ;;
	yum) yum install -y "$TMP/$f" </dev/null ;;
	zypper) zypper --non-interactive install --allow-unsigned-rpm "$TMP/$f" </dev/null ;;
	esac
	UNINSTALL="sudo $PKGTOOL remove lync"
	;;
apk)
	f=lync-linux-$ARCH.apk
	get "$f"
	apk add --allow-untrusted "$TMP/$f" </dev/null
	UNINSTALL="sudo apk del lync"
	;;
manual)
	say "no apt/dnf/yum/zypper/apk found: installing the static binaries by hand"
	install_manual
	UNINSTALL="sudo systemctl disable --now lync; sudo rm -f /usr/sbin/lyncd /usr/bin/lync /usr/lib/systemd/system/lync.service; sudo rm -rf /etc/lync /var/lib/lync"
	;;
esac

# --- report ------------------------------------------------------------------
echo
if [ -d /run/systemd/system ]; then
	systemctl status lync --no-pager </dev/null || true
else
	say "systemd is not running here; start the daemon with '/usr/sbin/lyncd &' or run a single scan with 'lyncd -once'."
fi
echo
lync version || die "lync is not on PATH after install"
echo
say "installed. Status: lync status | Scan now: lync scan | Reports: /var/lib/lync/reports/"
say "config: /etc/lync/lync.yaml (restart lync after edits)"
say "uninstall: $UNINSTALL"
