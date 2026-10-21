#!/bin/sh
# run.sh - run Lync once on this host without installing anything.
#
#   curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh
#   ... | sudo sh -s -- --cve CVE-2026-109618
#
# What it does:
#   1. creates a private temp dir (mktemp -d, mode 700) on a filesystem
#      that allows exec and has enough space (/dev/shm, $TMPDIR, /tmp,
#      /var/tmp in that order);
#   2. puts the static lyncd binary there: downloaded from GitHub Releases
#      (LYNC_GH_TOKEN for a private repo) or received over SSH from
#      lync-run (--bundle-stdin); the SHA256 is verified before it runs;
#   3. runs one scan (or one --cve check) at low priority with a timeout:
#      feeds download into the temp dir, the report is written there;
#   4. hands the report back (stdout, --keep-report DIR, or a tar stream
#      for lync-run), then removes the temp dir on exit, Ctrl-C, SIGTERM
#      or SSH hangup.
# The only file left on the host is the log (default
# /var/log/lync-run-<UTC>.log as root, else ~/lync-run-<UTC>.log), which
# records every command, download, file and check.
#
# Exit codes: 0 ok | 1 usage | 2 preflight (temp space, arch, tools) |
# 3 download/checksum | 4 scan failed | 5 report produced but a feed
# failed | 10/11/12 --cve affected/possibly/unknown | 129/130/143 signal.
#
# Environment: LYNC_GH_TOKEN, LYNC_REPO (ryan785/lync), LYNC_VERSION
# (latest | vX.Y.Z), LYNC_BASE_URL (mirror dir holding lyncd-linux-<arch>
# + SHA256SUMS), LYNC_NVD_KEY, LYNC_LOG, LYNC_MIN_FREE_MB (300),
# LYNC_TIMEOUT (seconds, 3600).

set -u
umask 077

REPO=${LYNC_REPO:-ryan785/lync}
VERSION=${LYNC_VERSION:-latest}
MIN_FREE_MB=${LYNC_MIN_FREE_MB:-300}
RUN_TIMEOUT=${LYNC_TIMEOUT:-3600}
CVE=""
SOURCES="auto"
CACHE_SRC=""
KEEP_DIR=""
CONTAINER_EXEC=0
BUNDLE_STDIN=0
TAR_OUT=0
SAVE_CACHE=0
LOG=${LYNC_LOG:-}
T=""
LPID=""
FINAL_RC=0

usage() {
	cat >&2 <<'EOF'
usage: run.sh [--cve CVE-ID] [--keep-report DIR] [--cache DIR] [--sources auto|LIST]
              [--container-exec] [--log FILE] [--min-free-mb N] [--timeout SECS]
  --cve ID          check one CVE instead of a full scan (exit 0/10/11/12)
  --keep-report DIR also copy report JSON+PDF to DIR (default: JSON to stdout only)
  --cache DIR       seed the feed cache from DIR (copied; DIR is not modified)
  --container-exec  enable the opt-in `docker exec php -r` check
  --log FILE        log path (default /var/log/lync-run-<UTC>.log as root)
Internal (used by lync-run): --bundle-stdin --tar-out --save-cache
EOF
	exit 1
}

while [ $# -gt 0 ]; do
	case $1 in
	--cve) [ $# -ge 2 ] || usage; CVE=$2; shift ;;
	--keep-report) [ $# -ge 2 ] || usage; KEEP_DIR=$2; shift ;;
	--cache) [ $# -ge 2 ] || usage; CACHE_SRC=$2; shift ;;
	--sources) [ $# -ge 2 ] || usage; SOURCES=$2; shift ;;
	--log) [ $# -ge 2 ] || usage; LOG=$2; shift ;;
	--min-free-mb) [ $# -ge 2 ] || usage; MIN_FREE_MB=$2; shift ;;
	--timeout) [ $# -ge 2 ] || usage; RUN_TIMEOUT=$2; shift ;;
	--container-exec) CONTAINER_EXEC=1 ;;
	--bundle-stdin) BUNDLE_STDIN=1 ;;
	--tar-out) TAR_OUT=1 ;;
	--save-cache) SAVE_CACHE=1 ;;
	-h | --help) usage ;;
	*) echo "run.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

case $CVE in
"" | CVE-[0-9][0-9][0-9][0-9]-[0-9]*) ;;
*) echo "run.sh: --cve wants CVE-YYYY-NNNN" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
if [ -z "$LOG" ]; then
	if [ "$(id -u)" = 0 ]; then
		LOG=/var/log/lync-run-$TS.log
	else
		LOG=${HOME:-/tmp}/lync-run-$TS.log
	fi
fi
if ! : >>"$LOG" 2>/dev/null; then
	echo "run.sh: cannot write log $LOG (use --log FILE)" >&2
	exit 2
fi
chmod 600 "$LOG" 2>/dev/null

# --- logging -----------------------------------------------------------------

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# log KIND MESSAGE...: one line in the run log (tokens never passed in).
log() {
	k=$1
	shift
	printf '%s %-7s %s\n' "$(now)" "$k" "$*" >>"$LOG"
}

# say MESSAGE: progress on stderr (stdout is reserved for results).
say() { printf 'lync-run: %s\n' "$*" >&2; }

# run_cmd CMD...: run, log exact command, exit code and duration.
run_cmd() {
	rc_start=$(date +%s)
	"$@"
	rc=$?
	log CMD "$* exit=$rc dur=$(($(date +%s) - rc_start))s"
	return $rc
}

die() {
	code=$1
	shift
	say "$*"
	log ERROR "$* (exit $code)"
	exit "$code"
}

# --- cleanup (runs on every exit path) --------------------------------------

# shellcheck disable=SC2317 # invoked via trap
cleanup() {
	rc=$?
	[ "$FINAL_RC" != 0 ] && rc=$FINAL_RC
	trap - EXIT INT TERM HUP
	if [ -n "$LPID" ] && kill -0 "$LPID" 2>/dev/null; then
		kill -TERM "$LPID" 2>/dev/null
		sleep 2
		kill -KILL "$LPID" 2>/dev/null
		log CLEANUP "stopped lyncd pid $LPID"
	fi
	if [ -n "$T" ] && [ -d "$T" ]; then
		n=$(find "$T" -type f 2>/dev/null | wc -l | tr -d ' ')
		kb=$(du -sk "$T" 2>/dev/null | awk '{print $1}')
		find "$T" -type f 2>/dev/null | while IFS= read -r f; do
			log FILE- "$f $(wc -c <"$f" 2>/dev/null | tr -d ' ')B"
		done
		rm -rf "$T"
		if [ -e "$T" ]; then
			log CLEANUP "FAILED to remove $T"
			say "WARNING: could not remove $T"
		else
			log CLEANUP "removed $T ($n files, ${kb:-0}KB); verified absent"
		fi
	fi
	log END "exit=$rc log=$LOG (the only file this run leaves on the host)"
	say "done (exit $rc). Log: $LOG"
	printf 'LYNC_LOG_PATH=%s\n' "$LOG" >&2
	exit "$rc"
}
trap cleanup EXIT
trap 'FINAL_RC=130; exit 130' INT
trap 'FINAL_RC=143; exit 143' TERM
trap 'FINAL_RC=129; exit 129' HUP

# --- start ---------------------------------------------------------------------

log START "lync run.sh pid=$$ user=$(id -un 2>/dev/null)($(id -u)) cwd=$(pwd) args: cve=${CVE:-none} sources=$SOURCES keep_report=${KEEP_DIR:-no} cache=${CACHE_SRC:-none} container_exec=$CONTAINER_EXEC bundle_stdin=$BUNDLE_STDIN"
log POLICY "read-only scan: this run writes only inside its temp dir and to this log; it installs nothing and changes no system state"
log HOST "hostname=$(hostname 2>/dev/null) uname=$(uname -srvm 2>/dev/null)"
if [ -r /etc/os-release ]; then
	# shellcheck disable=SC1091
	log HOST "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
fi
log HOST "uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)s"
[ "$(id -u)" = 0 ] || log WARN "not running as root: shadow, sudoers, other users' files and some tools will be unreadable; results will be incomplete"

# --- arch ----------------------------------------------------------------------

case $(uname -m) in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die 2 "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
esac
log HOST "arch=$ARCH"

# --- temp dir ------------------------------------------------------------------

free_mb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print int($4/1024)}'; }

pick_tmpdir() {
	for base in /dev/shm ${TMPDIR:-} /tmp /var/tmp; do
		if [ ! -d "$base" ] || [ ! -w "$base" ]; then
			continue
		fi
		fm=$(free_mb "$base")
		if [ -z "$fm" ] || [ "$fm" -lt "$MIN_FREE_MB" ]; then
			log TMP "skip $base: ${fm:-?}MB free < ${MIN_FREE_MB}MB required"
			continue
		fi
		cand=$(mktemp -d "$base/lync-run.XXXXXXXX" 2>/dev/null) || continue
		chmod 700 "$cand"
		printf '#!/bin/sh\nexit 0\n' >"$cand/exec-probe"
		chmod 700 "$cand/exec-probe"
		if "$cand/exec-probe" 2>/dev/null; then
			rm -f "$cand/exec-probe"
			T=$cand
			log TMP "using $T (mode 700, ${fm}MB free, exec allowed)"
			return 0
		fi
		log TMP "skip $base: mounted noexec"
		rm -rf "$cand"
	done
	return 1
}
pick_tmpdir || die 2 "no writable, exec-capable temp dir with ${MIN_FREE_MB}MB free (tried /dev/shm \$TMPDIR /tmp /var/tmp)"
mkdir -p "$T/out" "$T/cache" "$T/in"
log FILE+ "$T/ (out/ cache/ in/)"

# --- sha256 helper ---------------------------------------------------------------

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		return 1
	fi
}

# verify FILE NAME SUMSFILE
verify() {
	want=$(awk -v n="$2" '$2 == n || $2 == "*"n {print $1}' "$3")
	[ -n "$want" ] || die 3 "no checksum for $2 in SHA256SUMS"
	got=$(sha256 "$1") || die 2 "no sha256sum/openssl to verify the binary"
	if [ "$got" != "$want" ]; then
		die 3 "checksum mismatch for $2: got $got want $want"
	fi
	log VERIFY "$2 sha256=$got OK"
}

# --- fetch helpers ---------------------------------------------------------------

# fetch URL OUT [AUTH] - curl (or wget), retries; logs URL, status, bytes.
fetch() {
	f_url=$1
	f_out=$2
	f_auth=${3:-}
	f_try=1
	while [ $f_try -le 4 ]; do
		f_start=$(date +%s)
		case $f_url in
		file://*) # local mirror (NFS, USB, tests): no curl needed
			if cp "${f_url#file://}" "$f_out" 2>>"$T/fetch.err"; then f_code=200; else f_code=404; fi ;;
		*) f_code="" ;;
		esac
		if [ -n "$f_code" ]; then
			:
		elif command -v curl >/dev/null 2>&1; then
			if [ -n "$f_auth" ]; then
				f_code=$(curl -sSL --proto '=https' --retry 0 --connect-timeout 20 --max-time 600 \
					-H "Authorization: Bearer $f_auth" -H "Accept: application/octet-stream" \
					-w '%{http_code}' -o "$f_out" "$f_url" 2>>"$T/fetch.err")
			else
				f_code=$(curl -sSL --retry 0 --connect-timeout 20 --max-time 600 \
					-w '%{http_code}' -o "$f_out" "$f_url" 2>>"$T/fetch.err")
			fi
		elif command -v wget >/dev/null 2>&1 && [ -z "$f_auth" ]; then
			if wget -q -T 60 -O "$f_out" "$f_url" 2>>"$T/fetch.err"; then f_code=200; else f_code=000; fi
		else
			die 2 "need curl (or wget for public downloads)"
		fi
		f_bytes=$(wc -c <"$f_out" 2>/dev/null | tr -d ' ')
		log FETCH "GET $f_url status=$f_code bytes=${f_bytes:-0} dur=$(($(date +%s) - f_start))s attempt=$f_try auth=$([ -n "$f_auth" ] && echo token || echo none)"
		case $f_code in
		2??) log FILE+ "$f_out ${f_bytes:-0}B"; return 0 ;;
		401 | 403 | 404) return 1 ;;
		esac
		sleep $((f_try * 2))
		f_try=$((f_try + 1))
	done
	return 1
}

# gh_asset_url NAME: API URL of a release asset (private repos).
gh_asset_url() {
	if [ "$VERSION" = latest ]; then
		rel="https://api.github.com/repos/$REPO/releases/latest"
	else
		rel="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
	fi
	if [ ! -s "$T/release.json" ]; then
		fetch "$rel" "$T/release.json" "$LYNC_GH_TOKEN" ||
			die 3 "GitHub API $rel failed (token scope must include contents:read for $REPO)"
	fi
	tr ',' '\n' <"$T/release.json" | awk -v want="$1" '
		/"url" *: *"https:\/\/api\.github\.com\/repos\/.*\/releases\/assets\/[0-9]+"/ {
			u = $0; sub(/.*"url" *: *"/, "", u); sub(/".*/, "", u); last = u }
		/"name" *: *"/ { n = $0; sub(/.*"name" *: *"/, "", n); sub(/".*/, "", n)
			if (n == want && last != "") { print last; exit } }'
}

get_artifact() { # NAME OUT
	if [ -n "${LYNC_BASE_URL:-}" ]; then
		fetch "${LYNC_BASE_URL%/}/$1" "$2"
	elif [ -n "${LYNC_GH_TOKEN:-}" ]; then
		a_url=$(gh_asset_url "$1")
		[ -n "$a_url" ] || die 3 "release $VERSION of $REPO has no asset $1"
		fetch "$a_url" "$2" "$LYNC_GH_TOKEN"
	elif [ "$VERSION" = latest ]; then
		fetch "https://github.com/$REPO/releases/latest/download/$1" "$2"
	else
		fetch "https://github.com/$REPO/releases/download/$VERSION/$1" "$2"
	fi
}

# --- obtain the binary -------------------------------------------------------------

BIN=$T/lyncd
if [ "$BUNDLE_STDIN" = 1 ]; then
	run_cmd tar -xf - -C "$T/in" || die 3 "could not read the bundle from stdin"
	find "$T/in" -type f | while IFS= read -r f; do log FILE+ "$f $(wc -c <"$f" | tr -d ' ')B"; done
	[ -f "$T/in/lyncd-linux-$ARCH" ] || die 3 "bundle has no lyncd-linux-$ARCH"
	verify "$T/in/lyncd-linux-$ARCH" "lyncd-linux-$ARCH" "$T/in/SHA256SUMS"
	mv "$T/in/lyncd-linux-$ARCH" "$BIN"
	if [ -f "$T/in/nvd.key" ]; then
		LYNC_NVD_KEY=$(cat "$T/in/nvd.key")
		export LYNC_NVD_KEY
		rm -f "$T/in/nvd.key"
		log FILE- "$T/in/nvd.key (NVD key loaded into the lyncd environment; value not logged)"
	fi
	if [ -d "$T/in/cache" ]; then
		rmdir "$T/cache" && mv "$T/in/cache" "$T/cache"
		log CACHE "seeded feed cache from the bundle ($(du -sk "$T/cache" | awk '{print $1}')KB)"
	fi
else
	say "downloading lyncd-linux-$ARCH ($REPO $VERSION)"
	get_artifact SHA256SUMS "$T/SHA256SUMS" || die 3 "could not download SHA256SUMS"
	get_artifact "lyncd-linux-$ARCH" "$BIN" || die 3 "could not download lyncd-linux-$ARCH"
	verify "$BIN" "lyncd-linux-$ARCH" "$T/SHA256SUMS"
	if [ -n "$CACHE_SRC" ]; then
		[ -d "$CACHE_SRC" ] || die 1 "--cache $CACHE_SRC is not a directory"
		rmdir "$T/cache" && cp -R "$CACHE_SRC" "$T/cache"
		log CACHE "seeded feed cache from $CACHE_SRC (copied; source untouched)"
	fi
fi
chmod 700 "$BIN"
log BIN "$("$BIN" -version 2>&1)"

# --- run -----------------------------------------------------------------------------

set -- -once -config none -sources "$SOURCES" -cache-dir "$T/cache" -report-dir "$T/out" -audit-log "$LOG"
[ -n "$CVE" ] && set -- "$@" -cve "$CVE"
[ "$CONTAINER_EXEC" = 1 ] && set -- "$@" -enable container:php-upload-progress

prefix=""
command -v nice >/dev/null 2>&1 && prefix="nice -n 19"
command -v ionice >/dev/null 2>&1 && prefix="$prefix ionice -c 3"
command -v timeout >/dev/null 2>&1 && prefix="$prefix timeout -s TERM $RUN_TIMEOUT"
log RUN "$prefix $BIN $* $( [ -n "${LYNC_NVD_KEY:-}" ] && echo '(LYNC_NVD_KEY set in env, value not logged)')"
say "scanning (log: $LOG)"
start=$(date +%s)
# shellcheck disable=SC2086 # $prefix is a deliberately word-split command prefix
$prefix "$BIN" "$@" >"$T/out/stdout.json" 2>"$T/lyncd.stderr" &
LPID=$!
wait "$LPID"
LRC=$?
LPID=""
log RUN "lyncd exit=$LRC dur=$(($(date +%s) - start))s"
sed 's/^/          lyncd: /' "$T/lyncd.stderr" >>"$LOG"

case $LRC in
0) RC=0 ;;
3) RC=5 ;;
10 | 11 | 12) RC=$LRC ;;
124) RC=4; log ERROR "lyncd timed out after ${RUN_TIMEOUT}s" ;;
*) RC=4 ;;
esac

# --- hand results back ---------------------------------------------------------------

REPORT=""
for f in "$T/out"/lync-*.json; do
	[ -f "$f" ] && REPORT=$f && break
done
if [ -n "$CVE" ]; then
	mv "$T/out/stdout.json" "$T/out/cve-$CVE.json"
	RESULT=$T/out/cve-$CVE.json
else
	rm -f "$T/out/stdout.json"
	RESULT=$REPORT
fi
if [ -n "$KEEP_DIR" ] && [ -n "$RESULT" ]; then
	mkdir -p "$KEEP_DIR" && cp "$T/out"/* "$KEEP_DIR"/ &&
		for f in "$T/out"/*; do log KEEP "${KEEP_DIR%/}/$(basename "$f") (kept at caller's request)"; done
fi
if [ "$TAR_OUT" = 1 ]; then
	[ "$SAVE_CACHE" = 1 ] && [ -d "$T/cache" ] && cp -R "$T/cache" "$T/out/cache"
	(cd "$T/out" && tar -cf - .)
	log OUTPUT "streamed $(find "$T/out" -type f | wc -l | tr -d ' ') result files to the caller over stdout"
elif [ -n "$RESULT" ] && [ -f "$RESULT" ]; then
	cat "$RESULT"
	log OUTPUT "printed $(basename "$RESULT") to stdout"
fi
if [ -n "$REPORT" ]; then
	summary=$(tr ',' '\n' <"$REPORT" | awk -F: '/"(critical|high|medium|low|total)"/ {gsub(/[ "{}]/,""); printf "%s=%s ", $1, $2}' | head -c 200)
	log SUMMARY "$summary"
	say "findings: $summary"
fi
FINAL_RC=$RC
exit "$RC"
