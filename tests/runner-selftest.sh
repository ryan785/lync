#!/bin/sh
# runner-selftest.sh - end-to-end test of run.sh + lync-run on THIS Linux box
# with a fake ssh (the "remote host" is localhost via `sh -c`), offline
# (--sources none: collector + all rules, no feed downloads).
#
#   make release && sudo sh tests/runner-selftest.sh
#
# Proves: results come back, the run log has the promised sections, the
# temp dir is removed on success, SIGTERM and checksum failure, nothing
# else named lync is created, and mode (b) (download from LYNC_BASE_URL)
# verifies the checksum, writes the PDF into the caller's directory (owned
# by SUDO_USER) and cleans up.

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
DIST=${DIST:-$ROOT/dist}
case $(uname -m) in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *) echo "unsupported arch"; exit 2 ;; esac
if [ ! -f "$DIST/lyncd-linux-$ARCH" ] || [ ! -f "$DIST/SHA256SUMS" ]; then
	echo "run 'make release' first"
	exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/lync-selftest.XXXXXX")
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL  $*"; }
check() { # DESC CMD...
	d=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
leftovers() { # temp dirs named like ours in every candidate base
	for b in /dev/shm /tmp /var/tmp ${TMPDIR:-}; do
		ls -d "$b"/lync-run.* "$b"/lync-run-local.* 2>/dev/null
	done | sort -u
}

# Fake ssh: drop -o options, take the host, run the remote command locally
# the way sshd does (`$SHELL -c "<command>"`).
cat >"$WORK/fake-ssh" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
	case $1 in
	-o) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
shift # host
exec sh -c "$*"
EOF
chmod 755 "$WORK/fake-ssh"

mkdir -p "$WORK/remote"
before=$(leftovers)
touch "$WORK/marker"
sleep 1

echo "== mode (a): lync-run over fake ssh"
LYNC_SSH=$WORK/fake-ssh sh ./lync-run --bin "$DIST" --out "$WORK/results" \
	--remote-log "$WORK/remote/lync-run.log" --sources none fakehost >"$WORK/table.txt" 2>"$WORK/driver.err"
rc=$?
cat "$WORK/table.txt"
check "lync-run exit 0 (got $rc)" test "$rc" = 0
HD=$(find "$WORK/results" -mindepth 2 -maxdepth 2 -type d -name fakehost | head -n 1)
check "report.json returned" test -s "$HD/report.json"
check "report.pdf returned" test -s "$HD/report.pdf"
check "host log copied back" test -s "$HD/lync-run.log"
LOG=$WORK/remote/lync-run.log
check "log: POLICY statement" grep -q ' POLICY .*installs nothing' "$LOG"
check "log: mode (a) leaves no report on the host" sh -c "! grep -q ' REPORT+ ' '$LOG'"
check "log: temp dir chosen" grep -q ' TMP .*using .*lync-run\.' "$LOG"
check "log: checksum verified" grep -q ' VERIFY .*OK' "$LOG"
check "log: package collector command" grep -Eq ' CMD +(rpm -qa|dpkg-query|apk info)' "$LOG"
check "log: rules ran" grep -q ' RULE .*web-exposure ran' "$LOG"
ncheck=$(grep -c ' CHECK ' "$LOG")
nexp=$("$DIST/lync-linux-$ARCH" -json checks -config none 2>/dev/null | grep -c '"id"')
check "log: every check listed ($ncheck of $nexp)" test "$ncheck" = "$nexp"
check "log: summary counts" grep -q ' SUMMARY .*findings=' "$LOG"
check "log: temp dir removed + verified" grep -q ' CLEANUP .*verified absent' "$LOG"
check "log: END line" grep -q ' END .*exit=0' "$LOG"
check "log: no NVD key / token text" sh -c "! grep -Eiq 'ghp_|github_pat_|apikey=[^[]' '$LOG'"
check "summary marks remote temp removed" grep -q 'fakehost.* removed' "$WORK/table.txt"

echo "== SIGTERM mid-scan"
# A stand-in "lyncd" that never finishes, so the signal always lands
# mid-scan (a real offline scan can finish in under a second).
mkdir -p "$WORK/slow"
# shellcheck disable=SC2016 # $1 belongs to the stub script
printf '#!/bin/sh\n[ "$1" = -version ] && { echo "lyncd slow-stub"; exit 0; }\nsleep 60\n' >"$WORK/slow/lyncd-linux-$ARCH"
(cd "$WORK/slow" && sha256sum "lyncd-linux-$ARCH" >SHA256SUMS)
tar -cf "$WORK/bundle.tar" -C "$WORK/slow" "lyncd-linux-$ARCH" SHA256SUMS
sh ./run.sh --bundle-stdin --tar-out --sources none --log "$WORK/term.log" <"$WORK/bundle.tar" >/dev/null 2>"$WORK/term.err" &
pid=$!
i=0
until grep -q ' RUN .*-once' "$WORK/term.log" 2>/dev/null || [ $i -ge 50 ]; do
	sleep 0.2
	i=$((i + 1))
done
sleep 0.5
kill -TERM "$pid"
wait "$pid"
rc=$?
check "SIGTERM exit 143 (got $rc)" test "$rc" = 143
check "SIGTERM: cleanup verified in log" grep -q ' CLEANUP .*verified absent' "$WORK/term.log"

echo "== checksum mismatch"
mkdir -p "$WORK/badsum"
cp "$DIST/lyncd-linux-$ARCH" "$WORK/badsum/"
echo "0000000000000000000000000000000000000000000000000000000000000000  lyncd-linux-$ARCH" >"$WORK/badsum/SHA256SUMS"
tar -cf - -C "$WORK/badsum" . | sh ./run.sh --bundle-stdin --sources none --log "$WORK/bad.log" >/dev/null 2>&1
rc=$?
check "bad checksum exit 3 (got $rc)" test "$rc" = 3
check "bad checksum: binary never ran" sh -c "! grep -q ' RUN ' '$WORK/bad.log'"
check "bad checksum: cleanup verified" grep -q ' CLEANUP .*verified absent' "$WORK/bad.log"

echo "== mode (b): download from LYNC_BASE_URL, PDF lands in the caller's cwd"
mkdir -p "$WORK/cwd"
(cd "$WORK/cwd" && SUDO_USER=nobody LYNC_BASE_URL=file://$DIST sh "$ROOT/run.sh" --sources none --json --log "$WORK/b.log" >"$WORK/b.out" 2>"$WORK/b.err")
rc=$?
check "mode b exit 0 (got $rc)" test "$rc" = 0
PDF=$(find "$WORK/cwd" -name 'lync-*.pdf' | head -n 1)
check "mode b: PDF report in the current directory" test -s "$PDF"
check "mode b: --json writes the JSON next to it" sh -c "ls '$WORK'/cwd/lync-*.json >/dev/null"
check "mode b: report path printed at the end" grep -q "==> Report: $PDF" "$WORK/b.err"
check "mode b: nothing large on stdout by default" test ! -s "$WORK/b.out"
if [ "$(id -u)" = 0 ] && id nobody >/dev/null 2>&1; then
	check "mode b: PDF chowned to SUDO_USER" test "$(stat -c %U "$PDF")" = nobody
fi
check "mode b: log names the report" grep -q " REPORT+ $PDF" "$WORK/b.log"
check "mode b: END lists the report" grep -q ' END .*report=' "$WORK/b.log"
check "mode b: POLICY mentions the report" grep -q ' POLICY .*report (PDF+JSON) in ' "$WORK/b.log"
check "mode b: download logged" grep -q ' FETCH .*lyncd-linux-' "$WORK/b.log"
check "mode b: cleanup verified" grep -q ' CLEANUP .*verified absent' "$WORK/b.log"
LYNC_BASE_URL=file://$DIST sh ./run.sh --sources none --out "$WORK/out2" --print-json --log "$WORK/b2.log" >"$WORK/b2.json" 2>/dev/null
check "mode b: --print-json still prints the report" grep -q '"findings"' "$WORK/b2.json"
check "mode b: --out DIR" sh -c "ls '$WORK'/out2/lync-*.pdf >/dev/null"

echo "== --cve with no feeds -> unknown (12)"
LYNC_BASE_URL=file://$DIST sh ./run.sh --sources none --cve CVE-2026-109618 --log "$WORK/cve.log" >"$WORK/cve.json" 2>/dev/null
rc=$?
check "cve unknown exit 12 (got $rc)" test "$rc" = 12
check "cve JSON has verdict" grep -q '"verdict": "unknown"' "$WORK/cve.json"

echo "== nothing left behind"
after=$(leftovers)
check "no lync-run temp dirs left (before: $(echo "$before" | wc -w), after: $(echo "$after" | wc -w))" test "$before" = "$after"
find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path "$WORK" -o -path /var/log/journal \) -prune -o -newer "$WORK/marker" -print 2>/dev/null |
	grep -v "^$WORK" >"$WORK/newfiles.txt"
grep -i lync "$WORK/newfiles.txt" >"$WORK/newlync.txt"
check "no new files named *lync* outside the test dir ($(wc -l <"$WORK/newlync.txt") found)" test ! -s "$WORK/newlync.txt"
echo "-- all paths newer than the marker on / (excluding /proc /sys /run /dev, the test dir):"
sed 's/^/   /' "$WORK/newfiles.txt" | head -n 40

echo
echo "self-test: $PASS passed, $FAIL failed (artifacts: $WORK)"
[ "$FAIL" = 0 ]
