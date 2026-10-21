#!/bin/sh
# lync-fleet.sh - agentless fleet sweep using `lyncd -once` over SSH.
#
# For each host in HOSTS_FILE (one "user@host" or "host" per line, # comments
# allowed) this:
#   1. copies a linux/amd64 lyncd binary to $REMOTE_DIR on the host
#      (only if the checksum differs),
#   2. runs `lyncd -once` there (full scan, or a single -cve check),
#      reusing $REMOTE_DIR/feeds as the feed cache between runs,
#   3. saves the JSON to $OUT_DIR/<host>.json and stderr to <host>.log.
# Then prints a one-line-per-host summary (needs jq locally).
#
# Nothing is installed as a service and no config under /etc is touched;
# remove with `ssh host rm -rf /var/tmp/lync`. Each host fetches its own
# feeds (OSV is per-distro), so hosts need HTTPS egress to osv.dev's bucket,
# access.redhat.com and services.nvd.nist.gov. The first run per host takes
# a few minutes; later runs reuse the cache unless older than sync_interval.
#
# Usage:
#   contrib/lync-fleet.sh [-b bin/lyncd] [-c CVE-ID] [-o out-dir] [-p parallel] HOSTS_FILE
#
# Build the binary first:
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/lyncd ./cmd/lyncd
#
# Exit status: 0 if every host answered; 1 if any host failed. With -c, the
# summary column is the verdict (affected / possibly_affected /
# not_affected / unknown).
set -eu

BIN=bin/lyncd
CVE=
OUT_DIR=fleet-$(date +%Y%m%d-%H%M%S)
PARALLEL=4
REMOTE_DIR=/var/tmp/lync
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10"

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }

while getopts b:c:o:p:h opt; do
  case $opt in
    b) BIN=$OPTARG ;;
    c) CVE=$OPTARG ;;
    o) OUT_DIR=$OPTARG ;;
    p) PARALLEL=$OPTARG ;;
    h) usage 0 ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage
HOSTS_FILE=$1
[ -f "$BIN" ] || { echo "lyncd binary not found: $BIN" >&2; exit 1; }
[ -f "$HOSTS_FILE" ] || { echo "hosts file not found: $HOSTS_FILE" >&2; exit 1; }
mkdir -p "$OUT_DIR"

LOCAL_SUM=$(sha256sum "$BIN" | cut -d' ' -f1)

one_host() {
  target=$1
  name=$(printf '%s' "$target" | sed 's/.*@//')
  out="$OUT_DIR/$name.json"
  log="$OUT_DIR/$name.log"

  remote_sum=$(ssh $SSH_OPTS "$target" "sha256sum $REMOTE_DIR/lyncd 2>/dev/null | cut -d' ' -f1" 2>>"$log" || true)
  if [ "$remote_sum" != "$LOCAL_SUM" ]; then
    ssh $SSH_OPTS "$target" "mkdir -p $REMOTE_DIR && chmod 700 $REMOTE_DIR" 2>>"$log" &&
      scp -q $SSH_OPTS "$BIN" "$target:$REMOTE_DIR/lyncd" 2>>"$log" &&
      ssh $SSH_OPTS "$target" "chmod 700 $REMOTE_DIR/lyncd" 2>>"$log" || {
        echo "$name: upload failed (see $log)" >&2
        return 1
      }
  fi

  cve_flag=
  [ -n "$CVE" ] && cve_flag="-cve $CVE"
  # -config points at a path that normally doesn't exist, so built-in
  # defaults apply even on hosts that also run the lync service.
  if ssh $SSH_OPTS "$target" \
      "$REMOTE_DIR/lyncd -once $cve_flag -config $REMOTE_DIR/lync.yaml -cache-dir $REMOTE_DIR/feeds -report-dir $REMOTE_DIR/reports" \
      >"$out" 2>>"$log"; then
    return 0
  fi
  echo "$name: lyncd -once failed (see $log)" >&2
  return 1
}

fail=0
running=0
pids=
while IFS= read -r line || [ -n "$line" ]; do
  host=$(printf '%s' "$line" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
  [ -n "$host" ] || continue
  one_host "$host" &
  pids="$pids $!"
  running=$((running + 1))
  if [ "$running" -ge "$PARALLEL" ]; then
    for p in $pids; do wait "$p" || fail=1; done
    pids=
    running=0
  fi
done <"$HOSTS_FILE"
for p in $pids; do wait "$p" || fail=1; done

if command -v jq >/dev/null 2>&1; then
  echo
  for f in "$OUT_DIR"/*.json; do
    [ -s "$f" ] || continue
    if [ -n "$CVE" ]; then
      jq -r '[.host, .verdict, .reason] | @tsv' "$f"
    else
      jq -r '[.host, .os.pretty_name, "critical=\(.counts.critical)", "high=\(.counts.high)", "total=\(.counts.total)"] | @tsv' "$f"
    fi
  done | column -t -s "$(printf '\t')"
else
  echo "results in $OUT_DIR (install jq for a summary)"
fi
exit "$fail"
