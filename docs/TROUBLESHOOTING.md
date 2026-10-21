# Troubleshooting

Things that go wrong, why, and what to do about them.

---

## `systemctl status lync` says inactive (failed)

Check journald:

```sh
journalctl -u lync --no-pager -n 50
```

Common causes:

- **Config parse error.** YAML indentation problems show up as
  `level=ERROR msg="config: parse /etc/lync/lync.yaml: ..."`. Re-paste the
  shipped default at `packaging/config/lync.yaml` and re-apply your
  changes.
- **Permission denied creating socket.** `/run/lync.sock` lives in a
  tmpfs that systemd manages. The unit runs as root by default; if you
  changed the user, give them the right to write `/run/`.
- **Feed store creation failed.** The daemon `mkdir`s the cache
  directory. If `/var/lib/lync` is on a read-only mount it'll fail.

---

## `lync status` says "dial /run/lync.sock: no such file or directory"

The daemon isn't running, or it's running but its socket path doesn't
match what the CLI is looking for.

```sh
systemctl status lync
# If it's running but on a different socket path:
lync -socket /custom/path/lync.sock status
```

If the daemon is running and the socket exists but you still get
permission denied, check `ls -l /run/lync.sock`. Mode should be `0660`
owned by root. The CLI as a non-root user needs to be in a matching
group, or run with `sudo`.

---

## First scan takes forever

The initial NVD sync without an API key pulls 158k CVEs at 5 req / 30 sec
and takes about 25 minutes. Either:

```yaml
# lync.yaml — set an NVD API key
feed:
  sources:
    - name: nvd
      enabled: true
      api_key: "00000000-1111-2222-3333-444455556666"
```

The daemon detects the key and pulls the full 120-day window in seconds.

Or shrink the window further:

```yaml
feed:
  sources:
    - name: nvd
      enabled: false   # rely on RH+Debian+Ubuntu+Alpine+OSV only
```

Watch progress with `lync status` — the sync job appears in the active
jobs table.

---

## `lync sync` runs every time the daemon restarts

That **used to** happen. The current daemon checks each source's manifest
age at startup and skips initial sync if the cache is younger than
`feed.sync_interval`. If you're seeing it on a current build:

```sh
journalctl -u lync --no-pager | grep "initial sync"
```

If it says `initial sync skipped (cache fresh)` you're on a current
build. If it says `initial sync starting` for every restart, you're on
an older build before commit `c0c55cb` — pull and rebuild.

---

## CVE was suppressed but I think it applies

By default Lync drops findings the distro marked `Not affected` or
`Will not fix` / `Fix deferred` / `Out of support scope`. To see what
got suppressed and why, set log level to `debug`:

```yaml
log:
  level: debug
```

Restart the daemon, run a scan, then:

```sh
journalctl -u lync --no-pager | grep "finding suppressed"
```

You'll see one line per suppressed finding with the judge and reason.

To temporarily disable filtering:

```yaml
applicability:
  enabled: false
```

To narrow what suppresses:

```yaml
applicability:
  suppress_on:
    - not_affected     # only suppress when distro says outright "doesn't apply"
```

---

## NVD finding still showing for a package the distro patched

This is the case [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) calls out:
NVD CPE matching is upstream-only and ignores distro backports. The
RedHatJudge handles it for RHEL family hosts (consults
`affected_release[]` and compares shipped NEVRA to installed). For
other distros the equivalent judge (Debian, Ubuntu) needs the right
data for that specific CVE.

If you're hitting this on a Debian or Ubuntu host:

- Check the per-judge cache for an entry. RH: `/var/lib/lync/feeds/redhat/details/<CVE>.json`.
  Ubuntu: `/var/lib/lync/feeds/ubuntu/details/<CVE>.json`. If absent,
  the judge didn't get data — either there's no upstream record, or the
  fetch failed.
- Try a `lync sync` and re-scan.

---

## Report PDF shows wrong kernel

`lync` reports the kernel from `uname -r`. If you have multiple kernels
installed (Rocky keeps the last three by default for fallback boot), the
**running** one is what shows in the PDF header. The **installed-and-
matched-against-vulns** copy is whichever has the highest NEVR — Lync
dedupes installed packages by name keeping the latest version. If
they don't match (e.g. you're booting an elrepo kernel-ml but the el9_7
stream is also installed), the kernel header field will look different
from kernel-CVE findings. Both are correct — they're tracking different
kernel packages.

---

## "Highest CVSS: 9.8" but the distro says Low

NVD's CVSS is the upstream rating; the distro's `threat_severity` is
their assessment of real-world impact in their build. The PDF currently
shows NVD's CVSS in the executive summary even when Red Hat has a
different opinion. To see the distro's view per finding, open the JSON:

```sh
jq '.findings[] | select(.cve=="CVE-2026-XXXXX")' /var/lib/lync/reports/lync-*.json
```

Severity normalization is documented in
[`docs/CONFIGURATION.md`](CONFIGURATION.md#severity-normalization).

---

## File-integrity monitor isn't catching changes

```sh
journalctl -u lync --no-pager | grep "file integrity monitor armed"
# Should say "paths=N baselined_files=M"
```

If the count is zero or you don't see the line:

- Confirm `monitor.enabled` and `monitor.file_integrity.enabled` are
  both `true` in `lync.yaml`.
- The watcher uses Linux inotify, which doesn't fire for NFS-mounted
  paths. If `/etc/passwd` is on a network share, you'll need a different
  watcher.
- Files larger than 4 MiB are tracked by mode + size + mtime only;
  content changes that preserve size + mtime won't be detected. Don't
  put `/var/log/syslog` in the watch list.

A `touch` with no content change is intentionally suppressed (same
SHA-256 + same mode = no event). To test detection, append a real byte:

```sh
echo "# test" | sudo tee -a /etc/sudoers.d/00-test
sleep 2
lync scan
sleep 6
jq '.findings | map(select(.source=="lync-monitor"))' /var/lib/lync/reports/lync-*.json
```

Don't forget to revert:

```sh
sudo rm /etc/sudoers.d/00-test
```

---

## Scoped scan produced fewer findings than expected

`lync scan -package <name>` filters facts to just that one package
before the matcher runs. If your installed copy is at the fixed version
or newer, no CVE findings result from the matcher. Rules and monitor
findings are skipped for scoped scans (they aren't package-specific) —
that's by design.

For a full picture, run `lync scan` with no flags.

---

## `lync render` fails to read JSON

```sh
$ lync render report.json
lync: open report.json: no such file or directory
```

The CLI doesn't search any directories. Use an absolute path or `cd` to
where the file lives.

For JSON files written by an older daemon, the schema may have changed
slightly — fields like `kernel_cves` were added later. The PDF renderer
is tolerant of missing fields but if you see a panic on render, check
the JSON parses with `jq`:

```sh
jq . report.json > /dev/null   # exit 0 means parses cleanly
```

---

## I want to see what Lync would do without applying

Set `applicability.enabled: false` and `monitor.enabled: false`, then
run a scoped scan. You'll get only the matcher's raw output, which is
useful for comparing pre/post applicability filtering.

For a single-CVE dry-run, drop a JSON file into the feed cache by hand
and force a scan. The matcher path is deterministic — given the same
facts and the same cache, the output is the same.

---

## Logs

`lync` logs to stdout, which systemd captures into the journal. Useful
filters:

```sh
journalctl -u lync -f                              # tail
journalctl -u lync --since "1 hour ago"
journalctl -u lync -p err                          # only errors
journalctl -u lync | grep "scan complete"
```

To switch to JSON log format:

```yaml
log:
  format: json
```

The text format is logfmt-style with `time=... level=... msg="..." key=val`.
