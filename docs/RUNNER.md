# One-shot runner (no install)

Two entry points run a full Lync scan on a host without installing
anything. The product is a **PDF report**; the only other thing left
behind is a log file:

| | Where you type it | Binary comes from | Report goes to | Left on the host |
|---|---|---|---|---|
| **(a) `lync-run`** | your workstation (Linux, macOS, Git Bash on Windows) | `./dist` (`make release`) or `gh release download`, streamed over SSH | `./lync-results/<UTC>/<host>/report.pdf` (+ JSON) on the workstation; paths printed at the end, `--open` opens them | the log |
| **(b) `run.sh`** | on the host itself | GitHub Release asset (token for a private repo), checksum-verified | `./lync-<host>-<UTC>.pdf` in the directory you ran it from (or `--out DIR`), owned by you under sudo; `--json` adds the JSON | the log and the report |

By default CVE data is **looked up**, not downloaded: one OSV.dev batch
query for the installed packages, details for the advisories that hit,
Red Hat per CVE on RHEL-family hosts, and NVD by CVE id for severities
(see [CONFIGURATION.md](CONFIGURATION.md#mode-lookup-default) for what is
sent where). Measured on a 159-package Debian 12 host (WSL), same box as
the full-feed run further down:

| | lookup (default) | full feeds (`--full-feeds`) |
|---|---|---|
| downloaded | 1.0 MB (343 OSV requests, 10 NVD requests) | 121 MB Debian tracker + OSV export, plus NVD's 30-day window |
| feed cache on disk | 0.34 MB | 80 MB (305 MB in the temp dir with NVD) |
| wall time, cold cache | 36 s (31 s of it is NVD's 5-requests-per-30-s limit) | 6 s without NVD; 44 min with NVD and no API key |
| wall time, warm cache | 1.4 s | - |
| peak RSS of lyncd | 16-18 MB | 680 MB (without NVD) |

The temp-space preflight is 64 MB in lookup mode and 400 MB with
`--full-feeds`. `--nvd-key-file` (lookup: 200 NVD lookups per run instead
of 10; full: a 120-day window) and `--cache` still help fleets.

## Quick start

### (a) From the workstation, over SSH (works with the repo private)

```sh
make release                      # or: gh release download --repo ryan785/lync -D dist
./lync-run root@host.example.com
./lync-run --cve CVE-2026-109618 root@a root@b root@c
./lync-run -f hosts.txt --cache ~/.cache/lync-feeds --nvd-key-file ~/.nvd-key
```

`lync-run` probes each host's arch and OS over SSH, then runs one SSH
session: `tar` bundle (binary + `SHA256SUMS` [+ feed cache] [+ NVD key])
on stdin → `sh -c '<run.sh>'` on the host → results as a tar stream on
stdout. Afterwards it copies the host's log back and checks over SSH that
the host's temp dir is gone. It prints a table:

```
HOST                         EXIT  CRIT  HIGH  MED   LOW   TOTAL  VERDICT            REMOTE-TMP
debian-wsl                   0     2     8     18    6     231    -                  removed
```

(TOTAL also counts findings with unknown severity: the Debian feed has
no severities. `degraded` in VERDICT means exit 5: a feed failed to sync.)

### (b) On the host

Public repo (or after the repo is made public):

```sh
cd ~ && curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh
#   ...
#   ==> Report: /home/you/lync-web1-20261021T080035Z.pdf
curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh -s -- --json --out /tmp/reports
curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh -s -- --cve CVE-2026-109618
```

The PDF is written to the directory you started in (falling back to
`$HOME` if that is not writable), named `lync-<host>-<UTC>.pdf`, mode 600
and owned by `$SUDO_USER` when run through sudo. Its path is the last
thing printed. `--print-json` also prints the JSON report on stdout (the
old default) for scripts; `--cve` prints the verdict JSON and writes no
PDF.

Private repo (fine-grained token with *Contents: read* on ryan785/lync):

```sh
read -rs LYNC_GH_TOKEN; export LYNC_GH_TOKEN      # keeps the token out of shell history
curl -fsSL -H "Authorization: Bearer $LYNC_GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/ryan785/lync/contents/run.sh \
  | sudo LYNC_GH_TOKEN="$LYNC_GH_TOKEN" sh -s -- --keep-report /root/lync-report
```

With a token, `run.sh` resolves the release asset through the GitHub API
(`/repos/ryan785/lync/releases/latest`, or `/releases/tags/$LYNC_VERSION`)
and downloads it with `Accept: application/octet-stream`. curl drops the
`Authorization` header on the redirect to GitHub's storage host. The token
is never written to the log. Without a token it uses the public
`releases/latest/download/<asset>` URLs. `LYNC_BASE_URL` points at any
mirror directory (`https://...` or `file:///mnt/usb/lync`) holding
`lyncd-linux-<arch>` and `SHA256SUMS`.

## What runs on the host

1. **Temp dir.** `mktemp -d` (mode 700) in the first of `/dev/shm`,
   `$TMPDIR`, `/tmp`, `/var/tmp` that is writable, has at least
   `LYNC_MIN_FREE_MB` (300) free, and allows exec. A probe script is
   executed to detect `noexec` mounts. If none qualifies, the run exits 2.
2. **Binary.** Mode (a) gets it from the bundle; mode (b) downloads it.
   Either way, `sha256(lyncd-linux-<arch>)` must match `SHA256SUMS`
   before it runs. A mismatch exits 3 without executing anything.
3. **Scan.** `nice -n 19 ionice -c 3 timeout $LYNC_TIMEOUT lyncd -once
   -config none -feed-mode lookup|full -sources auto -cache-dir $T/cache
   -report-dir $T/out -audit-log $LOG [-cve ID] [-enable container:php-upload-progress]`.
   - Built-in defaults only. An existing `/etc/lync/lync.yaml` is ignored.
   - Lookup mode (default): OSV.dev queries for the installed packages and
     for application components found by the inventory, Red Hat per CVE
     on RHEL-family hosts, NVD by CVE id. `--full-feeds`: the distro's bulk
     feed (Red Hat, Debian, Ubuntu or Alpine) plus the OSV export plus NVD,
     downloaded into the temp dir.
   - The package-manager cross-check reads `dnf -C updateinfo` /
     `apt-get -s dist-upgrade` (cached metadata, nothing installed).
   - The matcher, the applicability judges and all rule checks run, and
     the PDF is rendered.
   - Each external command has a timeout (`audit.Output`, 20 s for rule
     tools, up to 5 min for `rpm -qa`).
   - Feed downloads retry with backoff. A body cut off mid-transfer is
     retried, the run falls back to HTTP/1.1 after repeated HTTP/2 stream
     errors, and a single hung attempt is cut after 3 min and retried.
4. **Results.** Mode (a) streams `$T/out` back as tar; nothing but the log
   stays on the host. Mode (b) copies the PDF (and with `--json` the JSON)
   to the output directory, logs it as `REPORT+` (and `CHOWN`), and prints
   the path last; `--cve` prints `cve-<ID>.json` to stdout. `--keep-report
   DIR` still copies JSON+PDF to DIR as well (`KEEP`).
5. **Cleanup** is an `EXIT`/`INT`/`TERM`/`HUP` trap. It stops `lyncd` if
   it is still running, lists every remaining file as `FILE-`, runs `rm -rf
   $T`, checks that `$T` is really gone, and logs `CLEANUP ... verified
   absent`. A dropped SSH session sends HUP, which triggers the trap.

### What it never does

It installs no packages, creates no systemd units, users or cron entries,
and writes nothing to `/etc` or `/usr`. It does not run Go and does not
change any service or firewall state. Lyncd's checks only read files and
run read-only tools (`rpm -q`, `ss`, `systemctl is-enabled`,
`firewall-cmd --list-*`, `docker ps/inspect`, `dnf -C updateinfo` (cache
only), `wg show`, ...). The one exception, `docker exec <c> php -r` for
`container:php-upload-progress`, runs only with `--container-exec`. The
log says this at the top (`POLICY` line).

**Besides the report in mode (b), the log is the only thing left on the host**:
`/var/log/lync-run-<UTC>.log` when run as root, otherwise
`~/lync-run-<UTC>.log`; override it with `--log FILE` (`lync-run
--remote-log`). The file is mode 600 and contains no secrets: tokens are
never passed to it, `key=value` secrets, Authorization headers and GitHub
tokens are redacted, and the NVD key travels in the environment, not
argv.

## Options

| run.sh | lync-run | Meaning |
|---|---|---|
| `--out DIR` | `--out DIR` | (b) where the PDF goes (default: current directory); (a) local results root |
| `--json` | | (b) also write the JSON report next to the PDF |
| `--print-json` | | (b) print the JSON report to stdout too |
| `--full-feeds` | `--full-feeds` | bulk feed downloads instead of lookups |
| | `--open` | open each host's PDF locally when done (xdg-open / open / start) |
| `--cve ID` | `--cve ID` | single-CVE verdict instead of a full scan |
| `--cache DIR` | `--cache DIR` | (b) seed the feed cache from a copy of DIR; (a) local cache root, pushed to and refreshed from each host per OS (`DIR/<id>-<major>/`), so a fleet run downloads feeds once per OS |
| env `LYNC_NVD_KEY` | `--nvd-key-file F` | NVD API key (120-day window, faster) |
| `--container-exec` | `--container-exec` | enable the opt-in `docker exec` PHP check |
| `--keep-report DIR` | `--keep-report DIR` | also keep the report on the host |
| `--sources auto\|none\|LIST` | `--sources ...` | feed selection (`none` = collector + rules only) |
| `--log FILE` | `--remote-log FILE` | log path on the host |
| `--min-free-mb N`, `--timeout S` | | preflight space (64 MB lookup, 400 MB full), scan time limit |
| | `-f FILE`, `--bin DIR` | hosts file, binary dir |

Environment for run.sh: `LYNC_GH_TOKEN`, `LYNC_REPO` (ryan785/lync),
`LYNC_VERSION` (latest | vX.Y.Z), `LYNC_BASE_URL`, `LYNC_NVD_KEY`,
`LYNC_LOG`, `LYNC_MIN_FREE_MB`, `LYNC_TIMEOUT`. For lync-run:
`LYNC_SSH_OPTS`, `LYNC_SSH`.

## Exit codes

| Code | run.sh | lync-run |
|---|---|---|
| 0 | scan completed | every host produced results |
| 1 | usage | usage |
| 2 | preflight: no usable temp dir, too little space, unsupported arch, no sha256 tool | local preflight: no binary / ssh / tar |
| 3 | download or checksum failure (binary not executed) | |
| 4 | lyncd failed or timed out | one or more hosts failed |
| 5 | report produced, but a feed failed to sync or a lookup failed: the CVE section is incomplete (degraded) | |
| 10 / 11 / 12 | `--cve`: affected / possibly affected / unknown to feeds | (per host in the table) |
| 129 / 130 / 143 | stopped by HUP / INT / TERM (cleanup still ran) | |

`lyncd -once` itself returns 0, 1, 3 (degraded), and 10/11/12.

## Log format

One line per event, in UTC: `<timestamp> <KIND> <details>`. The kinds are:

- `START`, `POLICY`, `PRIVACY` (lookup mode: what is sent where), `HOST`, `WARN`
- `TMP`: temp dir selection, with every skipped candidate and why
- `FILE+` / `FILE-`: every file created or removed
- `VERIFY`: checksum
- `FETCH` / `RETRY` / `HTTP`: URL (redacted), status, bytes, duration,
  attempts, protocol
- `CMD`: exact command line, exit code, duration, output size
- `SYNC` / `FEED`: per feed source (full mode)
- `LOOKUP`: per lookup source (ecosystem, packages, advisories, cache
  hits, requests, bytes, status, duration); `INCOMPLETE` when a source
  failed
- `LOCAL`: package-manager cross-check (pending, confirmed, lookup-only,
  package-manager-only)
- `INVENTORY`: application components found, warnings, OSV lookup
- `FACTS`, `MATCH`, `APPLIC`
- `RULE`: each rule with finding count
- `CHECK`: all 63 checks with on/off/opt-in and finding count
- `REPORT`, `SUMMARY`, `KEEP`, `OUTPUT`, `REPORT+` / `CHOWN` (mode b report)
- `CLEANUP`, `END`
- Lyncd's own stderr is appended, indented with `lyncd:`.

Lookup-mode excerpt (same host, mode (a), default options; 522 lines in
full, most of them the 342 `FETCH GET https://api.osv.dev/v1/vulns/...`
lines, trimmed):

```
2026-10-21T08:00:35Z PRIVACY lookup mode: installed package names+versions (and application components found on disk) go to api.osv.dev, matched CVE ids to NVD (and Red Hat on RHEL-family hosts); use --full-feeds to download feeds instead
2026-10-21T08:00:35.735Z FEEDS   mode=lookup active sources: osv,nvd (cache /dev/shm/lync-run.XLTjkHKh/cache)
2026-10-21T08:00:36.835Z FETCH   POST https://api.osv.dev/v1/querybatch status=200 bytes=24.6KB dur=601ms attempts=1 proto=HTTP/2.0
2026-10-21T08:00:40.152Z LOOKUP  osv ecosystem="Debian:12" packages=159 advisories=342 cache_hits=0 requests=343 bytes=976.2KB status=ok dur=3.919s
2026-10-21T08:01:11.497Z LOOKUP  nvd candidates=118 unscored=10 found=10 cache_hits=0 requests=10 bytes=52.4KB status=ok dur=31.344s
2026-10-21T08:01:11.497Z MATCH   vulns=363 candidate_findings=118
2026-10-21T08:01:11.717Z LOCAL   apt status=ok pending=0 confirmed=0 lookup_only=118 pkgmgr_only=0
2026-10-21T08:01:11.860Z INVENTORY collected components=0 queryable=0 by_ecosystem=map[] entries=35 files=0 truncated=false warnings=0 dur=13ms
2026-10-21T08:01:11.871Z SUMMARY findings=139 critical=12 high=62 medium=54 low=8 info=0 unknown=3 suppressed_by_applicability=0
2026-10-21T08:01:11Z CLEANUP removed /dev/shm/lync-run.XLTjkHKh (8 files, 9012KB); verified absent
```

Compared with the full-feed run below on the same host: the 118
Debian-tracker findings are found by lookup with identical fixed
versions, and lookup mode rates 115 of them (OSV CVSS vectors, NVD for 10
unscored CVEs) where the tracker left 197 Unknown. The full run's 79 OSV
findings were false positives from the old bulk converter, which applied
other ecosystems' fixed versions (Alpine `3.1.7-r0`, Debian 13 `2.37-12`)
to the Debian 12 host; that converter is fixed for full mode too, after
which full mode also reports exactly these 118. Its 13 NVD-only findings
were upstream CPE version-range matches (openssl, vim, glibc) against
backported Debian builds; lookup mode only asks NVD about CVEs a distro
source already matched. 214 CVEs affect installed packages with no Debian
fix yet; they are counted in `data_sources.unfixed_cves` and the PDF, and
`lync cve` reports them as possibly affected.

Full-feed excerpt (WSL Debian 12 as the "host", mode (a) through the fake ssh, all feeds, no NVD key; 223 lines in full, trimmed to one of each kind). It shows an NVD failure seen in the field (`stream error ... INTERNAL_ERROR`) being retried, the switch to HTTP/1.1, and the sync completing:

```
2026-10-21T05:04:47Z START   lync run.sh pid=292 user=root(0) cwd=/root args: cve=none sources=auto keep_report=no cache=none container_exec=0 bundle_stdin=1
2026-10-21T05:04:47Z POLICY  read-only scan: this run writes only inside its temp dir and to this log; it installs nothing and changes no system state
2026-10-21T05:04:47Z HOST    hostname=testhost uname=Linux 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64
2026-10-21T05:04:47Z HOST    os=Debian GNU/Linux 12 (bookworm)
2026-10-21T05:04:47Z HOST    uptime=749.47s
2026-10-21T05:04:47Z HOST    arch=amd64
2026-10-21T05:04:47Z TMP     using /dev/shm/lync-run.MZ2EjjE2 (mode 700, 15833MB free, exec allowed)
2026-10-21T05:04:47Z FILE+   /dev/shm/lync-run.MZ2EjjE2/ (out/ cache/ in/)
2026-10-21T05:04:47Z CMD     tar -xf - -C /dev/shm/lync-run.MZ2EjjE2/in exit=0 dur=0s
2026-10-21T05:04:47Z VERIFY  lyncd-linux-amd64 sha256=9a85fe35198c78c6e9b5386936853f13bd4ed4205ddca77e21b978be7bf12553 OK
2026-10-21T05:04:47Z BIN     lyncd 4dbd3f6-dirty linux/amd64
2026-10-21T05:04:47Z RUN     nice -n 19 ionice -c 3 timeout -s TERM 3600 /dev/shm/lync-run.MZ2EjjE2/lyncd -once -config none -sources auto -cache-dir /dev/shm/lync-run.MZ2EjjE2/cache -report-dir /dev/shm/lync-run.MZ2EjjE2/out -audit-log /var/log/lync-run-20261
2026-10-21T05:04:47.073Z LYNCD   start version=4dbd3f6-dirty mode=once cve="" cache=/dev/shm/lync-run.MZ2EjjE2/cache reports=/dev/shm/lync-run.MZ2EjjE2/out sources=debian,osv,nvd enable= config=none
2026-10-21T05:04:47.073Z FEEDS   active sources: debian,osv,nvd (cache /dev/shm/lync-run.MZ2EjjE2/cache)
2026-10-21T05:04:47.073Z SYNC    debian start
2026-10-21T05:04:47.716Z FETCH   GET https://security-tracker.debian.org/tracker/data/json status=200 bytes=80.3MB dur=642ms attempts=1 proto=HTTP/2.0
2026-10-21T05:04:48.733Z SYNC    debian ok entries=64508 dur=1.66s
2026-10-21T05:04:48.733Z SYNC    osv start
2026-10-21T05:04:49.208Z FETCH   GET https://osv-vulnerabilities.storage.googleapis.com/Debian:12/all.zip status=200 bytes=41.1MB dur=475ms attempts=1 proto=HTTP/2.0
2026-10-21T05:04:51.351Z SYNC    osv ok entries=27810 dur=2.618s
2026-10-21T05:04:51.351Z SYNC    nvd start
2026-10-21T05:05:33.017Z FETCH   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... status=200 bytes=3.5MB dur=41.666s attempts=1 proto=HTTP/2.0
2026-10-21T05:07:12.171Z FETCH   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... status=200 bytes=6.7MB dur=1m33.1s attempts=1 proto=HTTP/2.0
2026-10-21T05:26:08.988Z RETRY   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... error="stream error: stream ID 23; INTERNAL_ERROR; received from peer" attempt=1 wait=1s
2026-10-21T05:34:01.094Z HTTP    switching to HTTP/1.1 after 2 HTTP/2 errors
2026-10-21T05:34:01.094Z RETRY   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... error="stream error: stream ID 33; INTERNAL_ERROR; received from peer" attempt=1 wait=1s
2026-10-21T05:41:18.878Z RETRY   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... error="unexpected EOF" attempt=1 wait=1s
2026-10-21T05:44:59.002Z RETRY   GET https://services.nvd.nist.gov/rest/json/cves/2.0?... error="unexpected EOF" attempt=1 wait=1s
2026-10-21T05:48:42.608Z SYNC    nvd ok entries=48302 dur=43m51.257s
2026-10-21T05:48:42.617Z CMD     dpkg-query -W -f '${binary:Package}|${Version}|${Architecture}|${source:Package}|${db:Status-Status}\n' exit=0 dur=4ms out=7.7KB
2026-10-21T05:48:43.277Z FACTS   hostname=testhost os="Debian GNU/Linux 12 (bookworm)" kernel=6.6.87.2-microsoft-standard-WSL2 arch=x86_64 packages=159 running_services=10
2026-10-21T05:48:43.935Z FEED    debian loaded vulns=64508
2026-10-21T05:48:44.351Z FEED    osv loaded vulns=27810
2026-10-21T05:48:44.687Z FEED    nvd loaded vulns=48302
2026-10-21T05:48:44.713Z MATCH   vulns=140620 candidate_findings=210
2026-10-21T05:48:45.151Z APPLIC  evaluated=210 suppressed=0 by_judge=map[]
2026-10-21T05:48:45.151Z RULE    ssh-config ran findings=0 dur=0s
2026-10-21T05:48:45.175Z CMD     ss -H -tulnp exit=0 dur=24ms out=216B
2026-10-21T05:48:45.202Z RULE    web-exposure ran findings=0 dur=51ms
2026-10-21T05:48:45.206Z CMD     systemctl list-units --state=failed --plain --no-legend --no-pager exit=0 dur=5ms out=0B
2026-10-21T05:48:45.211Z RULE    filesystem ran findings=0 dur=60ms
2026-10-21T05:48:45.236Z FETCH   GET https://endoflife.date/api/debian.json status=200 bytes=4.5KB dur=85ms attempts=1 proto=HTTP/1.1
2026-10-21T05:48:45.253Z RULE    system ran findings=1 dur=101ms
2026-10-21T05:48:45.324Z CHECK   container:php-upload-progress state=off(opt-in) findings=0
2026-10-21T05:48:45.324Z CHECK   php:upload-progress state=on findings=0
2026-10-21T05:48:45.325Z CHECK   ssh:root-password-login state=on findings=0
2026-10-21T05:48:45.326Z FILE+   /dev/shm/lync-run.MZ2EjjE2/out/lync-2026-10-21_01-48-45.json 192.2KB
2026-10-21T05:48:45.343Z FILE+   /dev/shm/lync-run.MZ2EjjE2/out/lync-2026-10-21_01-48-45.pdf 41.4KB
2026-10-21T05:48:45.343Z SUMMARY findings=231 critical=2 high=8 medium=18 low=6 info=0 unknown=197 suppressed_by_applicability=0
2026-10-21T05:48:45.343Z LYNCD   end exit=0 dur=43m58.271s failed_sources="" err=<nil>
2026-10-21T05:48:45Z RUN     lyncd exit=0 dur=2638s
2026-10-21T05:48:45Z OUTPUT  streamed 9 result files to the caller over stdout
2026-10-21T05:48:45Z SUMMARY critical=2 high=8 medium=18 low=6 total=231 
2026-10-21T05:48:45Z FILE-   /dev/shm/lync-run.MZ2EjjE2/lyncd 7864472B
2026-10-21T05:48:45Z CLEANUP removed /dev/shm/lync-run.MZ2EjjE2 (19 files, 305572KB); verified absent
2026-10-21T05:48:45Z END     exit=0 log=/var/log/lync-run-20261021T050446Z.log (the only file this run leaves on the host)
```

## Testing

- `go test ./...`: transport retry/backoff, HTTP/2 mid-body
  `INTERNAL_ERROR` → HTTP/1.1 fallback (reproduces an NVD failure seen in the field),
  hung-attempt retry, no retry on x509/404, redaction, command logging,
  auto feed selection.
- `shellcheck -s sh run.sh lync-run tests/runner-selftest.sh` must be clean.
- `make release && sudo sh tests/runner-selftest.sh` on any Linux box (WSL
  works) runs the runner end to end with a fake `ssh` that executes the
  "remote" command locally, offline (`--sources none`: no lookups, no
  inventory), and asserts:
  - results come back;
  - every log section is present, and the CHECK count equals `lync checks`;
  - the temp dir is removed on success, on SIGTERM mid-scan and on a
    checksum mismatch (where the binary never runs);
  - mode (b) download from `LYNC_BASE_URL` works, the PDF (and with
    `--json` the JSON) lands in the caller's directory, owned by
    `SUDO_USER`, its path is printed last, `--out` and `--print-json`
    work, and mode (a) leaves no report on the host;
  - `--cve` returns exit code 12;
  - no new file named `*lync*` exists outside the test dir.
- Not yet validated end to end on a real RHEL-family host.
