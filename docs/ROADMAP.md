# Roadmap and known gaps

Status as of 2026-10 (branch `improvements-2026-10`). Phases 1-4 in the
README are done; this file covers what is still missing, ordered by value
for a Rocky Linux 8/9 fleet with Docker hosts.

## How Lync sees a RHEL-family appstream package (e.g. php-fpm 8.0.30)

| Source | What it contributes for `php-fpm-8.0.30-1.module+el8...` |
|---|---|
| `osv` (`Rocky Linux:8`) | Per-RPM fixed versions from RLSA advisories, full history. The main source. Module-stream aware matching picks the php:8.0 stream's fix. |
| `redhat` summary | Module errata appear only as module NSVCs (`php:8.0-8100020...`), which can't be compared with an RPM, so they are skipped. 365-day window. |
| Red Hat judge | Reads per-CVE `package_state` (`php:8.0/php`) to suppress Not affected / Will not fix, or confirm Affected. |
| `nvd` | CPE `php:php` ranges. Matched via the source RPM (`php`) onto `php-fpm`/`php-cli`. Dropped if OSV/Red Hat say the installed build is already patched. Only 30 days of history without an API key. |

Things to know when checking a just-published CVE:

1. Before the vendor ships an erratum, nothing has a fixed version. The scan
   report then shows **no finding** (the matcher needs a fixed version or a
   range). `lync cve CVE-ID` is the right tool: it says `unknown` (no feed
   has it yet) or `possibly_affected` (named package installed, no fix yet)
   instead of a reassuring silence.
2. NVD often lags days or weeks before it adds CPE configurations, so NVD
   can't be relied on for day-0 detection either.
3. If the installed module stream is no longer maintained (check
   `dnf module list php`), no fix will ever appear for it. Lync reports this
   as "no fix found for the installed module stream ... switch module
   stream" once another stream has a fix.

## 0. Next: false positives from the first field run (2026-10)

Listed in the order they inflate the report.
(f) NVD retry is done (`audit.Transport`).

| # | Finding | Fix | Effort |
|---|---|---|---|
| (a) | 28 kernel CVEs matched against installed-but-not-running stock `kernel` packages while `kernel-ml` runs | Match only the running kernel's package family (`sys:reboot-required` already identifies it) | 0.5 d |
| (b) | 9 CVEs on openssl 1.1.1k, platform-python, perl-URI, perl-Errno, librados2 with no dnf update | Check the matcher on these names (module/source naming); report unfixed as `fix_available=false` | 1 d |
| (c) | sudo NOPASSWD for root and for a user that no longer exists | Skip root; flag users not in passwd as Low "stale sudoers entry" | 1 h |
| (d) | `secrets:world-readable` on `/etc/sysconfig/authconfig` (`PASSWDALGORITHM=`) | Exclude *ALGORITHM*/*_POLICY keys, and require a value that looks like a secret | 1 h |
| (e) | `kernel.kexec_load_disabled` rated High | Lower to Low | 10 min |

Also from the runner work:

- Feed downloads fail on hosts without a CA bundle (seen on a minimal WSL
  Debian). Consider embedding fallback roots
  (`golang.org/x/crypto/x509roots/fallback`) so the static binary works
  anywhere. Effort: 1 h, plus one dependency.
- The Debian feed has no severities, so Debian CVE findings show as
  Unknown. Enrich from NVD/OSV CVSS when present. Effort: 0.5 d.
- `lync-run` cache reuse: OSV is per ecosystem, so the cache is keyed by
  `<os-id>-<major>`. A shared NVD/OSV cache across distros would save more.
  Effort: 0.5 d.

## 1. Fleet view (P1)

Today: one daemon per host behind a local-only Unix socket.

**Done (stage 1, agentless):**

- `lync-run` / `run.sh` (docs/RUNNER.md): one SSH session per host, the
  binary is streamed in, nothing is installed, the temp dir is removed by a
  trap, only a log stays on the host, and the results and the log come
  back to the workstation. It has a summary table and a per-OS feed cache
  pushed from the workstation. It replaces `contrib/lync-fleet.sh`, which
  left `/var/tmp/lync` behind.
- Real-host validation is still pending. The
  self-test (fake ssh) passes on WSL Debian 12, both with all feeds and
  offline.

Limits of stage 1: every host downloads its own feeds (needs egress, a few
minutes per host the first time), and there is no aggregated report.

**Stage 2: collect facts remotely, match centrally (`lync fleet`), about 2 days.**

1. `lyncd -once -facts`: print only `collector.Facts` JSON (fast: os-release,
   `rpm -qa`, services). No feeds or network on the target.
2. `feed.OSVSource` takes an explicit ecosystem list instead of reading the
   local `/etc/os-release`, so one central cache can hold `Rocky Linux:8`,
   `Rocky Linux:9`, `Debian:12`, and so on.
3. `lync fleet scan|cve ID -inventory hosts.yaml` (runs on the admin box,
   no daemon):
   - fan out over SSH (shell out to `ssh` so `~/.ssh/config`, jump hosts and
     agents keep working; bounded parallelism),
   - run the matcher + applicability engine centrally per host
     (`matcher.Match` and `applicability.Engine.Filter` are already pure
     functions of Facts + vulns),
   - write `fleet-<ts>.json` (per-host reports plus a CVE -> hosts index)
     and a fleet PDF/HTML summary,
   - `lync fleet cve ID` prints a host x verdict table using the same
     verdict logic as `lync cve` (`daemon.evaluateCVE`).
4. Inventory: `hosts.yaml` with `host`, `user`, optional `tags`
   (e.g. `docker: true`, so container scanning runs only where useful).

Stage 3 (optional): daemons push their latest report to a collector over
HTTPS with mTLS. Only worth it if agentless SSH becomes a problem; it brings
back auth/transport concerns the local socket avoids.

## 2. Container scanning (P1, about 3-5 days for OS packages)

Lync has none today: `collector.Collect` reads only the host's
`/etc/os-release` and `rpm -qa`/`dpkg-query`/`apk`. Images like
postgres (Debian), nginx (Debian/Alpine), minio (UBI 9 micro), twenty
(Node on Debian/Alpine) and poste.io (Debian/Ubuntu, **ships PHP for its
Roundcube webmail**) are invisible.

Design:

1. **Root-filesystem collector**: `collector.CollectRoot(root string)` reads
   `<root>/etc/os-release` and the package DB *without running binaries
   from the image*:
   - dpkg: parse `<root>/var/lib/dpkg/status` (plain text),
   - apk: parse `<root>/lib/apk/db/installed` (plain text),
   - rpm: `rpmdb.sqlite` (EL9/UBI9), BerkeleyDB (EL8) or ndb.
     `github.com/knqyf263/go-rpmdb` reads all three in pure Go and keeps
     CGO off.
2. **Discovery** of running containers: `docker ps -q` / `podman ps -q`, then
   `inspect` -> `State.Pid`; scan `/proc/<pid>/root` (the container's live
   rootfs, no image pull or unpack). Record container name, image ref and
   digest.
3. **Matching**: one Facts per container, matched with the container's own
   ecosystem (needs the explicit-ecosystem OSV change from fleet stage 2).
   Findings gain a `target` field (`host` or `container:<name>@<image>`),
   and reports group by target.
4. **Applicability**: the Debian, Ubuntu and Alpine judges already key off
   Facts.OS, so they work unchanged per container.
5. Later: stopped images via `docker save` + layer unpack; language
   ecosystems (npm `package-lock.json`, Go build info in binaries, composer)
   via OSV's npm/Go/Packagist ecosystems.

**Stopgap for this week:** run Trivy or Grype on the Docker hosts
(`trivy image --severity HIGH,CRITICAL <image>` for each running image).
They already cover OS packages plus language dependencies.

## 3. Feed quality (P1/P2)

| Item | Why | Effort |
|---|---|---|
| Red Hat CSAF/VEX feed in place of the Hydra summary API | No 365-day window; explicit module-stream product IDs; VEX "known_affected / under_investigation" before a fix ships. Red Hat is moving consumers to CSAF/VEX (check the Hydra API's deprecation status). | 2-3 d |
| Report unfixed CVEs as findings | OSV entries without a `fixed` event and Red Hat `package_state: Affected` with no erratum are silently dropped. Emit them as `fix_available=false` findings (severity kept, flagged). | 1 d |
| Rescan when a sync brings new CVEs | The "new CVE -> immediate exposure check" idea from the design isn't wired up: a sync doesn't trigger a scan. Diff CVE IDs per source and trigger a scan when new ones match installed names. | 0.5 d |
| NVD incremental merge | Each sync replaces the cache with the last 30/120 days, so older NVD-only CVEs vanish. Merge by `lastModified` instead. Get an NVD API key in the meantime. | 1 d |
| OSV zip streamed to disk | `fetchEcosystem` reads the whole all.zip into memory, a large RSS spike against the 30 MB target. | 0.5 d |
| dpkg version comparison | dpkg versions are compared with the RPM algorithm; ordering differs for `~`/`+`/letters in edge cases. Add a real dpkg vercmp for `Manager == "dpkg"`. | 0.5 d |

## 4. Daemon and packaging (P2/P3)

| Item | State | Effort |
|---|---|---|
| Live config reload | SIGHUP now validates only, and no longer kills the daemon. Real reload means rebuilding sources/engines under a lock and resetting scheduler tickers. | 1 d |
| Prebuilt release artifacts | `install.sh` installs Go + git on every target and builds there. For production servers, publish static binaries + nfpm RPM/DEB from CI (GitHub Actions release) and have install.sh download them. | 0.5-1 d |
| OpenRC init script (Alpine) | Docs contain a template only. Ship `packaging/openrc/lync` and install it from install.sh on Alpine. | 1-2 h |
| SUSE | Judge is a stub, no feed. | 2 d |
| EOL rule cache dir | Hardcoded `/var/lib/lync/feeds/eol`; should follow `feed.cache_dir` (matters for `-once -cache-dir`). | 0.5 h |
| Per-scan UUID in logs, TRACE level | Described in the original design, not implemented (`trace` maps to debug). | 0.5 d |
| eBPF (Phase 5) | Stub; keep deferred. Needs BTF/CO-RE packaging. | weeks |

## 5. Host checks (added 2026-10) and what's next

Done: about 50 new read-only checks covering web roots, nginx/PHP, Docker
and firewalld exposure, datastores, kernel/boot/SELinux state, failed
units, update hygiene, sudo/ssh/docker access, world-readable secrets,
writable cron scripts, EOL runtimes/images and WireGuard. Each can be
toggled. See `docs/CHECKS.md`.

Follow-ups:

| Item | Why | Effort |
|---|---|---|
| Port the original rules onto `rules.Host` | They still read `/` directly, so `rules.root` and fixture tests don't cover them. | 1 d |
| Apache equivalents of the nginx routing checks | php-writable-dir, fastcgi/proxy_fcgi targets and origin-exposed are nginx-only. | 1 d |
| Containers' root filesystems through `rules.Host` | `Host{Root: "/proc/<pid>/root"}` would let the web/php/secret checks run inside containers without `docker exec`. | 1-2 d |
| Process inventory for EOL runtimes | Uses `/proc/*/exe` plus `--version`; also read `/proc/<pid>/root` so containerized node/python count too. | 0.5 d |
| `needs-restarting -s` | Services still running deleted libraries after updates (glibc/openssl). | 0.5 d |
| Pending-advisory age | `updates:pending-security` approximates age from the advisory ID year; `dnf updateinfo info` has issue dates but is slow. | 0.5 d |

## 6. Test gaps (P3, about 1-2 days total)

Covered now: collector parsers, RPM vercmp, matcher (`Match`, module
streams, source fallback, distro-vs-NVD), Red Hat judge (offline via the
detail cache), feed converters/store, daemon CVE verdicts and retention,
config, and every check built on `rules.Host` (fixture-root tests).

Still untested: reporter (JSON round-trip, PDF renders without panicking
on long or odd text), the original rules other than sshd_config, the Debian/Ubuntu
judges, monitor (inotify debounce/hash logic), scheduler, the IPC
round-trip, and feed `Sync` against recorded HTTP fixtures
(`httptest.Server`).

The biggest gap is the lack of field validation: nothing here has run
end to end on a real Rocky host yet. Before trusting the
module-stream logic, run `lyncd -once` on the php-fpm host and compare
against `dnf updateinfo list --security`.
