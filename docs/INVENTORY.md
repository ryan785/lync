# Application inventory

The OS package scan (rpm/dpkg/apk) only sees what the package manager
installed. `internal/inventory` covers everything else: application
dependencies in lockfiles, pip/npm/gem installs, jars, Go and Rust
binaries, WordPress sites and, opt-in, running container images. Each
component is named in [OSV](https://ossf.github.io/osv-schema/) ecosystem
terms, so one OSV.dev lookup answers "is anything on this host affected by
a newly published advisory?".

## API

```go
comps, warns := inventory.Collect(ctx, host, inventory.Options{})       // host: *rules.Host, nil = real "/"
res := inventory.CollectResult(ctx, host, opts)                          // + Stats (roots, entries, duration, truncated)
hits, err := inventory.QueryOSV(ctx, &inventory.OSVClient{}, comps)      // nil client = defaults
findings := inventory.Findings(hits, time.Now())                         // []finding.Finding, category "cve"
```

`Component`:

| Field | Meaning |
|---|---|
| `Ecosystem` | `npm`, `PyPI`, `Maven`, `Packagist`, `Go`, `crates.io`, `RubyGems`, `NuGet`; app types `WordPress`, `WordPress:plugin`, `WordPress:theme`, `container-image` (not sent to OSV) |
| `Name`, `Version` | as OSV expects them (PyPI names PEP 503-normalised, Maven `group:artifact`, Go versions without `v`, composer `v` prefixes dropped) |
| `Paths` | every host path the component was seen at (lockfile, dist-info dir, `outer.war!WEB-INF/lib/x.jar`, binary, `docker:<container>`) |
| `Source` | `lockfile`, `manifest`, `binary`, `metadata` |
| `Scope` | `system` (under `/usr`, `/var/lib/gems`), `app`, `container` |
| `Dev` | every occurrence is a development-only dependency |
| `Meta` | non-secret extras: image digest/OS/arch, the binary a Go module came from |

`Warning{Kind, Path, Reason}` reports skipped mounts, size-capped files,
unparseable files and limits that cut the walk short (`Kind` = `skip`,
`error`, `limit`).

## What is collected

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` (v5, v6, v9), `node_modules/.package-lock.json`, and `node_modules/*/package.json` when there is no lockfile (global installs; bundled deps up to 4 levels) |
| PyPI | `site-packages` / `dist-packages`: `*.dist-info/METADATA`, `*.egg-info`; venvs found under the roots; `requirements*.txt` exact pins; `poetry.lock`; `Pipfile.lock` |
| Packagist | `composer.lock` (`packages-dev` flagged), `vendor/composer/installed.json` when no lock is beside it; Laravel is `laravel/framework` from the lock; Pterodactyl Panel from `config/app.php` `'version'` (only that key is read) as `pterodactyl/panel` |
| WordPress | core from `wp-includes/version.php`; plugins (main file `Version:` header, `readme.txt` `Stable tag:` fallback) and themes (`style.css`). `wp-config.php` is never opened |
| Maven | `*.jar`, `*.war`, `*.ear`: `META-INF/maven/**/pom.properties`, nested jars (2 levels), loose `pom.properties` in exploded archives; jars without one fall back to file name + `MANIFEST.MF` with a group table for log4j, spring, jackson, commons, struts, netty, tomcat... |
| Go | ELF binaries with build info: every module plus `stdlib` at the toolchain version. Found under the roots and at systemd `ExecStart=` paths |
| crates.io | `Cargo.lock` registry crates; cargo-auditable `.dep-v0` sections in binaries |
| RubyGems | `Gemfile.lock` / `gems.locked`; installed `specifications/*.gemspec` (from file names) |
| NuGet | `*.deps.json` `package` libraries |
| container-image | `docker`/`podman` `ps` + `inspect` + `image inspect`: reference, tag, digest, OS/arch, OCI labels. Opt-in (`Options.Containers`); nothing runs inside containers |

Only names and versions leave the parsers. File contents (configuration,
`.env`, credentials) are never copied into components, warnings or findings.

## Limits and defaults

| Option | Default |
|---|---|
| `Roots` | `/var/www`, `/srv`, `/opt`, `/usr/local` (depth 10); `/root`, `/home/*` (depth 7); `/usr/lib/node_modules`, `/usr/lib{,64}/python3*/site-packages` (depth 1); `/var/lib/gems` (depth 4). Globs allowed; missing roots ignored; nested roots merged |
| `MaxDepth` | 10 directories below a root |
| `MaxEntries` | 300 000 directory entries for the whole run |
| `MaxFileSize` | 64 MiB per lockfile/manifest |
| `MaxArchive` / `MaxNested` / `NestedDepth` | 512 MiB per archive on disk, 64 MiB per nested jar (read into memory), 2 levels |
| `TimeBudget` | 2 minutes |
| `NoBinaries` | false (Go/cargo-auditable reads on) |
| `Containers` | false |
| `IncludeOSManaged` | false |
| `SkipPaths` | none |

Never entered: `/proc`, `/sys`, `/dev`, `/run`, `/var/lib/{docker,containers,containerd,lxc,lxd}`,
`/var/lib/kubelet/pods`, `/snap`; mount points whose type is a network
filesystem (nfs, cifs/smb, sshfs, ceph, gluster, rclone, s3fs...), a host
share (9p, drvfs, virtiofs) or an image/overlay layer (overlay, aufs,
squashfs) unless it is `/` itself; `.git`, `.hg`, `.svn`, `__pycache__`,
`.cache`, `.npm`, `.m2`, `.gradle`, `.rustup`, `testdata`, `__tests__`, and
package caches (`go/pkg/mod`, `.cargo/registry`, pnpm/yarn/composer
caches). Symlinks are not followed. Skipped mounts and limits produce
warnings; `Stats.Truncated` is set when a limit stopped the walk.

**OS-managed components are skipped by default** so the OS scan (with its
backport-aware distro data) stays the authority for them: python modules
whose `INSTALLER` is `rpm`/`dpkg`/`debian`/`apk` or that sit under
`/usr/lib*` without an `INSTALLER`, gem specifications under `/usr/share`,
and `ExecStart=` binaries under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`,
`/usr/lib*`, `/usr/libexec`, `/lib*`.

Only ELF files without an extension (or `.bin`) and at least 512 KiB are
opened as binaries, and only their headers/sections are read.

## OSV.dev lookup

`QueryOSV` is a thin wrapper over `feed.OSVLookup` (`QueryBatchEach`,
`FetchRecords`), the one OSV client shared with the OS package lookups. It posts `{"queries":[{"package":{"name","ecosystem"},"version"}]}`
to `https://api.osv.dev/v1/querybatch` in chunks of `BatchSize` (max 1000,
the API limit), re-queries only the entries that returned a
`next_page_token` (up to `MaxPages` rounds), and then fetches
`/v1/vulns/{id}` once per distinct ID that hit (`Concurrency` parallel
requests). Components that OSV does not index (WordPress, container
images, Maven jars without a known group) are not sent.

`Findings` emits one finding per (vulnerability, component, path):

- `ID` `<CVE or OSV id>:<ecosystem>/<name>@<path>` (stable across runs).
  The CVE alias is preferred; records that alias each other (a GHSA and a
  PYSEC for the same CVE) collapse into one finding.
- `Severity` from the database severity (GHSA `LOW`/`MODERATE`/`HIGH`/`CRITICAL`),
  else from the CVSS v3 base score computed from the vector; `CVSS` holds
  that score when a v3 vector exists.
- `FixedIn` the lowest fixed version above the installed one in the
  record's ranges for this package.
- `Evidence` path, installed name/version/ecosystem/source/scope, dev flag,
  OSV ID and aliases, summary.
- `Remediation` e.g. `upgrade lodash to >= 4.17.21 in /var/www/shop (npm install lodash@4.17.21, or npm audit fix)`,
  with `composer update`, `pip install --upgrade`, `poetry update`,
  `pipenv update`, `cargo update -p`, `bundle update`, `dotnet add package`,
  a rebuild for Go binaries, or a dependency update/jar replacement for Maven.
- `Source` `osv`, `Category` `cve`, `Package`/`Installed` filled.

## Wiring into a scan

Full-host scans (daemon and `lyncd -once`) run the inventory after the
rules engine (`internal/daemon/inventory.go`): `CollectResult` with the
`inventory:` config block (`enabled` default true, `containers` default
false, `roots`, `skip_paths`, `time_budget` default 2m; `rules.root` is
honoured), warnings as `INVENTORY` audit lines (first 100), `QueryOSV`,
then `Findings`. A failed lookup marks the report's CVE data incomplete
(source `osv-apps`). The JSON report gets an `inventory` section
(component list, counts per ecosystem, vulnerable count, walk stats,
warning samples) and the PDF a short summary. `lyncd -sources none` turns
the inventory off.

## Not covered

- Image layers: container images are identified (ref, digest, OS) but
  their filesystems are not unpacked. Scanning a running container's
  merged root via `/proc/<pid>/root` with the same collectors is the cheap
  next step.
- Go modules from `go.mod`/`go.sum` (source trees) are not read; only
  built binaries.
- Composer/npm dependencies vendored into a WordPress plugin are found;
  WordPress core/plugin/theme vulnerabilities themselves are not in OSV
  (that needs the WPScan or Wordfence feed).
- Distro-packaged Go programs (`/usr/bin/*`) are skipped by default because
  distros patch Go without changing the reported toolchain version.
- Version ordering for picking `FixedIn` is generic (numeric segments,
  pre-releases first), not each ecosystem's exact rules; matching itself
  is done by OSV.
