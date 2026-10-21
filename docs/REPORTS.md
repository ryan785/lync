# Report format

Every scan writes two files under `report.dir` (default
`/var/lib/lync/reports/`):

```
lync-<timestamp>.json   # canonical, machine-readable, ~20-200 KB
lync-<timestamp>.pdf    # rendered from JSON, human-readable
```

`<timestamp>` is local time in `YYYY-MM-DD_HH-MM-SS` form. Scoped scans
add a suffix:

```
lync-2026-05-13_17-20-40-pkg_openssh.pdf       # lync scan -package openssh
lync-2026-05-13_17-20-45-svc_sshd.pdf          # lync scan -service sshd
lync-2026-05-13_17-20-47-kernel.pdf            # lync scan -kernel
```

The JSON is the authoritative artifact. The PDF renderer reads from the
JSON, so the two cannot drift. `lync render <json>` re-renders a PDF
from any past JSON.

---

## JSON schema

Top-level `Report` (defined in `internal/reporter/json.go`):

```jsonc
{
  "generated": "2026-05-13T17:30:35.123Z",
  "host":      "us-rock-test",
  "os":        { /* collector.OSInfo */ },
  "kernel":    { /* collector.KernelInfo */ },
  "package_count": 738,
  "counts":    { /* see below */ },
  "impact":    { /* see below */ },
  "findings":  [ /* array of finding.Finding */ ]
}
```

### `os` (collector.OSInfo)

```jsonc
{
  "id": "rocky",
  "name": "Rocky Linux",
  "version": "9.7 (Blue Onyx)",
  "version_id": "9.7",
  "id_like": ["rhel", "centos", "fedora"],
  "pretty_name": "Rocky Linux 9.7 (Blue Onyx)",
  "cpe_name": "cpe:/o:rocky:rocky:9::baseos"
}
```

### `kernel` (collector.KernelInfo)

```jsonc
{
  "release": "5.14.0-611.54.1.el9_7.x86_64",
  "version": "#1 SMP PREEMPT_DYNAMIC ...",
  "machine": "x86_64"
}
```

### `counts`

Severity histogram across all findings:

```jsonc
{
  "critical": 2,
  "high":     17,
  "medium":   17,
  "low":      3,
  "info":     0,
  "unknown":  0,
  "total":    39
}
```

### `impact` (ImpactSummary)

```jsonc
{
  "total_findings": 39,
  "unique_package_count": 14,
  "unique_packages": ["firewalld", "git", "glibc", "jq", "kernel", ...],
  "kernel_findings": 1,
  "kernel_cves": ["CVE-2026-43284"],
  "needs_reboot": true,
  "highest_cvss": 9.8,
  "highest_cvss_cve": "CVE-2026-5450",
  "highest_cvss_package": "glibc",
  "severity_counts": [
    {"severity": "Critical", "count": 2},
    {"severity": "High",     "count": 17},
    {"severity": "Medium",   "count": 17},
    {"severity": "Low",      "count": 3},
    {"severity": "Info",     "count": 0},
    {"severity": "Unknown",  "count": 0}
  ],
  "active_services_affected": ["firewalld.service"],
  "running_services_total": 21
}
```

### `findings[]` (finding.Finding)

```jsonc
{
  "id":          "CVE-2026-43284:kernel",        // uniqueness key
  "category":    "cve",                          // cve|config|eol|hardening|filesystem|network|tls|runtime
  "severity":    "High",                         // Critical|High|Medium|Low|Info|Unknown
  "title":       "CVE-2026-43284 affects kernel",
  "evidence":    "installed: kernel-5.14.0-611.54.1.el9_7.x86_64; reported by: redhat",
  "references":  ["https://access.redhat.com/errata/RHSA-2026:1234"],
  "remediation": "update kernel to 0:5.14.0-611.55.1.el9_7 or later",
  "detected_at": "2026-05-13T17:30:35.123Z",

  // CVE-specific (empty for rule findings)
  "cve":       "CVE-2026-43284",
  "package":   "kernel",
  "installed": "kernel-5.14.0-611.54.1.el9_7.x86_64",
  "fixed_in":  "0:5.14.0-611.55.1.el9_7",
  "cvss":      7.8,
  "source":    "redhat"
}
```

For non-CVE findings (rules + monitor), the `cve` / `package` /
`installed` / `fixed_in` / `cvss` fields are empty and `source` is
either `"lync-rules"` or `"lync-monitor"`.

### `data_sources` (feed.ScanSources)

Where the CVE data came from. Absent in reports from older versions.

```json
"data_sources": {
  "mode": "lookup",
  "checked_at": "2026-10-21T08:00:36Z",
  "ecosystem": "Debian:12",
  "packages_checked": 159,
  "complete": true,
  "incomplete_reasons": [],
  "sources": [
    {"name": "osv", "kind": "lookup", "status": "ok", "requests": 343, "cache_hits": 0, "records": 342, "bytes": 999661},
    {"name": "nvd", "kind": "lookup", "status": "ok", "requests": 10, "records": 10, "bytes": 53650},
    {"name": "apt", "kind": "local", "status": "ok", "requests": 1, "detail": "pending=0 confirmed=0 lookup_only=118 pkgmgr_only=0"},
    {"name": "osv-apps", "kind": "lookup", "status": "skipped", "detail": "no application components to look up"}
  ],
  "unfixed_cves": 214
}
```

`kind` is `lookup`, `bulk` (full mode) or `local` (package manager).
`status` is `ok`, `partial`, `failed` or `skipped`. When `complete` is
false the CVE section is incomplete: the PDF shows a red banner, a zero
finding count is not a clean bill of health, and `lyncd -once` exits 3.
`unfixed_cves` counts CVEs that affect an installed package but have no
fixed version yet (not listed as findings).

### `inventory`

Application components found outside the package manager (full-host
scans): `total`, `counts` per ecosystem, `queried` (sent to OSV.dev),
`vulnerable`, `status`, `warnings` with `warning_samples`, walk `stats`,
and `components[]` (ecosystem, name, version, paths, source, scope). See
[INVENTORY.md](INVENTORY.md).

### Categories vs sources

`category` is what kind of issue it is; `source` is who reported it.

| Category | Producers | Source values |
|---|---|---|
| `cve` | matcher, package-manager cross-check (`pkgmgr:security-update:<pkg>`), inventory | `redhat`, `nvd`, `debian`, `ubuntu`, `alpine`, `osv`, `apt`, `dnf`, `yum` |
| `config` | accounts.go, ssh_config.go | `lync-rules` |
| `eol` | eol.go | `lync-rules` |
| `hardening` | hardening.go | `lync-rules` |
| `filesystem` | filesystem.go | `lync-rules` |
| `network` | network.go | `lync-rules` |
| `tls` | (reserved) | `lync-rules` |
| `runtime` | monitor | `lync-monitor` |

---

## PDF format

The PDF is a faithful visual rendering of the JSON:

- **Page 1, header**: host + scan timestamp
- **Page 1, host block**: hostname / OS / kernel / package count / running
  services / scan time
- **Page 1, data sources**: feed mode, check time, packages checked,
  ecosystem, one line per source (status, requests, cached, records), the
  count of CVEs with no fix yet, and a red "CVE SECTION INCOMPLETE" banner
  with the reasons when a source failed
- **Page 1, executive summary**: total finding count, highest CVSS callout,
  kernel CVE callout (with specific CVE IDs), active-services-affected
  list
- **Page 1, severity distribution**: horizontal stacked-bar chart, one row
  per severity, sorted by count
- **Application inventory**: one paragraph (components per ecosystem, how
  many OSV.dev flagged, walk stats); the list is in the JSON
- **Page 2+, findings list**: one card per finding, sorted newest CVE
  first. Each card shows severity-colored left bar, CVE + package on the
  title row, severity label on the right, body fields (Fixed in, CVSS,
  Source, Fix) below

Severity colors:

| Severity | RGB |
|---|---|
| Critical | (176, 0, 32) — dark red |
| High | (216, 67, 21) — red-orange |
| Medium | (245, 124, 0) — amber |
| Low | (158, 157, 36) — olive |
| Info | (84, 110, 122) — blue-gray |
| Unknown | (158, 158, 158) — gray |

---

## Common jq queries

```sh
LATEST=$(ls -1t /var/lib/lync/reports/lync-*.json | head -1)

# Severity histogram
jq '.counts' "$LATEST"

# Just the High and Critical findings, sorted by CVSS desc
jq -r '.findings | map(select(.severity=="High" or .severity=="Critical")) |
       sort_by(-.cvss) |
       .[] | "\(.severity)\t\(.cvss)\t\(.cve)\t\(.package)"' "$LATEST"

# All kernel CVEs we still need patches for
jq -r '.findings[] | select(.package=="kernel") |
       "\(.severity)\t\(.cve)\t\(.fixed_in)"' "$LATEST"

# Findings by category
jq '[.findings[].category] | group_by(.) | map({category: .[0], count: length})' "$LATEST"

# Just runtime (file-integrity) findings
jq '.findings | map(select(.source=="lync-monitor"))' "$LATEST"

# Highest CVSS that the distro hasn't shipped a fix for yet
jq -r '.findings | map(select(.fixed_in=="" or .fixed_in==null)) |
       sort_by(-.cvss) | .[0:5] |
       .[] | "\(.cvss)\t\(.cve)\t\(.package)"' "$LATEST"
```

---

## Retention

Set `report.retention_days` in `lync.yaml` to a positive N and the daemon
deletes `lync-*.json` / `lync-*.pdf` older than N days after every scan.
`0` (the default) keeps everything.
