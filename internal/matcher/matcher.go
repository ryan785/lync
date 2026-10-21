package matcher

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

// Match runs vulnerabilities against collected facts and produces findings.
// Findings keyed on (CVE, package) are deduplicated, preferring
// distro-specific sources (redhat, debian, ubuntu, suse, alpine, then osv)
// over NVD. When a distro-specific source evaluated the same (CVE, package)
// against a concrete fixed version and found the installed build already
// patched, NVD's upstream-version opinion is dropped: distro backports beat
// upstream version ranges.
func Match(facts *collector.Facts, vulns []feed.Vulnerability, log *slog.Logger) []finding.Finding {
	// Dedupe installed packages by name, keeping the highest NEVR. Without
	// this, hosts with multiple installed kernels (5.14.0-611.5.1,
	// 611.16.1, 611.54.1 all on disk for fallback boot) would each produce
	// their own finding for the same CVE — and the .5.1 copy would be
	// reported as "vulnerable" even though .54.1 is also installed and
	// would be selected on next boot.
	pkgByName := make(map[string]collector.Package, len(facts.Packages))
	for _, p := range facts.Packages {
		if existing, ok := pkgByName[p.Name]; ok {
			if CompareNEVR(p.NEVR(), existing.NEVR()) <= 0 {
				continue
			}
		}
		pkgByName[p.Name] = p
	}
	bySource := sourceIndex(pkgByName)

	type key struct{ cve, pkg string }
	out := make(map[key]finding.Finding)
	// patched records (CVE, package) pairs that a distro-specific source
	// evaluated against a concrete fixed version and found NOT vulnerable.
	patched := make(map[key]bool)

	for _, v := range vulns {
		// Group this vulnerability's applicable entries by the installed
		// package they resolve to, so module-stream selection can see every
		// candidate fix for one package at once.
		var order []string
		cands := map[string][]feed.AffectedPackage{}
		viaSource := map[string]bool{}
		for _, ap := range v.Affects {
			if !distroMatches(ap.Distro, facts.OS) {
				continue
			}
			pkg, bySrc, ok := resolvePackage(ap.Name, pkgByName, bySource)
			if !ok {
				continue
			}
			if _, seen := cands[pkg.Name]; !seen {
				order = append(order, pkg.Name)
			}
			cands[pkg.Name] = append(cands[pkg.Name], ap)
			if bySrc {
				viaSource[pkg.Name] = true
			}
		}

		for _, name := range order {
			pkg := pkgByName[name]
			aps := selectModuleStream(pkg, cands[name])

			hit := -1
			for i := range aps {
				if isVulnerable(pkg, aps[i]) {
					hit = i
					break
				}
			}
			k := key{v.ID, pkg.Name}
			if hit < 0 {
				if sourcePriority(v.Source) > 0 && hasDistroFix(aps) {
					patched[k] = true
				}
				continue
			}
			ap := aps[hit]
			evidence := fmt.Sprintf("installed: %s; reported by: %s", pkg.NEVRA(), v.Source)
			if viaSource[name] {
				evidence += fmt.Sprintf("; matched via source package %q", ap.Name)
			}
			f := finding.Finding{
				ID:         v.ID + ":" + pkg.Name,
				Category:   finding.CategoryCVE,
				Severity:   normalizeSeverity(v.Severity, v.CVSS),
				Title:      fmt.Sprintf("%s affects %s", v.ID, pkg.Name),
				Evidence:   evidence,
				References: v.References,
				DetectedAt: time.Now(),
				CVE:        v.ID,
				Package:    pkg.Name,
				Installed:  pkg.NEVRA(),
				FixedIn:    ap.FixedVersion,
				CVSS:       v.CVSS,
				Source:     v.Source,
			}
			if ap.FixedVersion != "" {
				f.Remediation = fmt.Sprintf("update %s to %s or later", pkg.Name, ap.FixedVersion)
				if isModuleBuild(pkg.Release) && isModuleBuild(fixRelease(ap.FixedVersion)) &&
					streamOf(pkg.Version) != streamOf(fixVersion(ap.FixedVersion)) {
					f.Remediation = fmt.Sprintf(
						"no fix found for the installed module stream (%s %s); fixed in %s - switch module stream (dnf module switch-to)",
						pkg.Name, streamOf(pkg.Version), ap.FixedVersion)
				}
			}
			if existing, ok := out[k]; ok {
				if sourcePriority(v.Source) <= sourcePriority(existing.Source) {
					continue
				}
			}
			out[k] = f
		}
	}

	// Distro beats NVD: drop upstream-only findings the distro says are
	// already patched on this host.
	dropped := 0
	for k, f := range out {
		if sourcePriority(f.Source) == 0 && patched[k] {
			delete(out, k)
			dropped++
		}
	}

	findings := make([]finding.Finding, 0, len(out))
	for _, f := range out {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		yi, ni := cveSortKey(findings[i].CVE)
		yj, nj := cveSortKey(findings[j].CVE)
		if yi != yj {
			return yi > yj
		}
		if ni != nj {
			return ni > nj
		}
		// CVE collision (multi-package): higher severity first.
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		return findings[i].Package < findings[j].Package
	})

	if log != nil {
		log.Info("matcher complete",
			"vulns_evaluated", len(vulns),
			"installed_packages", len(facts.Packages),
			"nvd_dropped_as_distro_patched", dropped,
			"findings", len(findings))
	}
	return findings
}

// sourceIndex maps source-package name -> installed binary package names
// (sorted) for packages whose binary name differs from their source name.
func sourceIndex(pkgByName map[string]collector.Package) map[string][]string {
	idx := map[string][]string{}
	for name, p := range pkgByName {
		src := p.SourceName()
		if src == "" || src == name {
			continue
		}
		idx[src] = append(idx[src], name)
	}
	for _, names := range idx {
		sort.Strings(names)
	}
	return idx
}

// resolvePackage finds the installed package a feed entry refers to. An
// exact binary-name match wins. Otherwise the feed name is treated as a
// source package name: NVD CPE products ("php", "curl") and some distro
// feeds name the source, while hosts often install only binary subpackages
// ("php-fpm", "php-cli", "libcurl"). Binaries built from one source share a
// version, so the alphabetically first one stands in for the group; this
// keeps one finding per (CVE, source) instead of one per subpackage.
func resolvePackage(name string, pkgByName map[string]collector.Package, bySource map[string][]string) (pkg collector.Package, viaSource, ok bool) {
	if p, found := pkgByName[name]; found {
		return p, false, true
	}
	if names := bySource[name]; len(names) > 0 {
		return pkgByName[names[0]], true, true
	}
	return collector.Package{}, false, false
}

// hasDistroFix reports whether any candidate carries a concrete,
// distro-scoped fixed version (as opposed to NVD's distro-agnostic upstream
// ranges).
func hasDistroFix(aps []feed.AffectedPackage) bool {
	for _, ap := range aps {
		if ap.FixedVersion != "" && ap.Distro != "" && ap.Distro != "*" {
			return true
		}
	}
	return false
}

// moduleBuildRE matches RHEL-family appstream module build releases:
// "1.module+el8.10.0+1872+abcd" (RHEL/Rocky) or "1.module_el8.6.0+..." (Alma).
var moduleBuildRE = regexp.MustCompile(`(^|\.)module[+_]el\d`)

func isModuleBuild(release string) bool { return moduleBuildRE.MatchString(release) }

// fixVersion and fixRelease split a feed fixed-version "[E:]V-R" string.
func fixVersion(nevr string) string {
	_, v, _ := splitNEVR(nevr)
	return v
}

func fixRelease(nevr string) string {
	_, _, r := splitNEVR(nevr)
	return r
}

// streamOf returns "major.minor" of a version ("8.0.30" -> "8.0").
func streamOf(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

// selectModuleStream narrows candidate fixes for a module-built package to
// the ones from the installed module stream. RHEL-family appstreams ship the
// same binary name (php-fpm, nodejs, postgresql) in parallel streams, and
// one CVE produces one advisory per stream. Comparing an installed php 7.4
// build against the php 8.0 stream's fix would always report "vulnerable"
// (7.4.x < 8.0.30) even when the 7.4 stream's own fix is installed.
//
// Stream identity isn't in the package NEVRA, so it is inferred: among
// module-build candidates, keep those whose version shares the longest
// leading run of dotted components with the installed version (php 8.0.30
// vs 8.0.30/8.2.13/7.4.33 keeps 8.0.30; nodejs 18.19 vs 18.20/20.11 keeps
// 18.20). Non-module candidates (e.g. NVD upstream ranges) pass through
// untouched. If no candidate shares even the major version, all are kept
// and the caller reports a cross-stream remediation.
func selectModuleStream(pkg collector.Package, aps []feed.AffectedPackage) []feed.AffectedPackage {
	if len(aps) < 2 || !isModuleBuild(pkg.Release) {
		return aps
	}
	best := 0
	score := make([]int, len(aps))
	for i, ap := range aps {
		score[i] = -1
		if ap.FixedVersion == "" || !isModuleBuild(fixRelease(ap.FixedVersion)) {
			continue
		}
		score[i] = commonVersionPrefix(pkg.Version, fixVersion(ap.FixedVersion))
		if score[i] > best {
			best = score[i]
		}
	}
	if best == 0 {
		return aps
	}
	out := make([]feed.AffectedPackage, 0, len(aps))
	for i, ap := range aps {
		if score[i] == -1 || score[i] == best {
			out = append(out, ap)
		}
	}
	return out
}

func commonVersionPrefix(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	return n
}

func isVulnerable(pkg collector.Package, ap feed.AffectedPackage) bool {
	if ap.FixedVersion != "" {
		return CompareNEVR(pkg.NEVR(), ap.FixedVersion) < 0
	}
	if ap.VersionRange != "" {
		return matchVersionRange(pkg.Version, ap.VersionRange)
	}
	return false
}

func matchVersionRange(version, rng string) bool {
	for _, raw := range strings.Split(rng, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		var op, val string
		switch {
		case strings.HasPrefix(p, ">="):
			op, val = ">=", p[2:]
		case strings.HasPrefix(p, "<="):
			op, val = "<=", p[2:]
		case strings.HasPrefix(p, ">"):
			op, val = ">", p[1:]
		case strings.HasPrefix(p, "<"):
			op, val = "<", p[1:]
		case strings.HasPrefix(p, "="):
			op, val = "=", p[1:]
		default:
			return false
		}
		c := rpmvercmp(version, val)
		switch op {
		case ">=":
			if c < 0 {
				return false
			}
		case "<=":
			if c > 0 {
				return false
			}
		case ">":
			if c <= 0 {
				return false
			}
		case "<":
			if c >= 0 {
				return false
			}
		case "=":
			if c != 0 {
				return false
			}
		}
	}
	return true
}

// cveSortKey extracts (year, num) from a "CVE-YYYY-NNNN" id for sort ordering.
// Returns (0,0) for malformed ids so they sort to the bottom.
func cveSortKey(cve string) (int, int) {
	parts := strings.Split(cve, "-")
	if len(parts) != 3 {
		return 0, 0
	}
	year, _ := strconv.Atoi(parts[1])
	num, _ := strconv.Atoi(parts[2])
	return year, num
}

func sourcePriority(source string) int {
	switch source {
	case "redhat", "debian", "ubuntu", "suse", "alpine":
		return 2
	case "osv":
		return 1
	}
	return 0
}

// DistroMatches is the exported form of distroMatches for callers that need
// to apply the same distro filter outside Match (e.g. `lync cve`).
func DistroMatches(filter string, os collector.OSInfo) bool { return distroMatches(filter, os) }

// distroMatches returns true if the AffectedPackage's distro filter applies to
// the host OS. Filter format is "<family>[:<major>]" or "*"/empty for any.
func distroMatches(filter string, os collector.OSInfo) bool {
	if filter == "" || filter == "*" {
		return true
	}
	family, ver, _ := strings.Cut(filter, ":")
	if !familyMatches(family, os) {
		return false
	}
	if ver == "" {
		return true
	}
	// Match whole dotted components: "rhel:8" must accept VersionID "8" or
	// "8.10" but not "80"; "rhel:1" must not accept "10.0".
	return os.VersionID == ver || strings.HasPrefix(os.VersionID, ver+".")
}

func familyMatches(family string, os collector.OSInfo) bool {
	if family == "rhel" {
		return isRPMLike(os)
	}
	if os.ID == family {
		return true
	}
	for _, l := range os.IDLike {
		if l == family {
			return true
		}
	}
	return false
}

func isRPMLike(os collector.OSInfo) bool {
	switch os.ID {
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol", "amzn":
		return true
	}
	for _, l := range os.IDLike {
		if l == "rhel" {
			return true
		}
	}
	return false
}

func normalizeSeverity(s string, cvss float64) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high", "important":
		return finding.SeverityHigh
	case "medium", "moderate":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	}
	switch {
	case cvss >= 9.0:
		return finding.SeverityCritical
	case cvss >= 7.0:
		return finding.SeverityHigh
	case cvss >= 4.0:
		return finding.SeverityMedium
	case cvss > 0:
		return finding.SeverityLow
	}
	return finding.SeverityUnknown
}
