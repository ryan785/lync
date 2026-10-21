package lookup

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

// Runner runs a command and returns stdout (audit.Output in production).
type Runner func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error)

// PendingUpdate is one security update the package manager would install.
type PendingUpdate struct {
	Package  string // binary name, no arch
	Version  string // candidate version
	Advisory string // RLSA-2026:1234 (dnf/yum only)
	Severity string // Important/Moderate/... (dnf/yum only)
	Origin   string // apt suite ("Debian-Security:12/stable-security")
}

// LocalCheck asks the host's package manager which security updates it
// would install, from its cached metadata (dnf -C / yum -C; apt-get -s).
// It installs nothing. With refresh, metadata is refreshed first
// (dnf makecache / apt-get update), which writes to the package
// manager's cache directory and is therefore opt-in.
func LocalCheck(ctx context.Context, run Runner, manager string, refresh bool) ([]PendingUpdate, feed.SourceStat) {
	if run == nil {
		run = audit.Output
	}
	switch manager {
	case "rpm":
		return localRPM(ctx, run, refresh)
	case "dpkg":
		return localApt(ctx, run, refresh)
	}
	return nil, feed.SourceStat{Name: "pkgmgr", Kind: "local", Status: feed.StatusSkipped,
		Detail: "no security-update query for this package manager (apk has no security pocket)"}
}

var updateinfoRE = regexp.MustCompile(`^(\S+)\s+(\S+?)/Sec\.\s+(\S+)$`)

func localRPM(ctx context.Context, run Runner, refresh bool) ([]PendingUpdate, feed.SourceStat) {
	st := feed.SourceStat{Name: "dnf", Kind: "local", Status: feed.StatusOK}
	tool := "dnf"
	args := []string{"-C", "-q", "updateinfo", "list", "--security"}
	if _, err := run(ctx, 5*time.Second, "dnf", "--version"); err != nil {
		tool, st.Name = "yum", "yum"
		args = []string{"-C", "-q", "updateinfo", "list", "security"}
		if _, err := run(ctx, 5*time.Second, "yum", "--version"); err != nil {
			st.Status, st.Detail = feed.StatusSkipped, "neither dnf nor yum found"
			return nil, st
		}
	}
	st.Requests = 1
	if refresh {
		st.Requests++
		if _, err := run(ctx, 5*time.Minute, tool, "-q", "makecache"); err != nil {
			st.Detail = "metadata refresh failed: " + err.Error() + "; "
		}
	}
	out, err := run(ctx, 2*time.Minute, tool, args...)
	if err != nil && len(out) == 0 {
		st.Status = feed.StatusFailed
		st.Detail += tool + " updateinfo failed (no cached metadata? set feed.local_refresh: true or run `" + tool + " makecache`): " + err.Error()
		return nil, st
	}
	ups := ParseUpdateinfo(string(out))
	st.Records = len(ups)
	return ups, st
}

// ParseUpdateinfo parses `dnf updateinfo list --security` lines:
// "RLSA-2024:3501 Important/Sec. nghttp2-libs-1.43.0-5.el9_4.3.x86_64".
func ParseUpdateinfo(out string) []PendingUpdate {
	var ups []PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		m := updateinfoRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		name, ver := splitNEVRA(m[3])
		if name == "" {
			continue
		}
		ups = append(ups, PendingUpdate{Package: name, Version: ver, Advisory: m[1], Severity: m[2]})
	}
	return ups
}

// splitNEVRA: "curl-7.76.1-31.el9.x86_64" -> ("curl", "7.76.1-31.el9");
// "openssl-1:3.0.7-28.el9_4.x86_64" -> ("openssl", "1:3.0.7-28.el9_4").
func splitNEVRA(s string) (name, evr string) {
	if i := strings.LastIndex(s, "."); i > 0 {
		s = s[:i] // arch
	}
	r := strings.LastIndex(s, "-")
	if r <= 0 {
		return "", ""
	}
	v := strings.LastIndex(s[:r], "-")
	if v <= 0 {
		return "", ""
	}
	return s[:v], s[v+1:]
}

var aptInstRE = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^\[\)]*?)(?: \[[^\]]*\])?\)`)

func localApt(ctx context.Context, run Runner, refresh bool) ([]PendingUpdate, feed.SourceStat) {
	st := feed.SourceStat{Name: "apt", Kind: "local", Status: feed.StatusOK, Requests: 1}
	if refresh {
		st.Requests++
		if _, err := run(ctx, 5*time.Minute, "apt-get", "-q", "update"); err != nil {
			st.Detail = "metadata refresh failed: " + err.Error() + "; "
		}
	}
	out, err := run(ctx, 2*time.Minute, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil && len(out) == 0 {
		st.Status = feed.StatusFailed
		st.Detail += "apt-get -s dist-upgrade failed: " + err.Error()
		return nil, st
	}
	ups := ParseAptSimulate(string(out))
	st.Records = len(ups)
	return ups, st
}

// ParseAptSimulate parses `apt-get -s dist-upgrade` and keeps upgrades
// that come from a security suite ("...-security" / "Debian-Security").
func ParseAptSimulate(out string) []PendingUpdate {
	var ups []PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		m := aptInstRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[2] == "" { // new installs have no [old] version
			continue
		}
		if !strings.Contains(strings.ToLower(m[4]), "security") {
			continue
		}
		name, _, _ := strings.Cut(m[1], ":")
		ups = append(ups, PendingUpdate{Package: name, Version: m[3], Origin: strings.TrimSpace(m[4])})
	}
	return ups
}

// CrossCheck compares CVE findings with the package manager's pending
// security updates:
//   - a finding whose package (or a package from the same source) has a
//     pending security update is confirmed in its evidence;
//   - a finding with a fixed version but no pending update is flagged
//     (fix not visible to the package manager yet: stale metadata, or a
//     repository that has not shipped it);
//   - a pending security update no CVE finding explains becomes its own
//     finding ("pkgmgr:security-update:<pkg>"), with the advisory id.
func CrossCheck(facts *collector.Facts, findings []finding.Finding, ups []PendingUpdate, tool string) ([]finding.Finding, string) {
	bin := func(n string) string { b, _, _ := strings.Cut(n, ":"); return b }
	srcOf := map[string]string{}
	for _, p := range facts.Packages {
		s := p.SourceName()
		if s == "" {
			s = bin(p.Name)
		}
		srcOf[bin(p.Name)] = s
	}
	pending := map[string]PendingUpdate{}
	pendingSrc := map[string]PendingUpdate{}
	for _, u := range ups {
		pending[u.Package] = u
		if s := srcOf[u.Package]; s != "" {
			pendingSrc[s] = u
		}
	}
	covered := map[string]bool{} // sources with a CVE finding
	confirmed, lookupOnly := 0, 0
	for i := range findings {
		f := &findings[i]
		if f.Category != finding.CategoryCVE || f.CVE == "" {
			continue
		}
		b := bin(f.Package)
		src := srcOf[b]
		covered[src] = true
		covered[b] = true
		u, ok := pending[b]
		if !ok {
			u, ok = pendingSrc[src]
		}
		switch {
		case ok:
			confirmed++
			note := fmt.Sprintf("; %s: security update %s %s pending", tool, u.Package, u.Version)
			if u.Advisory != "" {
				note += " (" + u.Advisory + ")"
			}
			f.Evidence += note
		case f.FixedIn != "":
			lookupOnly++
			f.Evidence += fmt.Sprintf("; %s shows no pending security update for this package (metadata may be stale, or the fix is not in the configured repositories yet)", tool)
		}
	}
	var extra []finding.Finding
	names := make([]string, 0, len(pending))
	for n := range pending {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := pending[n]
		if covered[n] || covered[srcOf[n]] {
			continue
		}
		installed := ""
		for _, p := range facts.Packages {
			if bin(p.Name) == n {
				installed = p.NEVRA()
				break
			}
		}
		sev := finding.SeverityMedium
		switch strings.ToLower(u.Severity) {
		case "critical":
			sev = finding.SeverityCritical
		case "important":
			sev = finding.SeverityHigh
		case "low":
			sev = finding.SeverityLow
		}
		title := fmt.Sprintf("Security update pending for %s", n)
		rem := fmt.Sprintf("apt-get install --only-upgrade %s", n)
		var refs []string
		if tool != "apt" {
			rem = fmt.Sprintf("%s upgrade %s", tool, n)
		}
		if u.Advisory != "" {
			title += " (" + u.Advisory + ")"
			refs = append(refs, advisoryURL(u.Advisory))
		}
		ev := fmt.Sprintf("%s reports a security update to %s", tool, u.Version)
		if u.Origin != "" {
			ev += " from " + u.Origin
		}
		ev += "; no CVE lookup source matched this package"
		extra = append(extra, finding.Finding{
			ID:          "pkgmgr:security-update:" + n,
			Category:    finding.CategoryCVE,
			Severity:    sev,
			Title:       title,
			Evidence:    ev,
			References:  refs,
			Remediation: rem,
			DetectedAt:  time.Now(),
			Package:     n,
			Installed:   installed,
			FixedIn:     u.Version,
			Source:      tool,
		})
	}
	summary := fmt.Sprintf("pending=%d confirmed=%d lookup_only=%d pkgmgr_only=%d", len(ups), confirmed, lookupOnly, len(extra))
	return append(findings, extra...), summary
}

func advisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "RLSA-"):
		return "https://errata.rockylinux.org/" + id
	case strings.HasPrefix(id, "RH"):
		return "https://access.redhat.com/errata/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}
