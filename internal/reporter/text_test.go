package reporter

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

// fixtureReport mixes OS-package CVEs (one with no fix, one kernel),
// an application-component CVE, a package-manager advisory without a
// CVE, and config findings, with an incomplete data source, inventory
// and coverage.
func fixtureReport() *Report {
	when := time.Date(2026, 10, 21, 14, 3, 5, 0, time.UTC)
	facts := &collector.Facts{
		Hostname: "host1.example.com",
		OS:       collector.OSInfo{ID: "rocky", IDLike: []string{"rhel", "centos", "fedora"}, VersionID: "9.4", PrettyName: "Rocky Linux 9.4 (Blue Onyx)"},
		Kernel:   collector.KernelInfo{Release: "5.14.0-427.13.1.el9_4.x86_64", Machine: "x86_64"},
		Packages: make([]collector.Package, 612),
		Services: []collector.Service{{Name: "php-fpm.service", Package: "php-fpm"}, {Name: "sshd.service", Package: "openssh-server"}},
	}
	cve := func(id, pkg, inst, fixed string, sev finding.Severity, cvss float64) finding.Finding {
		f := finding.Finding{ID: id + ":" + pkg, Category: finding.CategoryCVE, Severity: sev, Title: id + " affects " + pkg,
			Evidence: "installed: " + inst + "; reported by: osv", CVE: id, Package: pkg, Installed: inst, FixedIn: fixed,
			CVSS: cvss, Source: "osv", References: []string{"https://osv.dev/vulnerability/" + id, "https://nvd.nist.gov/vuln/detail/" + id, "https://access.redhat.com/security/cve/" + id}}
		if fixed != "" {
			f.Remediation = "update " + pkg + " to " + fixed + " or later"
		}
		return f
	}
	fs := []finding.Finding{
		cve("CVE-2026-10001", "php-fpm", "php-fpm-8.0.30-1.el9.x86_64", "8.0.30-3.el9", finding.SeverityCritical, 9.8),
		cve("CVE-2026-10002", "php-fpm", "php-fpm-8.0.30-1.el9.x86_64", "8.0.30-2.el9", finding.SeverityCritical, 9.1),
		cve("CVE-2026-10003", "php-fpm", "php-fpm-8.0.30-1.el9.x86_64", "8.0.30-3.el9", finding.SeverityHigh, 7.5),
		cve("CVE-2026-20001", "kernel", "kernel-5.14.0-427.13.1.el9_4.x86_64", "5.14.0-503.11.1.el9_5", finding.SeverityHigh, 7.8),
		cve("CVE-2026-20002", "kernel", "kernel-5.14.0-427.13.1.el9_4.x86_64", "5.14.0-503.11.1.el9_5", finding.SeverityMedium, 5.5),
		cve("CVE-2026-30001", "openssl-libs", "openssl-libs-1:3.0.7-27.el9.x86_64", "1:3.0.7-28.el9_4", finding.SeverityMedium, 5.9),
		cve("CVE-2026-40001", "libxml2", "libxml2-2.9.13-6.el9_4.x86_64", "", finding.SeverityLow, 3.3),
		{ID: "pkgmgr:security-update:curl", Category: finding.CategoryCVE, Severity: finding.SeverityMedium,
			Title: "Security update pending for curl (RLSA-2026:1234)", Evidence: "dnf reports a security update to 7.76.1-31.el9; no CVE lookup source matched this package",
			Remediation: "dnf upgrade curl", Package: "curl", Installed: "curl-7.76.1-29.el9_4.x86_64", FixedIn: "7.76.1-31.el9", Source: "dnf"},
		{ID: "CVE-2026-50001:npm/lodash@/srv/app/package-lock.json", Category: finding.CategoryCVE, Severity: finding.SeverityHigh,
			Title: "CVE-2026-50001 affects lodash 4.17.15 (npm)", Evidence: "/srv/app/package-lock.json declares lodash 4.17.15",
			Remediation: "upgrade lodash to >= 4.17.21 in /srv/app (npm install lodash@4.17.21)", CVE: "CVE-2026-50001",
			Package: "lodash", Installed: "4.17.15", FixedIn: "4.17.21", CVSS: 7.4, Source: "osv"},
		{ID: "ssh-config:permit-root-login", Category: finding.CategoryConfig, Severity: finding.SeverityHigh, Check: "ssh-config:permit-root-login", Pack: "ssh",
			Title: "SSH allows root login with a password", Evidence: "/etc/ssh/sshd_config: PermitRootLogin yes (line 40)",
			Remediation: "Set 'PermitRootLogin prohibit-password' (or 'no') in /etc/ssh/sshd_config, then: systemctl reload sshd",
			References:  []string{"https://man.openbsd.org/sshd_config#PermitRootLogin"}},
		{ID: "web-exposure:dotgit:/var/www/html", Category: finding.CategoryConfig, Severity: finding.SeverityCritical, Pack: "web-exposure",
			Title: "Git repository exposed under the web root", Evidence: "/var/www/html/.git/config is readable and nginx serves /var/www/html (server 10.0.0.5:80); the repository history and any committed configuration are downloadable by anyone who can reach the site",
			Remediation: "Deny dot-files in the nginx server block: location ~ /\\.(?!well-known) { deny all; } and move the repository out of the web root"},
		{ID: "hardening:aslr", Category: finding.CategoryHardening, Severity: finding.SeverityMedium, Title: "Address space layout randomisation is reduced",
			Evidence: "kernel.randomize_va_space = 1", Remediation: "sysctl -w kernel.randomize_va_space=2 and persist it in /etc/sysctl.d/"},
		{ID: "accounts:inactive-default", Category: finding.CategoryConfig, Severity: finding.SeverityInfo, Title: "No default inactivity lock for new accounts",
			Evidence: "useradd -D: INACTIVE=-1"},
		{ID: "monitor:/etc/passwd", Category: "integrity", Severity: finding.SeverityUnknown, Title: "Critical file changed: /etc/passwd"},
	}
	r := BuildReport(facts, fs, ComputeImpact(facts, fs))
	r.Generated = when
	r.LyncVersion = "0.5.0"
	r.DataSources = &feed.ScanSources{Mode: feed.ModeLookup, CheckedAt: when.Add(-15 * time.Second), Ecosystem: "Rocky Linux:9",
		PackagesChecked: 612, Complete: false, UnfixedCVEs: 4,
		IncompleteReasons: []string{"nvd: 2 of 9 CVE lookups failed (severity enrichment incomplete)"},
		Sources: []feed.SourceStat{
			{Name: "osv", Kind: "lookup", Status: "ok", Requests: 7, Records: 342},
			{Name: "nvd", Kind: "lookup", Status: "partial", Requests: 9, CacheHits: 2, Records: 7, Detail: "2 requests failed: HTTP 503"},
			{Name: "dnf", Kind: "local", Status: "ok", Requests: 1, Records: 1},
		}}
	r.Inventory = &InventorySummary{Total: 3, Counts: map[string]int{"npm": 2, "PyPI": 1}, Queried: 3, Vulnerable: 1, Status: "ok", Warnings: 1,
		Stats:      inventory.Stats{Entries: 1840, FilesParsed: 12, Duration: 1234 * time.Millisecond},
		Components: []inventory.Component{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}}
	r.Coverage = []finding.PackCoverage{
		{Pack: "ssh", Checks: 12, Applicable: 12, Passed: 11, Failed: 1},
		{Pack: "web-exposure", Checks: 9, Applicable: 6, Passed: 5, Failed: 1, NotApplicable: 3},
		{Pack: "php", Checks: 8, Applicable: 7, Passed: 6, Skipped: 1, NotApplicable: 1,
			Skips: []finding.CheckSkip{{Check: "php:expose-php", Reason: "php -i timed out after 20s"}}},
		{Pack: "container", Checks: 2, Disabled: 2},
	}
	return r
}

func TestTextReportGolden(t *testing.T) {
	got := RenderText(fixtureReport())
	golden := filepath.Join("testdata", "report.golden.txt")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/reporter -run TestTextReportGolden -update)", err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("text report differs from %s (rerun with -update and review the diff)\n%s", golden, got)
	}
	for i, l := range strings.Split(got, "\n") {
		if n := utf8.RuneCountInString(l); n > textWidth {
			t.Errorf("line %d is %d columns: %q", i+1, n, l)
		}
		if strings.HasSuffix(l, " ") {
			t.Errorf("line %d has trailing space: %q", i+1, l)
		}
	}
	for _, want := range []string{
		"!! CVE SECTION INCOMPLETE: nvd: 2 of 9 CVE lookups failed",
		"dnf upgrade --refresh curl kernel openssl-libs php-fpm",
		"8.0.30-1.el9 -> 8.0.30-3.el9",
		"fixes 3 CVEs (2 critical, 1 high)",
		"[reboot]",
		"libxml2",
		"Git repository exposed under the web root",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text report lacks %q", want)
		}
	}
}

func TestWriteTextFromJSONAndOldReports(t *testing.T) {
	dir := t.TempDir()
	jp, tp := filepath.Join(dir, "r.json"), filepath.Join(dir, "sub", "r.txt")
	r := fixtureReport()
	if err := WriteReport(jp, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextFromJSON(jp, tp); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(tp)
	if err != nil || string(b) != RenderText(r) {
		t.Fatalf("round trip through JSON changed the text (%v)", err)
	}
	// A report from an older version (no sources, inventory, coverage
	// or findings) still renders.
	old := &Report{Host: "h", Generated: r.Generated}
	out := RenderText(old)
	for _, want := range []string{"not recorded", "No vulnerabilities or configuration problems", "Nothing to fix"} {
		if !strings.Contains(out, want) {
			t.Errorf("old report text lacks %q:\n%s", want, out)
		}
	}
	// Incomplete with no findings must not claim the host is clean.
	old.DataSources = &feed.ScanSources{Complete: false, IncompleteReasons: []string{"osv: failed"}}
	if out := RenderText(old); strings.Contains(out, "No vulnerabilities or configuration problems") || !strings.Contains(out, "INCOMPLETE") {
		t.Errorf("incomplete empty report:\n%s", out)
	}
}

func TestWrapText(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  []string
	}{
		{"the quick brown fox jumps", 10, []string{"the quick", "brown fox", "jumps"}},
		{"a\tb\x07c", 20, []string{"a bc"}},
		{"line one\nline two", 40, []string{"line one", "line two"}},
		{"https://example.com/a/very/long/path", 12, []string{"https://exam", "ple.com/a/ve", "ry/long/path"}},
		{"x https://example.com/abcdefgh y", 12, []string{"x", "https://exam", "ple.com/abcd", "efgh y"}},
		{"", 20, []string{""}},
		{"héllo wörld", 10, []string{"héllo", "wörld"}},
	}
	for _, c := range cases {
		got := wrapText(c.in, c.width)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrapText(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
	}
}

func TestUpdateCommand(t *testing.T) {
	pk := []string{"a", "b"}
	cases := []struct {
		os   collector.OSInfo
		want string
	}{
		{collector.OSInfo{ID: "rocky", VersionID: "9.4"}, "dnf upgrade --refresh a b"},
		{collector.OSInfo{ID: "centos", VersionID: "7"}, "yum update a b"},
		{collector.OSInfo{ID: "ol", IDLike: []string{"fedora"}, VersionID: "8.9"}, "dnf upgrade --refresh a b"},
		{collector.OSInfo{ID: "ubuntu", IDLike: []string{"debian"}}, "apt-get update && apt-get install --only-upgrade a b"},
		{collector.OSInfo{ID: "linuxmint", IDLike: []string{"ubuntu", "debian"}}, "apt-get update && apt-get install --only-upgrade a b"},
		{collector.OSInfo{ID: "alpine"}, "apk update && apk upgrade a b"},
		{collector.OSInfo{ID: "plan9"}, ""},
	}
	for _, c := range cases {
		if got := updateCommand(c.os, pk); got != c.want {
			t.Errorf("updateCommand(%+v) = %q, want %q", c.os, got, c.want)
		}
	}
}

func TestCommandWrapsWithContinuation(t *testing.T) {
	var pk []string
	for i := 0; i < 30; i++ {
		pk = append(pk, "package-number-"+string(rune('a'+i%26)))
	}
	d := &textDoc{}
	d.command("     ", updateCommand(collector.OSInfo{ID: "debian"}, pk))
	lines := strings.Split(strings.TrimSuffix(d.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a wrapped command, got %q", lines)
	}
	for i, l := range lines {
		if len(l) > textWidth {
			t.Errorf("line %d too long: %q", i, l)
		}
		if (i < len(lines)-1) != strings.HasSuffix(l, " \\") {
			t.Errorf("line %d continuation wrong: %q", i, l)
		}
	}
}
