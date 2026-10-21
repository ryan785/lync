package matcher

import (
	"strings"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

var rocky8 = collector.OSInfo{ID: "rocky", VersionID: "8.10", IDLike: []string{"rhel", "centos", "fedora"}}

// phpFPMHost is a Rocky 8 host running the php:8.0 appstream module behind
// nginx: only subpackages are installed, never a binary named "php".
func phpFPMHost() *collector.Facts {
	src := "php-8.0.30-1.module+el8.10.0+1872+5d4a5b6c.src.rpm"
	rel := "1.module+el8.10.0+1872+5d4a5b6c"
	return &collector.Facts{
		OS: rocky8,
		Packages: []collector.Package{
			{Name: "php-fpm", Version: "8.0.30", Release: rel, Arch: "x86_64", Source: src, Manager: "rpm"},
			{Name: "php-common", Version: "8.0.30", Release: rel, Arch: "x86_64", Source: src, Manager: "rpm"},
			{Name: "php-cli", Version: "8.0.30", Release: rel, Arch: "x86_64", Source: src, Manager: "rpm"},
			{Name: "openssl", Epoch: 1, Version: "1.1.1k", Release: "12.el8_9", Arch: "x86_64",
				Source: "openssl-1.1.1k-12.el8_9.src.rpm", Manager: "rpm"},
		},
	}
}

func findingsFor(fs []finding.Finding, cve string) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.CVE == cve {
			out = append(out, f)
		}
	}
	return out
}

func TestNVDCPEProductMatchesViaSourcePackage(t *testing.T) {
	// NVD names the CPE product "php"; the host has php-fpm/php-cli/php-common.
	vulns := []feed.Vulnerability{{
		ID: "CVE-2026-0001", Source: "nvd", CVSS: 9.8,
		Affects: []feed.AffectedPackage{{Distro: "*", Name: "php", VersionRange: "<8.1.40"}},
	}}
	got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0001")
	if len(got) != 1 {
		t.Fatalf("want exactly one finding for the php source group, got %d: %+v", len(got), got)
	}
	if got[0].Package != "php-cli" {
		t.Errorf("representative package = %q, want php-cli (alphabetically first)", got[0].Package)
	}
	if !strings.Contains(got[0].Evidence, `source package "php"`) {
		t.Errorf("evidence should explain the source-package match: %q", got[0].Evidence)
	}
	if got[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %s, want Critical from CVSS 9.8", got[0].Severity)
	}
}

func TestExactBinaryNameStillPreferred(t *testing.T) {
	vulns := []feed.Vulnerability{{
		ID: "CVE-2026-0002", Source: "osv",
		Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "php-fpm",
			FixedVersion: "8.0.30-2.module+el8.10.0+2000+aaaa"}},
	}}
	got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0002")
	if len(got) != 1 || got[0].Package != "php-fpm" {
		t.Fatalf("want one finding on php-fpm, got %+v", got)
	}
	if strings.Contains(got[0].Evidence, "source package") {
		t.Errorf("exact binary match should not claim a source match: %q", got[0].Evidence)
	}
}

func TestModuleStreamSelection(t *testing.T) {
	// One CVE, one advisory per module stream. The host is on php:8.0 and
	// already has the 8.0 stream's fix; the 8.2 stream fix must not make it
	// look vulnerable.
	host := phpFPMHost()
	vulns := []feed.Vulnerability{{
		ID: "CVE-2026-0003", Source: "osv",
		Affects: []feed.AffectedPackage{
			{Distro: "rhel:8", Name: "php-fpm", FixedVersion: "8.2.13-1.module+el8.10.0+1700+bbbb"},
			{Distro: "rhel:8", Name: "php-fpm", FixedVersion: "8.0.30-1.module+el8.10.0+1872+5d4a5b6c"},
			{Distro: "rhel:8", Name: "php-fpm", FixedVersion: "7.4.33-1.module+el8.9.0+1500+cccc"},
		},
	}}
	if got := findingsFor(Match(host, vulns, nil), "CVE-2026-0003"); len(got) != 0 {
		t.Fatalf("host has the 8.0-stream fix; want no finding, got %+v", got)
	}

	// Same CVE but the 8.0 stream fix is newer than what's installed.
	vulns[0].Affects[1].FixedVersion = "8.0.30-3.module+el8.10.0+2100+dddd"
	got := findingsFor(Match(host, vulns, nil), "CVE-2026-0003")
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if got[0].FixedIn != "8.0.30-3.module+el8.10.0+2100+dddd" {
		t.Errorf("FixedIn = %q, want the 8.0-stream fix", got[0].FixedIn)
	}
}

func TestModuleStreamNoSameStreamFix(t *testing.T) {
	// Only the 8.2 stream got a fix: the 8.0 host is flagged and told to
	// switch streams rather than "update php-fpm to 8.2".
	vulns := []feed.Vulnerability{{
		ID: "CVE-2026-0004", Source: "osv",
		Affects: []feed.AffectedPackage{
			{Distro: "rhel:8", Name: "php-fpm", FixedVersion: "8.2.13-1.module+el8.10.0+1700+bbbb"},
		},
	}}
	got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0004")
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if !strings.Contains(got[0].Remediation, "switch module stream") {
		t.Errorf("remediation should recommend a stream switch: %q", got[0].Remediation)
	}
}

func TestDistroPatchedSuppressesNVD(t *testing.T) {
	// NVD (upstream ranges) says 8.0.30 is vulnerable; Rocky's advisory says
	// the backported fix in 8.0.30-1.module... is installed. Distro wins.
	vulns := []feed.Vulnerability{
		{ID: "CVE-2026-0005", Source: "nvd", CVSS: 9.8,
			Affects: []feed.AffectedPackage{{Distro: "*", Name: "php", VersionRange: "<8.1.40"}}},
		{ID: "CVE-2026-0005", Source: "osv",
			Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "php",
				FixedVersion: "8.0.30-1.module+el8.10.0+1872+5d4a5b6c"}}},
	}
	if got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0005"); len(got) != 0 {
		t.Fatalf("distro says patched; NVD finding should be dropped, got %+v", got)
	}

	// Distro source for a *different* major version must not suppress.
	vulns[1].Affects[0].Distro = "rhel:9"
	if got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0005"); len(got) != 1 {
		t.Fatalf("rhel:9 data does not apply to Rocky 8; want NVD finding kept, got %+v", got)
	}
}

func TestDistroVulnerableBeatsNVD(t *testing.T) {
	vulns := []feed.Vulnerability{
		{ID: "CVE-2026-0006", Source: "nvd",
			Affects: []feed.AffectedPackage{{Distro: "*", Name: "openssl", VersionRange: "<3.0.0"}}},
		{ID: "CVE-2026-0006", Source: "redhat", Severity: "important",
			Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "openssl", FixedVersion: "1:1.1.1k-14.el8_10"}}},
	}
	got := findingsFor(Match(phpFPMHost(), vulns, nil), "CVE-2026-0006")
	if len(got) != 1 || got[0].Source != "redhat" {
		t.Fatalf("want a single redhat-sourced finding, got %+v", got)
	}
	if got[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %s, want High (Red Hat 'important')", got[0].Severity)
	}
}

func TestDistroMatchesWholeComponents(t *testing.T) {
	cases := []struct {
		filter, versionID string
		want              bool
	}{
		{"rhel:8", "8.10", true},
		{"rhel:8", "8", true},
		{"rhel:1", "10.0", false},
		{"rhel:9", "8.10", false},
		{"rhel", "9.4", true},
		{"*", "anything", true},
		{"ubuntu:22.04", "22.04", true},
		{"alpine:3.18", "3.18.4", true},
		{"alpine:3.1", "3.18.4", false},
	}
	for _, c := range cases {
		osi := rocky8
		osi.VersionID = c.versionID
		if strings.HasPrefix(c.filter, "ubuntu") {
			osi = collector.OSInfo{ID: "ubuntu", VersionID: c.versionID}
		}
		if strings.HasPrefix(c.filter, "alpine") {
			osi = collector.OSInfo{ID: "alpine", VersionID: c.versionID}
		}
		if got := distroMatches(c.filter, osi); got != c.want {
			t.Errorf("distroMatches(%q, %q) = %v, want %v", c.filter, c.versionID, got, c.want)
		}
	}
}

func TestMultipleKernelsUseHighest(t *testing.T) {
	facts := &collector.Facts{OS: rocky8, Packages: []collector.Package{
		{Name: "kernel", Version: "4.18.0", Release: "513.5.1.el8_9", Manager: "rpm"},
		{Name: "kernel", Version: "4.18.0", Release: "553.22.1.el8_10", Manager: "rpm"},
	}}
	vulns := []feed.Vulnerability{{ID: "CVE-2026-0007", Source: "redhat",
		Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "kernel", FixedVersion: "0:4.18.0-553.16.1.el8_10"}}}}
	if got := Match(facts, vulns, nil); len(got) != 0 {
		t.Fatalf("newest installed kernel is patched; want no finding, got %+v", got)
	}
}

func TestMatchVersionRange(t *testing.T) {
	cases := []struct {
		v, rng string
		want   bool
	}{
		{"8.0.30", "<8.1.40", true},
		{"8.0.30", ">=8.0.0,<8.0.31", true},
		{"8.0.31", ">=8.0.0,<8.0.31", false},
		{"8.0.30", "<=8.0.30", true},
		{"8.0.30", ">8.0.30", false},
		{"8.0.30", "garbage", false},
	}
	for _, c := range cases {
		if got := matchVersionRange(c.v, c.rng); got != c.want {
			t.Errorf("matchVersionRange(%q, %q) = %v, want %v", c.v, c.rng, got, c.want)
		}
	}
}
