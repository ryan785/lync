package feed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitRedHatNEVRA(t *testing.T) {
	cases := []struct {
		in, name, fix, distro string
	}{
		{"openssl-1:3.0.7-25.el9_2", "openssl", "1:3.0.7-25.el9_2", "rhel:9"},
		{"kernel-0:4.18.0-553.22.1.el8_10", "kernel", "0:4.18.0-553.22.1.el8_10", "rhel:8"},
		{"curl-7.61.1-34.el8", "curl", "7.61.1-34.el8", "rhel:8"},
	}
	for _, c := range cases {
		name, fix, distro := splitRedHatNEVRA(c.in)
		if name != c.name || fix != c.fix || distro != c.distro {
			t.Errorf("splitRedHatNEVRA(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.in, name, fix, distro, c.name, c.fix, c.distro)
		}
	}
}

func TestConvertRedHatSkipsModuleNSVC(t *testing.T) {
	v := convertRedHat(rhCVE{
		CVE:      "CVE-2026-2001",
		Severity: "important",
		AffectedPackages: []string{
			"php:8.0-8100020240327101215.489197e6",
			"openssl-1:1.1.1k-14.el8_10",
		},
		Advisories: []string{"RHSA-2026:1234"},
	})
	if v.Severity != "Important" {
		t.Errorf("severity = %q, want Important", v.Severity)
	}
	if len(v.Affects) != 1 || v.Affects[0].Name != "openssl" {
		t.Fatalf("want only the openssl RPM entry, got %+v", v.Affects)
	}
	if v.Affects[0].Distro != "rhel:8" {
		t.Errorf("distro = %q, want rhel:8", v.Affects[0].Distro)
	}
}

func TestConvertOSVPrefersCVEAlias(t *testing.T) {
	rec := &osvRecord{
		ID:      "RLSA-2026:1234",
		Aliases: []string{"CVE-2026-2002"},
		Affected: []osvAffected{{
			Package: osvPackage{Ecosystem: "Rocky Linux:8", Name: "php-fpm"},
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{
				{Introduced: "0"}, {Fixed: "8.0.30-2.module+el8.10.0+2000+aaaa"},
			}}},
		}},
	}
	v, ok := convertOSV(rec, "Rocky Linux:8")
	if !ok {
		t.Fatal("convertOSV rejected a record with a CVE alias")
	}
	if v.ID != "CVE-2026-2002" {
		t.Errorf("id = %q, want CVE alias", v.ID)
	}
	if len(v.Affects) != 1 || v.Affects[0].Distro != "rhel:8" ||
		v.Affects[0].FixedVersion != "8.0.30-2.module+el8.10.0+2000+aaaa" {
		t.Errorf("affects = %+v", v.Affects)
	}

	// No CVE anywhere -> skipped (matcher dedupes on CVE id).
	if _, ok := convertOSV(&osvRecord{ID: "RLSA-2026:9"}, "Rocky Linux:8"); ok {
		t.Error("record without a CVE id should be skipped")
	}
}

func TestOSVEcosystemMapping(t *testing.T) {
	cases := map[string]string{
		"Rocky Linux:9": "rhel:9",
		"AlmaLinux:8":   "rhel:8",
		"Debian:12":     "debian:12",
		"Ubuntu:22.04":  "ubuntu:22.04",
		"Alpine:v3.19":  "alpine:3.19",
	}
	for in, want := range cases {
		if got := osvEcosystemToDistroFilter(in); got != want {
			t.Errorf("osvEcosystemToDistroFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOSVEcosystemsForHost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte("ID=\"rocky\"\nVERSION_ID=\"8.10\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := osvEcosystemsForHost(p)
	if len(got) != 1 || got[0] != "Rocky Linux:8" {
		t.Errorf("osvEcosystemsForHost = %v, want [Rocky Linux:8]", got)
	}
}

func TestNVDHelpers(t *testing.T) {
	if got := parseCPEProduct("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"); got != "php" {
		t.Errorf("parseCPEProduct = %q, want php", got)
	}
	r := buildVersionRange(nvdCPEMatch{VersionStartIncluding: "8.1.0", VersionEndExcluding: "8.1.34"})
	if r != ">=8.1.0,<8.1.34" {
		t.Errorf("buildVersionRange = %q", r)
	}
	if r := buildVersionRange(nvdCPEMatch{VersionEndIncluding: "8.0.30"}); r != "<=8.0.30" {
		t.Errorf("buildVersionRange = %q", r)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := []Vulnerability{{ID: "CVE-2026-2003", Source: "osv"}}
	if err := s.PutVulns("osv", in); err != nil {
		t.Fatal(err)
	}
	out, err := s.GetVulns("osv")
	if err != nil || len(out) != 1 || out[0].ID != "CVE-2026-2003" {
		t.Fatalf("GetVulns = %+v, %v", out, err)
	}
	m, err := s.GetManifest("osv")
	if err != nil || m == nil || m.EntryCount != 1 {
		t.Fatalf("GetManifest = %+v, %v", m, err)
	}
	if missing, err := s.GetVulns("nope"); err != nil || missing != nil {
		t.Errorf("missing source should be (nil, nil), got %v, %v", missing, err)
	}
}

func TestAutoSourceNames(t *testing.T) {
	cases := []struct {
		id   string
		like []string
		want string
	}{
		{"rocky", []string{"rhel", "centos", "fedora"}, "redhat,osv,nvd"},
		{"ubuntu", []string{"debian"}, "ubuntu,osv,nvd"},
		{"debian", nil, "debian,osv,nvd"},
		{"alpine", nil, "alpine,osv,nvd"},
		{"linuxmint", []string{"ubuntu", "debian"}, "ubuntu,osv,nvd"},
		{"arch", nil, "osv,nvd"},
	}
	for _, c := range cases {
		got := strings.Join(AutoSourceNames(c.id, c.like), ",")
		if got != c.want {
			t.Errorf("AutoSourceNames(%s, %v) = %s, want %s", c.id, c.like, got, c.want)
		}
	}
}
