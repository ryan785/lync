package applicability

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryan785/lync/internal/collector"
)

func TestParseFixNEVRA(t *testing.T) {
	cases := []struct {
		in, name, nevr string
		ok             bool
	}{
		{"openssl-1:3.5.1-7.el9_7", "openssl", "1:3.5.1-7.el9_7", true},
		{"kernel-0:5.14.0-611.54.1.el9_7", "kernel", "0:5.14.0-611.54.1.el9_7", true},
		{"python3.11-0:3.11.9-1.el9", "python3.11", "0:3.11.9-1.el9", true},
		{"curl-7.76.1-35.el9_7.3", "curl", "7.76.1-35.el9_7.3", true},
		{"nodash", "", "", false},
	}
	for _, c := range cases {
		name, nevr, ok := parseFixNEVRA(c.in)
		if name != c.name || nevr != c.nevr || ok != c.ok {
			t.Errorf("parseFixNEVRA(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, name, nevr, ok, c.name, c.nevr, c.ok)
		}
	}
}

func TestSourceRPMBaseName(t *testing.T) {
	cases := map[string]string{
		"curl-7.76.1-35.el9_7.3.src.rpm":                     "curl",
		"php-8.0.30-1.module+el8.10.0+1872+5d4a5b6c.src.rpm": "php",
		"not-an-srpm": "",
	}
	for in, want := range cases {
		if got := sourceRPMBaseName(in); got != want {
			t.Errorf("sourceRPMBaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPackageNamesMatch(t *testing.T) {
	cases := []struct {
		rh, pkg string
		want    bool
	}{
		{"openssh", "openssh-server", true},
		{"openssh-server", "openssh", true},
		{"openssl", "openssl", true},
		{"openssl", "openssl11", false},
		{"curl", "libcurl", false}, // handled by installedSourceMatches instead
	}
	for _, c := range cases {
		if got := packageNamesMatch(c.rh, c.pkg); got != c.want {
			t.Errorf("packageNamesMatch(%q, %q) = %v, want %v", c.rh, c.pkg, got, c.want)
		}
	}
}

func phpHostPackages() []collector.Package {
	src := "php-8.0.30-1.module+el8.10.0+1872+5d4a5b6c.src.rpm"
	rel := "1.module+el8.10.0+1872+5d4a5b6c"
	return []collector.Package{
		{Name: "php-fpm", Version: "8.0.30", Release: rel, Source: src, Manager: "rpm"},
		{Name: "php-cli", Version: "8.0.30", Release: rel, Source: src, Manager: "rpm"},
	}
}

func TestPackageStateAppliesModuleStreams(t *testing.T) {
	pkgs := phpHostPackages()
	cases := []struct {
		ps, pkg string
		want    bool
	}{
		{"php:8.0/php", "php-fpm", true},  // same stream, prefix match
		{"php:8.0/php", "php-cli", true},  // same stream
		{"php:8.2/php", "php-fpm", false}, // other stream
		{"php:7.4/php", "php-fpm", false}, // other stream
		{"nodejs:18/nodejs", "php-fpm", false},
		{"php", "php-fpm", true}, // plain (non-module) entry
	}
	for _, c := range cases {
		if got := packageStateApplies(c.ps, c.pkg, pkgs); got != c.want {
			t.Errorf("packageStateApplies(%q, %q) = %v, want %v", c.ps, c.pkg, got, c.want)
		}
	}
}

// writeDetail seeds the judge's on-disk cache so Evaluate runs offline.
func writeDetail(t *testing.T, dir, cve, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, cve+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRedHatJudgeEvaluate(t *testing.T) {
	dir := t.TempDir()
	j := NewRedHatJudge(dir)
	facts := &collector.Facts{
		OS: collector.OSInfo{ID: "rocky", VersionID: "8.10", IDLike: []string{"rhel"}},
		Packages: append(phpHostPackages(),
			collector.Package{Name: "libcurl", Version: "7.61.1", Release: "34.el8_10.2",
				Source: "curl-7.61.1-34.el8_10.2.src.rpm", Manager: "rpm"}),
	}

	writeDetail(t, dir, "CVE-2026-1001", `{"name":"CVE-2026-1001","package_state":[
		{"product_name":"Red Hat Enterprise Linux 8","package_name":"php:8.0/php","fix_state":"Not affected"}]}`)
	writeDetail(t, dir, "CVE-2026-1002", `{"name":"CVE-2026-1002","package_state":[
		{"product_name":"Red Hat Enterprise Linux 8","package_name":"php:8.2/php","fix_state":"Not affected"},
		{"product_name":"Red Hat Enterprise Linux 8","package_name":"php:8.0/php","fix_state":"Affected"}]}`)
	writeDetail(t, dir, "CVE-2026-1003", `{"name":"CVE-2026-1003","affected_release":[
		{"product_name":"Red Hat Enterprise Linux 8","package":"curl-0:7.61.1-34.el8_10.2","advisory":"RHSA-2026:1"}]}`)
	writeDetail(t, dir, "CVE-2026-1004", `{"name":"CVE-2026-1004","affected_release":[
		{"product_name":"Red Hat Enterprise Linux 8","package":"curl-0:7.61.1-34.el8_10.5","advisory":"RHSA-2026:2"}]}`)
	writeDetail(t, dir, "CVE-2026-1005", `{"name":"CVE-2026-1005","package_state":[
		{"product_name":"Red Hat Enterprise Linux 9","package_name":"php","fix_state":"Not affected"}]}`)

	cases := []struct {
		cve, pkg string
		want     Status
	}{
		{"CVE-2026-1001", "php-fpm", StatusNotAffected}, // module stream entry applies
		{"CVE-2026-1002", "php-fpm", StatusAffected},    // 8.2 entry ignored, 8.0 entry applies
		{"CVE-2026-1003", "libcurl", StatusNotAffected}, // fix on source "curl", installed == shipped
		{"CVE-2026-1004", "libcurl", StatusAffected},    // installed < shipped
		{"CVE-2026-1005", "php-fpm", StatusUnknown},     // RHEL 9 data, Rocky 8 host
	}
	for _, c := range cases {
		v, err := j.Evaluate(context.Background(), c.cve, c.pkg, facts)
		if err != nil {
			t.Fatalf("%s: %v", c.cve, err)
		}
		if v.Status != c.want {
			t.Errorf("%s/%s: status = %s (%s), want %s", c.cve, c.pkg, v.Status, v.Reason, c.want)
		}
	}
}
