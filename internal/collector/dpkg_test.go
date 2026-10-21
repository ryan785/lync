package collector

import (
	"strings"
	"testing"
)

func TestParseDpkgQueryOutput(t *testing.T) {
	fixture := strings.NewReader(`base-files|12.4+deb12u11|amd64|base-files|installed
openssl|3.0.15-1~deb12u1|amd64|openssl|installed
half-removed|1.0|all||config-files
libc6|2.36-9+deb12u10|amd64|glibc|installed
`)
	pkgs, err := parseDpkgQueryOutput(fixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 installed packages, got %d", len(pkgs))
	}
	expected := []struct{ name, version string }{
		{"base-files", "12.4+deb12u11"},
		{"openssl", "3.0.15-1~deb12u1"},
		{"libc6", "2.36-9+deb12u10"},
	}
	for i, e := range expected {
		if pkgs[i].Name != e.name {
			t.Errorf("[%d] name = %q, want %q", i, pkgs[i].Name, e.name)
		}
		if pkgs[i].Version != e.version {
			t.Errorf("[%d] version = %q, want %q", i, pkgs[i].Version, e.version)
		}
		if pkgs[i].Manager != "dpkg" {
			t.Errorf("[%d] manager = %q, want dpkg", i, pkgs[i].Manager)
		}
	}
}
