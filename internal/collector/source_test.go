package collector

import (
	"strings"
	"testing"
)

func TestParseApkOrigins(t *testing.T) {
	db := strings.NewReader("C:Q1abc=\nP:libcrypto3\nV:3.1.4-r0\no:openssl\n\nP:musl\nV:1.2.4-r2\no:musl\n\nP:noorigin\nV:1-r0\n")
	got := parseApkOrigins(db)
	if got["libcrypto3"] != "openssl" || got["musl"] != "musl" || got["noorigin"] != "" {
		t.Errorf("origins = %v", got)
	}
}

func TestParseDpkgSourceVersion(t *testing.T) {
	fixture := strings.NewReader("libgcc-s1:amd64|12.2.0-14|amd64|gcc-12|installed|12.2.0-14\nlibfoo1|1.0-1+b1|amd64|foo|installed|1.0-1\n")
	pkgs, err := parseDpkgQueryOutput(fixture)
	if err != nil || len(pkgs) != 2 {
		t.Fatalf("got %v, %v", pkgs, err)
	}
	if pkgs[0].SourceVersion != "" {
		t.Errorf("same version should leave SourceVersion empty, got %q", pkgs[0].SourceVersion)
	}
	if pkgs[1].SourceVersion != "1.0-1" || pkgs[1].SourceName() != "foo" {
		t.Errorf("binNMU: got %+v", pkgs[1])
	}
}
