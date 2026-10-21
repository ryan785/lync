package collector

import (
	"strings"
	"testing"
)

func TestSplitApkPackage(t *testing.T) {
	cases := []struct {
		in            string
		name, version string
		ok            bool
	}{
		{"openssl-3.1.4-r0", "openssl", "3.1.4-r0", true},
		{"musl-1.2.4-r2", "musl", "1.2.4-r2", true},
		{"py3-cryptography-41.0.7-r0", "py3-cryptography", "41.0.7-r0", true},
		{"alpine-keys-2.4-r1", "alpine-keys", "2.4-r1", true},
		{"no-rel-suffix", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		gotName, gotVer, gotOK := splitApkPackage(c.in)
		if gotOK != c.ok || gotName != c.name || gotVer != c.version {
			t.Errorf("splitApkPackage(%q) = (%q, %q, %t); want (%q, %q, %t)",
				c.in, gotName, gotVer, gotOK, c.name, c.version, c.ok)
		}
	}
}

func TestParseApkInfoOutput(t *testing.T) {
	fixture := strings.NewReader(`musl-1.2.4-r2
busybox-1.36.1-r5
openssl-3.1.4-r0
`)
	pkgs, err := parseApkInfoOutput(fixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "musl" || pkgs[0].Version != "1.2.4-r2" || pkgs[0].Manager != "apk" {
		t.Errorf("got %+v", pkgs[0])
	}
}
