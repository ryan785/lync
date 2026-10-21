package collector

import "testing"

func TestSourceName(t *testing.T) {
	cases := []struct {
		pkg  Package
		want string
	}{
		{Package{Manager: "rpm", Source: "php-8.0.30-1.module+el8.10.0+1872+5d4a5b6c.src.rpm"}, "php"},
		{Package{Manager: "rpm", Source: "curl-7.76.1-35.el9_7.3.src.rpm"}, "curl"},
		{Package{Manager: "rpm", Source: "python3.11-3.11.9-1.el9.src.rpm"}, "python3.11"},
		{Package{Manager: "rpm", Source: "compat-openssl11-1.1.1k-4.el9.src.rpm"}, "compat-openssl11"},
		{Package{Manager: "rpm", Source: "(none)"}, ""},
		{Package{Manager: "rpm", Source: ""}, ""},
		{Package{Manager: "dpkg", Source: "glibc"}, "glibc"},
		{Package{Manager: "dpkg", Source: "openssl (3.0.15-1)"}, "openssl"},
	}
	for _, c := range cases {
		if got := c.pkg.SourceName(); got != c.want {
			t.Errorf("SourceName(%q) = %q, want %q", c.pkg.Source, got, c.want)
		}
	}
}
