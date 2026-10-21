package rules

import (
	"os"
	"strings"
	"testing"
)

// TestChecksDocCurrent keeps docs/CHECKS.md in sync with the catalog.
// Regenerate with: go generate ./internal/checks
func TestChecksDocCurrent(t *testing.T) {
	want := ChecksMarkdown()
	got, err := os.ReadFile("../../docs/CHECKS.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Error("docs/CHECKS.md is out of date: run `go generate ./internal/checks`")
	}
}

func TestExplainAndFilter(t *testing.T) {
	s, ok := Explain("ssh:permit-root-login")
	if !ok || !strings.Contains(s, "permitrootlogin") || !strings.Contains(s, "Remediation") {
		t.Errorf("explain ssh:permit-root-login: %q", s)
	}
	if _, ok := Explain("ssh:permit-root-login:extra"); !ok {
		t.Error("explain should accept a finding ID")
	}
	if _, ok := Explain("nope:nothing"); ok {
		t.Error("unknown id explained")
	}
	if s, ok := Explain("cron:writable-script"); !ok || !strings.Contains(s, "Go rule") {
		t.Errorf("explain go check: %q", s)
	}
	for _, c := range FilterCatalog(CatalogFilter{Pack: "ssh", Severity: "high"}) {
		if c.PackName() != "ssh" || c.Severity.Rank() < 4 {
			t.Errorf("filter leaked %s", c.ID)
		}
	}
	if len(FilterCatalog(CatalogFilter{Tag: "cis"})) == 0 {
		t.Error("no cis-tagged checks")
	}
}

func TestPackToggles(t *testing.T) {
	cases := []struct {
		tg   Toggles
		id   string
		want bool
	}{
		{Toggles{Disable: []string{"pack:ssh"}}, "ssh:password-auth", false},
		{Toggles{Disable: []string{"ssh-config"}}, "ssh:password-auth", false}, // legacy rule name
		{Toggles{Disable: []string{"tag:cis"}}, "ssh:max-auth-tries", false},
		{Toggles{Disable: []string{"tag:cis"}}, "ssh:gateway-ports", true},
		{Toggles{Disable: []string{"pack:ssh"}, Enable: []string{"ssh:password-auth"}}, "ssh:password-auth", true},
		{Toggles{Disable: []string{"hardening"}}, "hardening:kernel.sysrq", false},
	}
	for _, c := range cases {
		if got := c.tg.CheckEnabled(c.id); got != c.want {
			t.Errorf("%+v CheckEnabled(%s) = %v, want %v", c.tg, c.id, got, c.want)
		}
	}
}
