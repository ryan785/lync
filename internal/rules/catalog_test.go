package rules

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func TestCatalogComplete(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("empty catalog")
	}
	for _, c := range cat {
		if c.ID == "" || c.Rule == "" || c.Description == "" || c.Severity == "" {
			t.Errorf("incomplete catalog entry %+v", c)
		}
	}
	names := map[string]bool{}
	for _, r := range DefaultRules() {
		names[r.Name()] = true
	}
	for _, c := range cat {
		if !names[c.Rule] {
			t.Errorf("check %s names unknown rule %q", c.ID, c.Rule)
		}
	}
}

func TestToggles(t *testing.T) {
	register(CheckInfo{ID: "test:optin", Rule: "fake", Severity: finding.SeverityLow, Description: "x", DefaultOff: true})
	defer func() {
		catalogMu.Lock()
		delete(catalog, "test:optin")
		catalogMu.Unlock()
	}()
	cases := []struct {
		name string
		tg   Toggles
		id   string
		want bool
	}{
		{"default on", Toggles{}, "php:upload-progress:system:www", true},
		{"default off", Toggles{}, "test:optin:poste", false},
		{"enable default-off", Toggles{Enable: []string{"test:optin"}}, "test:optin:poste", true},
		{"disable exact", Toggles{Disable: []string{"php:expose-php"}}, "php:expose-php:system", false},
		{"disable prefix", Toggles{Disable: []string{"docker"}}, "docker:group-members", false},
		{"disable prefix with colon", Toggles{Disable: []string{"web:"}}, "web:phpinfo:/x", false},
		{"prefix is not substring", Toggles{Disable: []string{"web:php"}}, "web:phpinfo:/x", true},
		{"enable beats disable", Toggles{Disable: []string{"php"}, Enable: []string{"php:upload-progress"}}, "php:upload-progress:x", true},
		{"legacy finding", Toggles{Disable: []string{"ssh:x11-forwarding"}}, "ssh:x11-forwarding", false},
	}
	for _, c := range cases {
		if got := c.tg.CheckEnabled(c.id); got != c.want {
			t.Errorf("%s: CheckEnabled(%q) = %v, want %v", c.name, c.id, got, c.want)
		}
	}
	if (Toggles{Disable: []string{"ssh-config"}}).RuleEnabled("ssh-config") {
		t.Error("rule name in disable should switch the rule off")
	}
}

type fakeRule struct{ ids []string }

func (f fakeRule) Name() string { return "fake" }
func (f fakeRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var out []finding.Finding
	for _, id := range f.ids {
		out = append(out, finding.Finding{ID: id})
	}
	return out
}

func TestEngineAppliesToggles(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	e := NewEngineWithOptions(log, Options{Level: LevelMedium, Toggles: Toggles{Disable: []string{"nginx:no-hsts", "fake-off"}}},
		fakeRule{ids: []string{"nginx:no-hsts", "nginx:server-tokens"}})
	got := e.Run(context.Background(), &collector.Facts{})
	if len(got) != 1 || got[0].ID != "nginx:server-tokens" {
		t.Errorf("engine toggles: got %v", ids(got))
	}
	e = NewEngineWithOptions(log, Options{Toggles: Toggles{Disable: []string{"fake"}}}, fakeRule{ids: []string{"x"}})
	if got := e.Run(context.Background(), &collector.Facts{}); len(got) != 0 {
		t.Errorf("disabled rule ran: %v", ids(got))
	}
}
