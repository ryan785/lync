package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValidAndEnablesOSV(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	found := false
	for _, s := range cfg.Feed.Sources {
		if s.Name == "osv" && s.Enabled {
			found = true
		}
	}
	if !found {
		t.Error("osv should be enabled by default (full advisory history for Rocky/Alma/Debian/Ubuntu/Alpine)")
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil || cfg == nil || cfg.IPC.Socket != "/run/lync.sock" {
		t.Fatalf("Load(missing) = %+v, %v", cfg, err)
	}
}

func TestLoadRejectsZeroInterval(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lync.yaml")
	if err := os.WriteFile(p, []byte("scan:\n  interval: 0s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "scan.interval") {
		t.Fatalf("want scan.interval error, got %v", err)
	}
}

func TestShippedConfigParses(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "packaging", "config", "lync.yaml"))
	if err != nil {
		t.Fatalf("packaging/config/lync.yaml: %v", err)
	}
	names := map[string]bool{}
	for _, s := range cfg.Feed.Sources {
		if s.Enabled {
			names[s.Name] = true
		}
	}
	for _, want := range []string{"redhat", "osv", "nvd"} {
		if !names[want] {
			t.Errorf("shipped config should enable %s", want)
		}
	}
}

func TestRulesToggleKeysParse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lync.yaml")
	body := `rules:
  disable: [cockpit:enabled, docker]
  enable: [container:php-upload-progress]
  image_max_age_days: 90
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules.Disable) != 2 || cfg.Rules.Enable[0] != "container:php-upload-progress" || cfg.Rules.ImageMaxAgeDays != 90 {
		t.Errorf("rules = %+v", cfg.Rules)
	}
}
