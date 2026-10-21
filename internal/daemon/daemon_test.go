package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
)

func TestPruneReports(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	files := map[string]time.Duration{
		"lync-old.json":  -40 * 24 * time.Hour,
		"lync-old.pdf":   -40 * 24 * time.Hour,
		"lync-new.json":  -1 * time.Hour,
		"unrelated.json": -400 * 24 * time.Hour, // not ours: never touched
		"lync-notes.txt": -400 * 24 * time.Hour, // wrong extension
	}
	for name, age := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(age), now.Add(age)); err != nil {
			t.Fatal(err)
		}
	}

	if n, err := pruneReports(dir, 0, now); n != 0 || err != nil {
		t.Fatalf("retention 0 must keep everything, removed %d (%v)", n, err)
	}
	n, err := pruneReports(dir, 30, now)
	if err != nil || n != 2 {
		t.Fatalf("pruneReports removed %d (%v), want 2", n, err)
	}
	for _, keep := range []string{"lync-new.json", "unrelated.json", "lync-notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s should survive: %v", keep, err)
		}
	}
	if n, err := pruneReports(filepath.Join(dir, "missing"), 30, now); n != 0 || err != nil {
		t.Errorf("missing dir: got %d, %v", n, err)
	}
}

func cveHost() *collector.Facts {
	src := "php-8.0.30-1.module+el8.10.0+1872+5d4a5b6c.src.rpm"
	rel := "1.module+el8.10.0+1872+5d4a5b6c"
	return &collector.Facts{
		Hostname: "web1",
		OS:       collector.OSInfo{ID: "rocky", VersionID: "8.10", IDLike: []string{"rhel"}},
		Packages: []collector.Package{
			{Name: "php-fpm", Version: "8.0.30", Release: rel, Source: src, Manager: "rpm"},
			{Name: "php-common", Version: "8.0.30", Release: rel, Source: src, Manager: "rpm"},
		},
	}
}

func TestEvaluateCVEVerdicts(t *testing.T) {
	ctx := context.Background()
	const id = "CVE-2026-109618"

	// No feed knows the CVE: must say unknown, never "not affected".
	if r := evaluateCVE(ctx, nil, cveHost(), id, nil); r.Verdict != VerdictUnknownToFeeds {
		t.Errorf("no data: verdict = %s, want %s", r.Verdict, VerdictUnknownToFeeds)
	}

	// Feed names the package but has no fix yet.
	noFix := []feed.Vulnerability{{ID: id, Source: "osv",
		Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "php"}}}}
	if r := evaluateCVE(ctx, nil, cveHost(), id, noFix); r.Verdict != VerdictNoFixYet {
		t.Errorf("no fix: verdict = %s (%s), want %s", r.Verdict, r.Reason, VerdictNoFixYet)
	}

	// Fix published, host older.
	fixed := []feed.Vulnerability{{ID: id, Source: "osv",
		Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "php-fpm",
			FixedVersion: "8.0.30-2.module+el8.10.0+2000+aaaa"}}}}
	r := evaluateCVE(ctx, nil, cveHost(), id, fixed)
	if r.Verdict != VerdictAffected || len(r.Findings) != 1 {
		t.Errorf("fix newer: verdict = %s, findings = %d", r.Verdict, len(r.Findings))
	}

	// Fix published, host already has it.
	fixed[0].Affects[0].FixedVersion = "8.0.30-1.module+el8.10.0+1872+5d4a5b6c"
	if r := evaluateCVE(ctx, nil, cveHost(), id, fixed); r.Verdict != VerdictNotAffected {
		t.Errorf("patched: verdict = %s, want %s", r.Verdict, VerdictNotAffected)
	}

	// Feed knows the CVE only for a package that isn't installed.
	other := []feed.Vulnerability{{ID: id, Source: "osv",
		Affects: []feed.AffectedPackage{{Distro: "rhel:8", Name: "nginx", FixedVersion: "1:1.24.0-1.el8"}}}}
	r = evaluateCVE(ctx, nil, cveHost(), id, other)
	if r.Verdict != VerdictNotAffected || len(r.Installed) != 0 {
		t.Errorf("not installed: verdict = %s, installed = %v", r.Verdict, r.Installed)
	}
}

func TestRulesOptionsFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Rules.Disable = []string{"docker"}
	cfg.Rules.Enable = []string{"container:php-upload-progress"}
	cfg.Rules.Root = "/mnt/image"
	o := RulesOptions(cfg)
	if o.Toggles.CheckEnabled("docker:group-members") || !o.Toggles.CheckEnabled("container:php-upload-progress:x") {
		t.Errorf("toggles not mapped: %+v", o.Toggles)
	}
	if o.Host == nil || o.Host.Root != "/mnt/image" {
		t.Errorf("root not mapped: %+v", o.Host)
	}
}
