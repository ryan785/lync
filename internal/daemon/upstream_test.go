package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/upstream"
)

func TestNodeSourceEnabled(t *testing.T) {
	src := func(pairs ...any) []config.FeedSourceCfg {
		var out []config.FeedSourceCfg
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, config.FeedSourceCfg{Name: pairs[i].(string), Enabled: pairs[i+1].(bool)})
		}
		return out
	}
	for _, c := range []struct {
		name string
		srcs []config.FeedSourceCfg
		want bool
	}{
		{"default config", config.Default().Feed.Sources, true},
		{"-sources none", nil, false},
		{"osv off, no nodejs entry", src("redhat", true, "nvd", true), false},
		{"explicitly disabled", src("osv", true, "nodejs", false), false},
		{"explicitly enabled alone", src("nodejs", true), true},
	} {
		cfg := config.Default()
		cfg.Feed.Sources = c.srcs
		if got := nodeSourceEnabled(cfg); got != c.want {
			t.Errorf("%s: nodeSourceEnabled = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDistroFactsDropsNodeSource(t *testing.T) {
	facts := &collector.Facts{Packages: []collector.Package{
		{Name: "nodejs", Version: "22.22.0-1nodesource1", Manager: "dpkg"},
		{Name: "bash", Version: "5.2.15-2+b7", Manager: "dpkg"},
	}}
	d := &Daemon{cfg: config.Default()}
	if got := d.distroFacts(facts); len(got.Packages) != 1 || got.Packages[0].Name != "bash" {
		t.Errorf("distroFacts = %+v", got.Packages)
	}
	// Upstream Node matching off: the package stays with the distro data.
	d.cfg.Rules.Disable = []string{"upstream", "runtime:eol-node"}
	if got := d.distroFacts(facts); got != facts {
		t.Error("NodeSource package dropped although upstream Node matching is off")
	}
}

func TestUpstreamFindingsSourceStatus(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	d := &Daemon{cfg: config.Default(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	newPass := func(installs []upstream.Install) *upstreamPass {
		n := upstream.NewNode(t.TempDir())
		n.IndexURL, n.VulnURL, n.ScheduleURL = down.URL+"/i", down.URL+"/v", down.URL+"/s"
		return &upstreamPass{node: n, installs: installs}
	}
	ctx := context.Background()

	// No Node at all: nothing fetched, skipped, CVE data still complete.
	src := &feed.ScanSources{Complete: true}
	if fs := d.upstreamFindings(ctx, newPass(nil), nil, nil, src); len(fs) != 0 || !src.Complete ||
		len(src.Sources) != 1 || src.Sources[0].Status != feed.StatusSkipped {
		t.Errorf("no node: findings=%d sources=%+v", len(fs), src)
	}

	// An upstream install and the data unreachable: the report says the
	// CVE section is incomplete.
	src = &feed.ScanSources{Complete: true}
	in := []upstream.Install{{Runtime: "node", Path: "/opt/node/bin/node", Version: "22.22.0", Via: "tarball"}}
	fs := d.upstreamFindings(ctx, newPass(in), nil, nil, src)
	if len(fs) != 0 || src.Complete || len(src.Sources) != 1 || src.Sources[0].Name != "nodejs" ||
		src.Sources[0].Status != feed.StatusFailed || len(src.FailedSources()) != 1 {
		t.Errorf("offline: findings=%d sources=%+v", len(fs), src)
	}
}
