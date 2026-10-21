package daemon

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/reporter"
	"github.com/ryan785/lync/internal/rules"
	"github.com/ryan785/lync/internal/upstream"
)

// nodeSourceEnabled: the "nodejs" entry in feed.sources decides; without
// one, it follows "osv" (both are upstream advisory data), so existing
// configs get it and `-sources none` turns it off.
func nodeSourceEnabled(cfg *config.Config) bool {
	for _, s := range cfg.Feed.Sources {
		if s.Name == upstream.NodeSourceName {
			return s.Enabled
		}
	}
	for _, s := range cfg.Feed.Sources {
		if s.Name == "osv" && s.Enabled {
			return true
		}
	}
	return false
}

// upstreamNodeOn reports whether upstream Node.js matching runs this scan.
func (d *Daemon) upstreamNodeOn() bool {
	return nodeSourceEnabled(d.cfg) && upstream.NodeChecksEnabled(RulesOptions(d.cfg).Toggles)
}

// distroFacts are the facts the distro CVE lookup and matcher see:
// NodeSource nodejs packages carry upstream Node versions, so they are
// matched by internal/upstream instead of against distro advisories.
func (d *Daemon) distroFacts(facts *collector.Facts) *collector.Facts {
	if !d.upstreamNodeOn() {
		return facts
	}
	out := upstream.WithoutNodeSource(facts)
	if out != facts {
		audit.Log("UPSTREAM", "nodejs: %d NodeSource package(s) excluded from the distro CVE lookup", len(facts.Packages)-len(out.Packages))
	}
	return out
}

// upstreamPass is one scan's upstream runtime work, split in two so the
// Node release schedule reaches runtime:eol-node before the rules run and
// container images from the inventory are matched after it.
type upstreamPass struct {
	node     *upstream.Node
	env      upstream.Env
	installs []upstream.Install
	stat     *feed.SourceStat
}

// upstreamPrepare detects non-distro Node installs and, when there is any
// Node on the host, fetches the Node data (also feeding the EOL table).
// nil when the source or its checks are off.
func (d *Daemon) upstreamPrepare(ctx context.Context, facts *collector.Facts) *upstreamPass {
	if !d.upstreamNodeOn() {
		return nil
	}
	h := rules.RealHost()
	if d.cfg.Rules.Root != "" {
		h = &rules.Host{Root: d.cfg.Rules.Root}
	}
	p := &upstreamPass{
		node: upstream.NewNode(filepath.Join(d.cfg.Feed.CacheDir, "upstream")),
		env:  upstream.Env{Host: h, Facts: facts, Toggles: RulesOptions(d.cfg).Toggles, Now: time.Now()},
	}
	start := time.Now()
	p.installs = p.node.Detect(ctx, p.env)
	running := false
	for exe := range rules.ProcessExes(h) {
		if b := path.Base(exe); b == "node" || b == "nodejs" {
			running = true
			break
		}
	}
	audit.Log("UPSTREAM", "nodejs: detected installs=%d node_process=%v dur=%s", len(p.installs), running, time.Since(start).Round(time.Millisecond))
	if len(p.installs) > 0 || running {
		p.fetch(ctx)
	}
	return p
}

func (p *upstreamPass) fetch(ctx context.Context) {
	start := time.Now()
	st := p.node.Fetch(ctx)
	p.stat = &st
	if eol := p.node.EOL(); len(eol) > 0 {
		rules.SetRuntimeEOL("node", eol)
	}
	audit.Log("UPSTREAM", "nodejs: fetch status=%s requests=%d cache_hits=%d bytes=%s dur=%s %s",
		st.Status, st.Requests, st.CacheHits, audit.Size(st.Bytes), time.Since(start).Round(time.Millisecond), st.Detail)
}

// upstreamFindings matches the installs (plus node: images from the
// inventory) and records the nodejs data source. all is the scan's
// vulnerability data, used in full mode for NVD scores.
func (d *Daemon) upstreamFindings(ctx context.Context, p *upstreamPass, inv *reporter.InventorySummary, all []feed.Vulnerability, src *feed.ScanSources) []finding.Finding {
	if inv != nil {
		p.installs = append(p.installs, upstream.NodeImageInstalls(inv.Components)...)
	}
	if len(p.installs) > 0 && p.stat == nil {
		p.fetch(ctx)
	}
	if p.stat == nil {
		src.Sources = append(src.Sources, feed.SourceStat{Name: upstream.NodeSourceName, Kind: "lookup",
			Status: feed.StatusSkipped, Detail: "no Node.js on this host: nothing fetched"})
		return nil
	}
	st := *p.stat
	var out []finding.Finding
	if st.Status != feed.StatusFailed {
		out = p.node.Match(ctx, p.env, p.installs, d.nvdEnricher(all, src))
	}
	var paths []string
	for _, in := range p.installs {
		paths = append(paths, in.Path+"="+in.Version+"("+in.Via+")")
	}
	st.Detail = plural(len(p.installs), "non-distro install") + "; " + st.Detail
	switch {
	case len(p.installs) == 0 && st.Status != feed.StatusOK:
		// Only the EOL schedule was wanted (distro node); the built-in
		// table covers it, so no CVE data is missing.
		st.Status = feed.StatusSkipped
		st.Detail += "; built-in EOL table used"
	case st.Status == feed.StatusFailed || st.Status == feed.StatusPartial:
		src.Fail("nodejs: " + p.stat.Detail)
	}
	src.Sources = append(src.Sources, st)
	audit.Log("UPSTREAM", "nodejs: installs=[%s] findings=%d status=%s", strings.Join(paths, " "), len(out), st.Status)
	d.log.Info("upstream node", "installs", len(p.installs), "findings", len(out), "status", st.Status)
	return out
}

// nvdEnricher scores upstream CVEs: by NVD lookup (lookup mode, when the
// nvd source is on) or from the cached NVD feed (full mode).
func (d *Daemon) nvdEnricher(all []feed.Vulnerability, src *feed.ScanSources) upstream.Enricher {
	return func(ctx context.Context, ids []string) map[string]feed.Vulnerability {
		out := map[string]feed.Vulnerability{}
		if d.lookup == nil {
			want := map[string]bool{}
			for _, id := range ids {
				want[id] = true
			}
			for _, v := range all {
				if want[v.ID] && v.Source == "nvd" && v.CVSS > 0 {
					out[v.ID] = v
				}
			}
			return out
		}
		vs, st, ok := d.lookup.NVD(ctx, ids)
		if !ok {
			return out
		}
		for _, v := range vs {
			if v.CVSS > 0 {
				out[v.ID] = v
			}
		}
		audit.Log("LOOKUP", "nvd (nodejs cves) asked=%d scored=%d cache_hits=%d requests=%d status=%s %s",
			len(ids), len(out), st.CacheHits, st.Requests, st.Status, st.Detail)
		if st.Status == feed.StatusFailed || st.Status == feed.StatusPartial {
			src.Fail("nvd: " + st.Detail + " (Node.js CVE scores incomplete)")
		}
		return out
	}
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}
