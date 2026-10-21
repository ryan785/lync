package daemon

import (
	"context"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
	"github.com/ryan785/lync/internal/reporter"
	"github.com/ryan785/lync/internal/rules"
)

// maxInventoryWarnLines caps INVENTORY warning lines in the run log.
const maxInventoryWarnLines = 100

// runInventory collects application components (full-host scans only),
// looks them up on OSV.dev with the shared client, and returns the report
// section plus findings. A failed lookup marks the scan's CVE data
// incomplete.
func (d *Daemon) runInventory(ctx context.Context, src *feed.ScanSources) (*reporter.InventorySummary, []finding.Finding) {
	ic := d.cfg.Inventory
	opts := inventory.Options{Containers: ic.Containers, SkipPaths: ic.SkipPaths, TimeBudget: ic.TimeBudget}
	for _, r := range ic.Roots {
		opts.Roots = append(opts.Roots, inventory.Root{Path: r})
	}
	var host *rules.Host
	if d.cfg.Rules.Root != "" {
		host = &rules.Host{Root: d.cfg.Rules.Root}
	}
	start := time.Now()
	res := inventory.CollectResult(ctx, host, opts)
	sum := &reporter.InventorySummary{
		Total: len(res.Components), Counts: map[string]int{}, Components: res.Components,
		Warnings: len(res.Warnings), Stats: res.Stats, Status: feed.StatusSkipped,
	}
	if sum.Components == nil {
		sum.Components = []inventory.Component{}
	}
	for _, c := range res.Components {
		sum.Counts[c.Ecosystem]++
		if inventory.Queryable(c) {
			sum.Queried++
		}
	}
	for i, w := range res.Warnings {
		if i < 20 {
			sum.Samples = append(sum.Samples, w)
		}
		if i < maxInventoryWarnLines {
			audit.Log("INVENTORY", "warning kind=%s path=%s reason=%q", w.Kind, w.Path, w.Reason)
		}
	}
	if len(res.Warnings) > maxInventoryWarnLines {
		audit.Log("INVENTORY", "%d more warnings not logged", len(res.Warnings)-maxInventoryWarnLines)
	}
	audit.Log("INVENTORY", "collected components=%d queryable=%d by_ecosystem=%v entries=%d files=%d truncated=%v warnings=%d dur=%s",
		sum.Total, sum.Queried, sum.Counts, res.Stats.Entries, res.Stats.FilesParsed, res.Stats.Truncated, len(res.Warnings), res.Stats.Duration.Round(time.Millisecond))

	var out []finding.Finding
	st := feed.SourceStat{Name: "osv-apps", Kind: "lookup", Status: feed.StatusSkipped, Detail: "no application components to look up"}
	if sum.Queried > 0 {
		qstart := time.Now()
		hits, err := inventory.QueryOSV(ctx, nil, res.Components)
		st = feed.SourceStat{Name: "osv-apps", Kind: "lookup", Status: feed.StatusOK, Records: len(hits)}
		if err != nil {
			st.Status, st.Detail = feed.StatusFailed, err.Error()
			sum.Status, sum.Error = feed.StatusFailed, err.Error()
			src.Fail("osv (application components): " + err.Error())
		} else {
			sum.Status = feed.StatusOK
			vuln := map[string]bool{}
			for _, h := range hits {
				vuln[h.Component.Key()] = true
			}
			sum.Vulnerable = len(vuln)
			out = inventory.Findings(hits, time.Now())
		}
		audit.Log("INVENTORY", "osv queried=%d hits=%d vulnerable_components=%d findings=%d status=%s dur=%s",
			sum.Queried, len(hits), sum.Vulnerable, len(out), st.Status, time.Since(qstart).Round(time.Millisecond))
	}
	src.Sources = append(src.Sources, st)
	d.log.Info("application inventory", "components", sum.Total, "vulnerable", sum.Vulnerable, "findings", len(out), "dur", time.Since(start).Round(time.Millisecond))
	return sum, out
}
