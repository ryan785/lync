package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
)

func TestReportWithSourcesAndInventoryRoundTrips(t *testing.T) {
	dir := t.TempDir()
	facts := &collector.Facts{Hostname: "h", OS: collector.OSInfo{PrettyName: "Debian 12"}}
	fs := []finding.Finding{{ID: "CVE-1:p", Category: finding.CategoryCVE, CVE: "CVE-1", Package: "p", Severity: finding.SeverityHigh}}
	r := BuildReport(facts, fs, ComputeImpact(facts, fs))
	r.DataSources = &feed.ScanSources{Mode: "lookup", CheckedAt: time.Now(), PackagesChecked: 159, Complete: false,
		IncompleteReasons: []string{"nvd: 1 lookup failed (severity enrichment incomplete)"},
		Sources:           []feed.SourceStat{{Name: "osv", Kind: "lookup", Status: "ok", Requests: 3, Records: 342}, {Name: "nvd", Kind: "lookup", Status: "partial", Detail: strings.Repeat("long detail ", 30)}},
		UnfixedCVEs:       12}
	r.Inventory = &InventorySummary{Total: 2, Counts: map[string]int{"npm": 1, "PyPI": 1}, Queried: 2, Vulnerable: 1, Status: "ok",
		Components: []inventory.Component{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}}
	jp, pp := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.pdf")
	if err := WriteReport(jp, r); err != nil {
		t.Fatal(err)
	}
	back, err := ReadJSON(jp)
	if err != nil || back.DataSources == nil || back.DataSources.Complete || back.Inventory.Total != 2 || back.DataSources.Sources[0].Records != 342 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if err := WritePDFFromJSON(jp, pp); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(pp); err != nil || fi.Size() < 1000 {
		t.Errorf("pdf: %v %v", fi, err)
	}
	// Older reports without the new sections still render.
	r.DataSources, r.Inventory, r.Findings = nil, nil, nil
	WriteReport(jp, r)
	if err := WritePDFFromJSON(jp, pp); err != nil {
		t.Fatal(err)
	}
}
