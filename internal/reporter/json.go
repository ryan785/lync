package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
)

type Report struct {
	Generated time.Time            `json:"generated"`
	Host      string               `json:"host"`
	OS        collector.OSInfo     `json:"os"`
	Kernel    collector.KernelInfo `json:"kernel"`
	PkgCount  int                  `json:"package_count"`
	Counts    Counts               `json:"counts"`
	Impact    ImpactSummary        `json:"impact"`
	Findings  []finding.Finding    `json:"findings"`
	// DataSources says where the CVE data came from and whether the CVE
	// section is complete. Absent in reports from older versions.
	DataSources *feed.ScanSources `json:"data_sources,omitempty"`
	// Inventory lists application components found outside the package
	// manager (full-host scans with inventory enabled).
	Inventory *InventorySummary `json:"inventory,omitempty"`
	// Coverage summarises the check packs: how many checks applied to
	// this host and passed, failed or were skipped (full scans only).
	Coverage []finding.PackCoverage `json:"check_coverage,omitempty"`
}

// InventorySummary is the application inventory part of a report.
type InventorySummary struct {
	Total      int                   `json:"total"`
	Counts     map[string]int        `json:"counts"`     // components per ecosystem
	Vulnerable int                   `json:"vulnerable"` // components with at least one OSV hit
	Queried    int                   `json:"queried"`    // components sent to OSV.dev
	Status     string                `json:"status"`     // ok | failed | skipped
	Error      string                `json:"error,omitempty"`
	Warnings   int                   `json:"warnings"`
	Samples    []inventory.Warning   `json:"warning_samples,omitempty"`
	Stats      inventory.Stats       `json:"stats"`
	Components []inventory.Component `json:"components"`
}

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// BuildReport assembles the canonical Report struct that both WriteJSON
// and WritePDF consume. Called once per scan; JSON is written first as the
// authoritative artifact, the PDF renderer reads back from JSON.
func BuildReport(facts *collector.Facts, findings []finding.Finding, impact ImpactSummary) *Report {
	r := &Report{
		Generated: time.Now(),
		Host:      facts.Hostname,
		OS:        facts.OS,
		Kernel:    facts.Kernel,
		PkgCount:  len(facts.Packages),
		Impact:    impact,
		Findings:  findings,
	}
	r.Counts.Critical = impact.Counts[finding.SeverityCritical]
	r.Counts.High = impact.Counts[finding.SeverityHigh]
	r.Counts.Medium = impact.Counts[finding.SeverityMedium]
	r.Counts.Low = impact.Counts[finding.SeverityLow]
	r.Counts.Info = impact.Counts[finding.SeverityInfo]
	r.Counts.Unknown = impact.Counts[finding.SeverityUnknown]
	r.Counts.Total = len(findings)
	return r
}

// ReadJSON loads a Report from disk so the PDF renderer (or future
// re-render tooling) can produce a PDF from the canonical artifact.
func ReadJSON(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func WriteJSON(path string, facts *collector.Facts, findings []finding.Finding, impact ImpactSummary) error {
	return WriteReport(path, BuildReport(facts, findings, impact))
}

// WriteReport writes a prepared Report as indented JSON.
func WriteReport(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
