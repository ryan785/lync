package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildReport(facts, findings, impact))
}
