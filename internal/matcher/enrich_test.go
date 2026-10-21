package matcher

import (
	"testing"

	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

func TestEnrichSeverity(t *testing.T) {
	fs := []finding.Finding{
		{CVE: "CVE-1", Category: finding.CategoryCVE, Severity: finding.SeverityUnknown, Source: "debian"},
		{CVE: "CVE-2", Category: finding.CategoryCVE, Severity: finding.SeverityLow, Source: "redhat"},
		{CVE: "CVE-3", Category: finding.CategoryCVE, Severity: finding.SeverityUnknown, Source: "osv"},
	}
	vulns := []feed.Vulnerability{
		{ID: "CVE-1", Source: "osv", CVSS: 5.5},
		{ID: "CVE-1", Source: "nvd", CVSS: 9.8, Severity: "CRITICAL"},
		{ID: "CVE-2", Source: "nvd", CVSS: 9.8, Severity: "CRITICAL"},
		{ID: "CVE-3", Source: "osv", Severity: "Moderate", CVSS: 9.0},
	}
	out := EnrichSeverity(fs, vulns)
	if out[0].Severity != finding.SeverityCritical || out[0].CVSS != 9.8 {
		t.Errorf("CVE-1 = %+v", out[0])
	}
	if out[1].Severity != finding.SeverityLow || out[1].CVSS != 9.8 {
		t.Errorf("distro severity must win: %+v", out[1])
	}
	if out[2].Severity != finding.SeverityMedium {
		t.Errorf("distro label beats CVSS: %+v", out[2])
	}
}
