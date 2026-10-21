package matcher

import (
	"fmt"

	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

// EnrichSeverity fills in severity and CVSS for CVE findings whose winning
// source had none (Debian tracker and many OSV records carry no rating).
// A distro rating from another source wins over a bare CVSS score; among
// CVSS scores NVD's is preferred, then Red Hat's, then OSV's. Findings
// that already have a severity keep it (distro data beats NVD).
func EnrichSeverity(findings []finding.Finding, vulns []feed.Vulnerability) []finding.Finding {
	type best struct {
		label, labelSrc string
		cvss            float64
		cvssSrc         string
		cvssRank        int
	}
	rank := map[string]int{"nvd": 3, "redhat": 2, "osv": 1}
	byID := map[string]*best{}
	for _, v := range vulns {
		if v.Severity == "" && v.CVSS == 0 {
			continue
		}
		b := byID[v.ID]
		if b == nil {
			b = &best{}
			byID[v.ID] = b
		}
		if v.Severity != "" && normalizeSeverity(v.Severity, 0) != finding.SeverityUnknown && (b.label == "" || sourcePriority(v.Source) > sourcePriority(b.labelSrc)) {
			b.label, b.labelSrc = v.Severity, v.Source
		}
		if v.CVSS > 0 && (b.cvss == 0 || rank[v.Source] > b.cvssRank) {
			b.cvss, b.cvssSrc, b.cvssRank = v.CVSS, v.Source, rank[v.Source]
		}
	}
	for i := range findings {
		f := &findings[i]
		if f.Category != finding.CategoryCVE || f.CVE == "" {
			continue
		}
		b := byID[f.CVE]
		if b == nil {
			continue
		}
		if f.CVSS == 0 && b.cvss > 0 {
			f.CVSS = b.cvss
		}
		if f.Severity == finding.SeverityUnknown {
			switch {
			case b.label != "":
				f.Severity = normalizeSeverity(b.label, 0)
				f.Evidence += fmt.Sprintf("; severity from %s", b.labelSrc)
			case b.cvss > 0:
				f.Severity = normalizeSeverity("", b.cvss)
				f.Evidence += fmt.Sprintf("; severity from %s CVSS %.1f", b.cvssSrc, b.cvss)
			}
		}
	}
	return findings
}
