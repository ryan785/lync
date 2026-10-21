package reporter

import (
	"sort"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// ImpactSummary is a quick-read view used at the top of every report. It
// answers "given what's actually installed and running on this host, how bad
// is it" — not the raw finding count.
type ImpactSummary struct {
	TotalFindings          int                      `json:"total_findings"`
	UniquePackageCount     int                      `json:"unique_package_count"`
	UniquePackages         []string                 `json:"unique_packages,omitempty"`
	KernelFindings         int                      `json:"kernel_findings"`
	KernelCVEs             []string                 `json:"kernel_cves,omitempty"`
	NeedsReboot            bool                     `json:"needs_reboot"`
	HighestCVSS            float64                  `json:"highest_cvss"`
	HighestCVSSCVE         string                   `json:"highest_cvss_cve,omitempty"`
	HighestCVSSPackage     string                   `json:"highest_cvss_package,omitempty"`
	Counts                 map[finding.Severity]int `json:"-"`
	CountsList             []SeverityCount          `json:"severity_counts"`
	ActiveServicesAffected []string                 `json:"active_services_affected,omitempty"`
	RunningServicesCount   int                      `json:"running_services_total"`
}

type SeverityCount struct {
	Severity finding.Severity `json:"severity"`
	Count    int              `json:"count"`
}

func ComputeImpact(facts *collector.Facts, findings []finding.Finding) ImpactSummary {
	s := ImpactSummary{
		TotalFindings:        len(findings),
		Counts:               map[finding.Severity]int{},
		RunningServicesCount: len(facts.Services),
	}

	// Build package → services map for "what's running" lookup.
	servicesByPkg := map[string][]string{}
	for _, svc := range facts.Services {
		if svc.Package != "" {
			servicesByPkg[svc.Package] = append(servicesByPkg[svc.Package], svc.Name)
		}
	}

	pkgs := map[string]bool{}
	activeSvcs := map[string]bool{}
	for _, f := range findings {
		s.Counts[f.Severity]++
		pkgs[f.Package] = true
		if f.Package == "kernel" {
			s.KernelFindings++
			s.NeedsReboot = true
			s.KernelCVEs = append(s.KernelCVEs, f.CVE)
		}
		if f.CVSS > s.HighestCVSS {
			s.HighestCVSS = f.CVSS
			s.HighestCVSSCVE = f.CVE
			s.HighestCVSSPackage = f.Package
		}
		for _, svc := range servicesByPkg[f.Package] {
			activeSvcs[svc] = true
		}
	}

	s.UniquePackageCount = len(pkgs)
	for p := range pkgs {
		s.UniquePackages = append(s.UniquePackages, p)
	}
	sort.Strings(s.UniquePackages)
	sort.Strings(s.KernelCVEs)

	for svc := range activeSvcs {
		s.ActiveServicesAffected = append(s.ActiveServicesAffected, svc)
	}
	sort.Strings(s.ActiveServicesAffected)

	for _, sev := range []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo, finding.SeverityUnknown,
	} {
		s.CountsList = append(s.CountsList, SeverityCount{Severity: sev, Count: s.Counts[sev]})
	}
	return s
}
