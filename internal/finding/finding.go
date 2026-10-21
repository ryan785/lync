package finding

import "time"

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
	SeverityUnknown  Severity = "Unknown"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

type Category string

const (
	CategoryCVE        Category = "cve"
	CategoryConfig     Category = "config"
	CategoryEOL        Category = "eol"
	CategoryHardening  Category = "hardening"
	CategoryFilesystem Category = "filesystem"
	CategoryNetwork    Category = "network"
	CategoryTLS        Category = "tls"
	CategoryRuntime    Category = "runtime"
)

type Finding struct {
	ID          string    `json:"id"`
	Category    Category  `json:"category"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Evidence    string    `json:"evidence,omitempty"`
	References  []string  `json:"references,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`

	CVE       string  `json:"cve,omitempty"`
	Package   string  `json:"package,omitempty"`
	Installed string  `json:"installed,omitempty"`
	FixedIn   string  `json:"fixed_in,omitempty"`
	CVSS      float64 `json:"cvss,omitempty"`
	Source    string  `json:"source,omitempty"`
}
