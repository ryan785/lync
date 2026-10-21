package feed

import (
	"context"
	"log/slog"
	"time"
)

type Vulnerability struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	Severity    string            `json:"severity,omitempty"`
	Description string            `json:"description,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	Affects     []AffectedPackage `json:"affects,omitempty"`
	References  []string          `json:"references,omitempty"`
	Published   time.Time         `json:"published,omitempty"`
	Modified    time.Time         `json:"modified,omitempty"`
}

type AffectedPackage struct {
	Distro       string `json:"distro,omitempty"`
	Name         string `json:"name"`
	FixedVersion string `json:"fixed_version,omitempty"`
	VersionRange string `json:"version_range,omitempty"`
	// Status is the upstream provider's stance for this exact distro+package
	// combination. Vocabulary varies by provider (Debian: "resolved" / "open"
	// / "no-dsa" / "ignored"; Ubuntu: "released" / "needed" / "deferred" /
	// "ignored" / "not-affected"; Alpine: empty when fix shipped). Applicability
	// judges read it to decide whether to suppress the finding.
	Status string `json:"status,omitempty"`
}

type Source interface {
	Name() string
	Sync(ctx context.Context, store *Store, log *slog.Logger) error
	Vulnerabilities(store *Store) ([]Vulnerability, error)
}
