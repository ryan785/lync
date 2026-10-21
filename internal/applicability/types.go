// Package applicability decides whether a candidate finding actually applies
// to the host being scanned. Each Judge is one feed provider's curated view
// of "does this CVE matter on this distro+package right now". The Engine
// runs every judge that AppliesTo the host's OS and uses their combined
// verdicts to suppress findings the matcher emitted but a provider has
// explicitly de-prioritized.
//
// The Engine is provider-agnostic so adding Debian/Ubuntu/SUSE/Alpine
// support in later phases is a matter of dropping in another Judge.
package applicability

import (
	"context"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

type Status int

const (
	// StatusUnknown — judge has no opinion. Don't suppress, don't annotate.
	StatusUnknown Status = iota
	// StatusAffected — judge confirms the CVE applies here.
	StatusAffected
	// StatusNotAffected — judge explicitly says this code path / config
	// doesn't apply on this distro+package. Strong signal to suppress.
	StatusNotAffected
	// StatusDeferredOrWontFix — provider acknowledged the bug exists but
	// decided not to ship a fix (impact too low, EOL stream, etc.). For our
	// scanner, defaults to suppression: the provider is the authority on
	// real-world impact for their distro.
	StatusDeferredOrWontFix
)

func (s Status) String() string {
	switch s {
	case StatusAffected:
		return "affected"
	case StatusNotAffected:
		return "not_affected"
	case StatusDeferredOrWontFix:
		return "deferred_or_wontfix"
	}
	return "unknown"
}

type Verdict struct {
	Status Status
	Judge  string
	Reason string
}

type Judge interface {
	Name() string
	// AppliesTo returns true if this judge has relevant data for the host's
	// OS. RedHatJudge returns true for rhel/rocky/alma/centos/oraclelinux,
	// DebianJudge for debian/ubuntu, etc.
	AppliesTo(os collector.OSInfo) bool
	// Evaluate decides applicability of a (cve, package) pair on this host.
	// Returns StatusUnknown when the judge has no data for that specific
	// pair — the engine then defers to other judges or keeps the finding.
	Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error)
}

// FindingKey is what we evaluate against — minimal info pulled from a Finding.
type FindingKey struct {
	CVE     string
	Package string
}

func KeyOf(f finding.Finding) FindingKey {
	return FindingKey{CVE: f.CVE, Package: f.Package}
}
