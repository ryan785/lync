package applicability

import (
	"context"

	"github.com/ryan785/lync/internal/collector"
)

// SUSEJudge will consult SUSE's CVE database
// (https://www.suse.com/security/cve/<id>.json) which carries per-product
// "Affected" / "Not affected" / "Already fixed" status. Stub in Phase 1;
// implemented alongside the SUSE OVAL feed in Phase 2.
type SUSEJudge struct{}

func NewSUSEJudge() *SUSEJudge { return &SUSEJudge{} }

func (j *SUSEJudge) Name() string { return "suse" }

func (j *SUSEJudge) AppliesTo(os collector.OSInfo) bool {
	switch os.ID {
	case "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse":
		return true
	}
	for _, l := range os.IDLike {
		if l == "suse" {
			return true
		}
	}
	return false
}

func (j *SUSEJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
	return Verdict{Status: StatusUnknown, Judge: j.Name(), Reason: "not implemented (Phase 2)"}, nil
}
