package applicability

import (
	"context"

	"github.com/ryan785/lync/internal/collector"
)

// AlpineJudge will consult Alpine secdb's per-package CVE data
// (https://secdb.alpinelinux.org/v<ver>/community.json,
//
//	https://secdb.alpinelinux.org/v<ver>/main.json) which lists fixed
//
// versions or "wontfix"/"rejected" entries. Stub in Phase 1; implemented
// alongside the apk collector + Alpine secdb feed in Phase 2.
type AlpineJudge struct{}

func NewAlpineJudge() *AlpineJudge { return &AlpineJudge{} }

func (j *AlpineJudge) Name() string { return "alpine" }

func (j *AlpineJudge) AppliesTo(os collector.OSInfo) bool {
	return os.ID == "alpine"
}

func (j *AlpineJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
	return Verdict{Status: StatusUnknown, Judge: j.Name(), Reason: "not implemented (Phase 2)"}, nil
}
