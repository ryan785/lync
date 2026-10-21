package applicability

import (
	"context"
	"strings"
	"sync"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
)

// DebianJudge consumes the Debian Security Tracker bulk data the
// DebianSource already wrote into the feed cache. No additional network
// fetching needed.
type DebianJudge struct {
	store *feed.Store

	once  sync.Once
	index map[string]map[debianKey]string // cve -> {distro, pkg} -> status
}

type debianKey struct {
	distro, pkg string
}

func NewDebianJudge(store *feed.Store) *DebianJudge {
	return &DebianJudge{store: store}
}

func (j *DebianJudge) Name() string { return "debian" }

func (j *DebianJudge) AppliesTo(os collector.OSInfo) bool {
	if os.ID == "debian" {
		return true
	}
	for _, l := range os.IDLike {
		if l == "debian" {
			return true
		}
	}
	return false
}

func (j *DebianJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
	j.once.Do(func() { j.loadIndex() })
	if j.index == nil {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}
	major := facts.OS.VersionID
	if i := strings.Index(major, "."); i > 0 {
		major = major[:i]
	}
	distroFilter := "debian:" + major
	status := j.index[cveID][debianKey{distro: distroFilter, pkg: pkgName}]
	switch status {
	case "":
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	case "not-affected":
		return Verdict{Status: StatusNotAffected, Judge: j.Name(),
			Reason: "Debian: not-affected on " + distroFilter}, nil
	case "no-dsa", "postponed":
		return Verdict{Status: StatusDeferredOrWontFix, Judge: j.Name(),
			Reason: "Debian: " + status + " on " + distroFilter}, nil
	case "ignored", "end-of-life":
		return Verdict{Status: StatusDeferredOrWontFix, Judge: j.Name(),
			Reason: "Debian: " + status + " on " + distroFilter}, nil
	case "open", "undetermined":
		return Verdict{Status: StatusAffected, Judge: j.Name(),
			Reason: "Debian: " + status + " on " + distroFilter}, nil
	case "resolved":
		return Verdict{Status: StatusAffected, Judge: j.Name(),
			Reason: "Debian: shipped fix"}, nil
	}
	return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
}

// loadIndex rebuilds the in-memory lookup from the on-disk Debian vulns
// cache. Called once lazily on the first Evaluate.
func (j *DebianJudge) loadIndex() {
	if j.store == nil {
		return
	}
	vulns, err := j.store.GetVulns("debian")
	if err != nil || len(vulns) == 0 {
		return
	}
	j.index = make(map[string]map[debianKey]string, len(vulns))
	for _, v := range vulns {
		for _, ap := range v.Affects {
			if j.index[v.ID] == nil {
				j.index[v.ID] = map[debianKey]string{}
			}
			j.index[v.ID][debianKey{distro: ap.Distro, pkg: ap.Name}] = ap.Status
		}
	}
}
