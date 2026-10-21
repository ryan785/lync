package daemon

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/matcher"
)

// CVE verdicts, from most to least certain. The distinction between
// NotAffected and Unknown is the point of this command: "no finding" is
// only reassuring if some cached feed actually knows the CVE.
const (
	VerdictAffected       = "affected"          // a feed's fixed version / range says vulnerable
	VerdictNoFixYet       = "possibly_affected" // installed package named by a feed, but no fixed version published yet
	VerdictNotAffected    = "not_affected"      // feeds know the CVE; installed versions are fixed or packages absent
	VerdictUnknownToFeeds = "unknown"           // no cached feed has this CVE (not published yet, or feeds stale)
)

var cveIDRE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CVECheck is the answer to "is this host affected by CVE-X?".
type CVECheck struct {
	Host       string            `json:"host"`
	OS         string            `json:"os"`
	CVE        string            `json:"cve"`
	Verdict    string            `json:"verdict"`
	Reason     string            `json:"reason"`
	KnownBy    map[string]int    `json:"known_by"`             // source -> affected entries
	Installed  []CVEInstalledPkg `json:"installed,omitempty"`  // installed packages a feed names
	Findings   []finding.Finding `json:"findings,omitempty"`   // after applicability filtering
	Suppressed int               `json:"suppressed,omitempty"` // findings dropped by distro judges
	Sources    *feed.ScanSources `json:"sources,omitempty"`    // lookups queried (lookup mode)
}

type CVEInstalledPkg struct {
	FeedName  string `json:"feed_name"`
	Source    string `json:"source"`
	Installed string `json:"installed"`
	FixedIn   string `json:"fixed_in,omitempty"`
	Range     string `json:"range,omitempty"`
	Status    string `json:"status,omitempty"`
}

// CheckCVE collects fresh facts and evaluates a single CVE against every
// cached feed. It does not trigger a feed sync: run `lync sync` first if the
// CVE was published after the last sync.
func (d *Daemon) CheckCVE(ctx context.Context, id string) (*CVECheck, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if !cveIDRE.MatchString(id) {
		return nil, fmt.Errorf("invalid CVE id %q (want CVE-YYYY-NNNN)", id)
	}
	facts, err := collector.Collect(ctx, d.log)
	if err != nil {
		return nil, err
	}

	if d.lookup != nil {
		vulns, src := d.lookup.CVE(ctx, facts, id)
		res := evaluateCVE(ctx, d, facts, id, vulns)
		res.Sources = &src
		if !src.Complete {
			if len(vulns) == 0 {
				res.Reason = "lookups failed, verdict unknown: " + strings.Join(src.IncompleteReasons, "; ")
			} else {
				res.Reason += " (some lookups failed: " + strings.Join(src.IncompleteReasons, "; ") + ")"
			}
		}
		return res, nil
	}

	var vulns []feed.Vulnerability
	for _, src := range d.sources {
		all, err := src.Vulnerabilities(d.store)
		if err != nil {
			d.log.Warn("feed read failed", "source", src.Name(), "err", err)
			continue
		}
		for _, v := range all {
			if v.ID == id {
				vulns = append(vulns, v)
			}
		}
	}
	return evaluateCVE(ctx, d, facts, id, vulns), nil
}

// evaluateCVE is CheckCVE minus the I/O, so it can be unit-tested.
func evaluateCVE(ctx context.Context, d *Daemon, facts *collector.Facts, id string, vulns []feed.Vulnerability) *CVECheck {
	res := &CVECheck{
		Host:    facts.Hostname,
		OS:      facts.OS.PrettyName,
		CVE:     id,
		KnownBy: map[string]int{},
	}
	for _, v := range vulns {
		res.KnownBy[v.Source] += len(v.Affects)
	}
	res.Installed = installedCandidates(facts, vulns)

	matched := matcher.Match(facts, vulns, nil)
	kept := matched
	if d != nil && d.applicEngine != nil {
		kept, _ = d.applicEngine.Filter(ctx, matched, facts)
	}
	res.Findings = kept
	res.Suppressed = len(matched) - len(kept)

	// "No fix yet" only when no feed offers any fixed version or range for
	// the installed packages; one concrete fix is enough to judge.
	hasFix := false
	for _, c := range res.Installed {
		if c.FixedIn != "" || c.Range != "" {
			hasFix = true
		}
	}
	noFixYet := len(res.Installed) > 0 && !hasFix
	switch {
	case len(kept) > 0:
		res.Verdict = VerdictAffected
		res.Reason = fmt.Sprintf("%d finding(s); see findings[].remediation", len(kept))
	case len(vulns) == 0:
		res.Verdict = VerdictUnknownToFeeds
		res.Reason = "no feed has data for this CVE yet - vendors may not have published (full mode: run `lync sync` and retry)"
	case noFixYet:
		res.Verdict = VerdictNoFixYet
		res.Reason = "an installed package is named by a feed but no fixed version is published yet"
	case len(res.Installed) == 0:
		res.Verdict = VerdictNotAffected
		res.Reason = "none of the packages named by the feeds are installed"
	default:
		res.Verdict = VerdictNotAffected
		res.Reason = "installed versions are at or above the published fixes"
		if res.Suppressed > 0 {
			res.Reason = fmt.Sprintf("%d candidate finding(s) suppressed by distro applicability data", res.Suppressed)
		}
	}
	return res
}

// installedCandidates lists installed packages that a feed entry for this
// CVE names (by binary name or by source package name) on this distro.
func installedCandidates(facts *collector.Facts, vulns []feed.Vulnerability) []CVEInstalledPkg {
	var out []CVEInstalledPkg
	seen := map[string]bool{}
	for _, v := range vulns {
		for _, ap := range v.Affects {
			if !matcher.DistroMatches(ap.Distro, facts.OS) {
				continue
			}
			for _, p := range facts.Packages {
				if p.Name != ap.Name && p.SourceName() != ap.Name {
					continue
				}
				k := v.Source + "|" + ap.Name + "|" + p.NEVRA() + "|" + ap.FixedVersion + "|" + ap.VersionRange
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, CVEInstalledPkg{
					FeedName:  ap.Name,
					Source:    v.Source,
					Installed: p.NEVRA(),
					FixedIn:   ap.FixedVersion,
					Range:     ap.VersionRange,
					Status:    ap.Status,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Installed != out[j].Installed {
			return out[i].Installed < out[j].Installed
		}
		return out[i].Source < out[j].Source
	})
	return out
}
