package feed

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// cveIDs returns every CVE id an OSV record stands for, in a stable order:
// the record id itself when it is a CVE, then aliases, then upstream.
// Distro records name the CVE in different places: DSA/RLSA bulk records
// historically used aliases, DEBIAN-CVE-*, UBUNTU-CVE-*, ALPINE-CVE-* and
// current RLSA/RHSA records use upstream.
func (r *osvRecord) cveIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(r.ID)
	for _, a := range r.Aliases {
		add(a)
	}
	for _, a := range r.Upstream {
		add(a)
	}
	return out
}

// severity extracts the distro's own rating and the best CVSS v3 score.
//   - Rocky/Alma advisories: summary "Important: openssl security update"
//   - Ubuntu: severity[] entry {type: Ubuntu, score: medium}
//   - Debian: affected[].ecosystem_specific.urgency (low/medium/high)
//   - CVSS_V3 vectors: scored with CVSS3BaseScore (highest wins)
func (r *osvRecord) severity(accept func(string) bool) (label string, cvss float64) {
	if p, _, ok := strings.Cut(r.Summary, ":"); ok {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "critical", "important", "moderate", "low":
			label = strings.TrimSpace(p)
		}
	}
	for _, s := range r.Severity {
		switch {
		case strings.HasPrefix(s.Type, "CVSS_V3"):
			if v, ok := CVSS3BaseScore(s.Score); ok && v > cvss {
				cvss = v
			}
		case s.Type == "Ubuntu" && label == "":
			label = distroLabel(s.Score)
		}
	}
	if label == "" {
		for _, a := range r.Affected {
			if accept != nil && !accept(a.Package.Ecosystem) {
				continue
			}
			var es struct {
				Urgency string `json:"urgency"`
			}
			if len(a.EcosystemSpecific) > 0 && json.Unmarshal(a.EcosystemSpecific, &es) == nil {
				if l := distroLabel(es.Urgency); l != "" {
					label = l
					break
				}
			}
		}
	}
	return label, cvss
}

// distroLabel normalises Debian urgencies and Ubuntu priorities. Values
// that carry no rating ("not yet assigned", "untriaged") return "".
func distroLabel(s string) string {
	switch strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, "*"))) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low", "negligible", "unimportant":
		return "Low"
	}
	return ""
}

// osvToVulns converts one OSV record into one Vulnerability per CVE id it
// covers, keeping only affected[] entries whose ecosystem passes accept.
// distro is the matcher filter stamped on every entry ("debian:12").
// keepUnfixed keeps entries without a fixed event (Status "unfixed"):
// they never become findings but let `lync cve` say "possibly affected".
func osvToVulns(r *osvRecord, accept func(string) bool, distro string, keepUnfixed bool) []Vulnerability {
	ids := r.cveIDs()
	if len(ids) == 0 {
		return nil
	}
	var affects []AffectedPackage
	seen := map[string]bool{}
	for _, aff := range r.Affected {
		if accept != nil && !accept(aff.Package.Ecosystem) {
			continue
		}
		fixed := lastFixedInRanges(aff.Ranges)
		ap := AffectedPackage{Distro: distro, Name: aff.Package.Name, FixedVersion: fixed}
		if fixed == "" {
			if !keepUnfixed {
				continue
			}
			ap.Status = "unfixed"
		}
		k := ap.Name + "|" + ap.FixedVersion
		if seen[k] {
			continue
		}
		seen[k] = true
		affects = append(affects, ap)
	}
	if len(affects) == 0 {
		return nil
	}
	label, cvss := r.severity(accept)
	desc := r.Details
	if desc == "" {
		desc = r.Summary
	}
	var refs []string
	if r.ID != "" && !strings.HasPrefix(r.ID, "CVE-") {
		refs = append(refs, "https://osv.dev/vulnerability/"+r.ID)
	}
	for _, ref := range r.References {
		refs = append(refs, ref.URL)
	}
	pub, _ := time.Parse(time.RFC3339, r.Published)
	mod, _ := time.Parse(time.RFC3339, r.Modified)
	out := make([]Vulnerability, 0, len(ids))
	for _, id := range ids {
		out = append(out, Vulnerability{
			ID:          id,
			Source:      "osv",
			Severity:    label,
			CVSS:        cvss,
			Description: desc,
			Affects:     affects,
			References:  refs,
			Published:   pub,
			Modified:    mod,
		})
	}
	return out
}

// trimVuln shortens free text so per-host lookup caches stay small.
func trimVuln(v Vulnerability) Vulnerability {
	if len(v.Description) > 600 {
		v.Description = v.Description[:600] + "..."
	}
	if len(v.References) > 5 {
		v.References = v.References[:5]
	}
	return v
}

// sortedKeys returns map keys in order (stable cache files and requests).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
