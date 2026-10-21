package rules

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/finding"
)

// CheckInfo describes one check: a stable ID prefix that every finding it
// emits starts with ("web:sensitive-file" -> "web:sensitive-file:/var/www/.env").
type CheckInfo struct {
	ID          string           `json:"id"`
	Rule        string           `json:"rule"`
	Severity    finding.Severity `json:"severity"` // typical/maximum severity
	Description string           `json:"description"`
	// DefaultOff checks run only when listed in rules.enable (e.g. ones
	// that exec into containers).
	DefaultOff bool `json:"default_off,omitempty"`
	// Declarative checks (packs) also carry these.
	Pack    string   `json:"pack,omitempty"`
	Title   string   `json:"title,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Applies string   `json:"applies_if,omitempty"`
	Level   string   `json:"level,omitempty"`

	aliases []string // legacy rule names that toggle the whole pack
}

// PackName is the pack a check belongs to (the rule name for Go checks).
func (c CheckInfo) PackName() string {
	if c.Pack != "" {
		return c.Pack
	}
	return c.Rule
}

var (
	catalogMu sync.Mutex
	catalog   = map[string]CheckInfo{}
)

// register adds a check to the catalog. Called from package init().
func register(cs ...CheckInfo) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	for _, c := range cs {
		catalog[c.ID] = c
	}
}

// Catalog returns every known check sorted by ID.
func Catalog() []CheckInfo {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	out := make([]CheckInfo, 0, len(catalog))
	for _, c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Toggles holds rules.disable / rules.enable from config. Entries are
// check IDs ("php:upload-progress"), ID prefixes ("php", "docker:"), rule
// or pack names ("ssh-config", "pack:nginx") or tags ("tag:cis").
type Toggles struct {
	Disable []string
	Enable  []string
}

func matchesToggle(entry, id string, info CheckInfo, known bool) bool {
	entry = strings.TrimSuffix(strings.TrimSpace(entry), ":")
	if entry == "" {
		return false
	}
	if id == entry || strings.HasPrefix(id, entry+":") {
		return true
	}
	if !known {
		return false
	}
	if p, ok := strings.CutPrefix(entry, "pack:"); ok {
		return p == info.PackName()
	}
	if tg, ok := strings.CutPrefix(entry, "tag:"); ok {
		for _, x := range info.Tags {
			if strings.EqualFold(x, tg) {
				return true
			}
		}
		return false
	}
	if info.Pack != "" && entry == info.Pack {
		return true
	}
	for _, a := range info.aliases {
		if entry == a {
			return true
		}
	}
	return false
}

// CheckEnabled reports whether a check (or a finding ID under it) is on.
func (t Toggles) CheckEnabled(id string) bool {
	catalogMu.Lock()
	info, known := catalog[checkIDOf(id)]
	catalogMu.Unlock()
	for _, e := range t.Enable {
		if matchesToggle(e, id, info, known) {
			return true
		}
	}
	for _, d := range t.Disable {
		if matchesToggle(d, id, info, known) {
			return false
		}
	}
	return !(known && info.DefaultOff)
}

// CheckInfoOf returns the catalog entry a finding ID belongs to.
func CheckInfoOf(findingID string) (CheckInfo, bool) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	c, ok := catalog[checkIDOf(findingID)]
	return c, ok
}

// RuleEnabled reports whether a whole rule (by Name()) is on.
func (t Toggles) RuleEnabled(name string) bool {
	for _, d := range t.Disable {
		if strings.TrimSpace(d) == name {
			return false
		}
	}
	return true
}

// checkIDOf maps a finding ID to the registered check ID it belongs to
// (longest registered prefix), or returns the ID unchanged.
func checkIDOf(findingID string) string {
	best := ""
	for id := range catalog {
		if (findingID == id || strings.HasPrefix(findingID, id+":")) && len(id) > len(best) {
			best = id
		}
	}
	if best == "" {
		return findingID
	}
	return best
}

// on is the guard checks call before doing any work.
func (o Options) on(id string) bool { return o.Toggles.CheckEnabled(id) }

// host returns the configured Host or the real one.
func (o Options) host() *Host {
	if o.Host != nil {
		return o.Host
	}
	return RealHost()
}

// mkFinding builds a rules finding with the shared shape. key is appended
// to the check ID to make the finding ID unique and stable (a path, port,
// unit name...).
func mkFinding(h *Host, checkID, key string, cat finding.Category, sev finding.Severity,
	title, evidence, fix string, refs ...string) finding.Finding {
	id := checkID
	if key != "" {
		id += ":" + key
	}
	return finding.Finding{
		ID:          id,
		Category:    cat,
		Severity:    sev,
		Title:       title,
		Evidence:    evidence,
		Remediation: fix,
		References:  refs,
		DetectedAt:  h.now(),
		Source:      "lync-rules",
		Check:       checkID,
	}
}

// ageDays is a small helper for "N days" evidence strings.
func ageDays(d time.Duration) int { return int(d.Hours() / 24) }
