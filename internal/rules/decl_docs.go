package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ryan785/lync/internal/finding"
)

// CatalogFilter selects checks for `lync checks`.
type CatalogFilter struct {
	Pack     string // pack (or rule) name
	Tag      string
	Severity string // minimum severity
}

// FilterCatalog returns catalog entries matching f.
func FilterCatalog(f CatalogFilter) []CheckInfo {
	min := 0
	if f.Severity != "" {
		if s, ok := parseSeverity(f.Severity); ok {
			min = s.Rank()
		}
	}
	var out []CheckInfo
	for _, c := range Catalog() {
		if f.Pack != "" && !strings.EqualFold(c.PackName(), f.Pack) {
			continue
		}
		if f.Tag != "" {
			hit := false
			for _, t := range c.Tags {
				hit = hit || strings.EqualFold(t, f.Tag)
			}
			if !hit {
				continue
			}
		}
		if c.Severity.Rank() < min {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Explain renders everything known about one check ID.
func Explain(id string) (string, bool) {
	info, ok := CheckInfoOf(id)
	if !ok || (info.ID != id && !strings.HasPrefix(id, info.ID+":")) {
		return "", false
	}
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%-12s %s\n", k+":", v)
		}
	}
	line("ID", info.ID)
	line("Title", firstNonEmpty(info.Title, info.Description))
	line("Pack", info.PackName())
	line("Severity", string(info.Severity))
	line("Level", info.Level)
	line("Tags", strings.Join(info.Tags, ", "))
	line("Applies if", info.Applies)
	if info.DefaultOff {
		line("Default", "off (enable with rules.enable)")
	}
	c, decl := LookupCheck(info.ID)
	if !decl {
		line("Detects", info.Description)
		line("Source", "built-in Go rule "+info.Rule)
		return b.String(), true
	}
	line("Detects", c.Description)
	line("Probe", c.Probe.describe())
	if len(c.Where) > 0 {
		line("Where", strings.Join(c.Where, "; "))
	}
	if c.ExpectNone {
		line("Fails when", "any observation matches")
	} else {
		line("Expects", strings.Join(c.Expect, "; "))
	}
	line("Remediation", c.Remediation)
	line("Fix", c.Fix)
	refs := append(append([]string{}, c.References...), c.pack.References...)
	line("References", strings.Join(refs, "\n             "))
	line("Defined in", c.pack.source)
	return b.String(), true
}

// SeverityCounts tallies the catalog by pack and severity (for reports and docs).
func SeverityCounts() (map[string]map[finding.Severity]int, int) {
	out := map[string]map[finding.Severity]int{}
	n := 0
	for _, c := range Catalog() {
		p := c.PackName()
		if out[p] == nil {
			out[p] = map[finding.Severity]int{}
		}
		out[p][c.Severity]++
		n++
	}
	return out, n
}

var sevOrder = []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

// ChecksMarkdown renders docs/CHECKS.md from the catalog.
func ChecksMarkdown() string {
	var b strings.Builder
	counts, total := SeverityCounts()
	b.WriteString("# Checks reference\n\n")
	b.WriteString("<!-- Generated from the check catalog by `go run ./internal/checks/gendoc`; do not edit by hand. -->\n\n")
	b.WriteString("Every non-CVE check Lync runs. The ID is the prefix of every finding the check emits (`web:sensitive-file` -> `web:sensitive-file:/var/www/site/.env`), so it is what you put in `rules.disable` / `rules.enable`; `pack:<name>` and `tag:<tag>` toggle whole packs or tags. `lync checks` lists them with their state under your config and `lync checks --explain ID` shows the probe, expectation, remediation and references.\n\n")
	b.WriteString("Severity is the typical/maximum; some checks adjust it with context. Level is the minimum `rules.level` (basic, medium, strict) at which a check runs. \"opt-in\" checks run only when listed in `rules.enable`. \"Applies if\" is the gate: a check whose gate doesn't match the host is reported as not applicable, never as a finding.\n\n")
	b.WriteString("## Summary\n\n| Pack | Checks | Critical | High | Medium | Low | Info |\n|---|---|---|---|---|---|---|\n")
	packs := sortedKeys(counts)
	sum := map[finding.Severity]int{}
	for _, p := range packs {
		fmt.Fprintf(&b, "| %s | %d", p, func() int {
			n := 0
			for _, v := range counts[p] {
				n += v
			}
			return n
		}())
		for _, s := range sevOrder {
			fmt.Fprintf(&b, " | %d", counts[p][s])
			sum[s] += counts[p][s]
		}
		b.WriteString(" |\n")
	}
	fmt.Fprintf(&b, "| **total** | **%d**", total)
	for _, s := range sevOrder {
		fmt.Fprintf(&b, " | %d", sum[s])
	}
	b.WriteString(" |\n\n")

	titles := map[string]string{}
	for _, p := range Packs() {
		titles[p.Name] = p.Title
	}
	byPack := map[string][]CheckInfo{}
	for _, c := range Catalog() {
		byPack[c.PackName()] = append(byPack[c.PackName()], c)
	}
	for _, p := range packs {
		title := titles[p]
		if title == "" {
			title = "Go rule"
		}
		fmt.Fprintf(&b, "## %s (`%s`)\n\n", title, p)
		cs := byPack[p]
		sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
		b.WriteString("| ID | Severity | Level | Detects | Applies if |\n|---|---|---|---|---|\n")
		for _, c := range cs {
			desc := firstNonEmpty(c.Title, c.Description)
			if c.DefaultOff {
				desc += " **(opt-in)**"
			}
			lvl := c.Level
			if lvl == "" {
				lvl = "-"
			}
			app := c.Applies
			if app == "" {
				app = "-"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", c.ID, c.Severity, lvl, mdEscape(desc), mdEscape(app))
		}
		b.WriteString("\n")
	}
	b.WriteString("## How checks read the host\n\n")
	b.WriteString("All checks read through `rules.Host`: files are host paths mapped under `rules.root` (default `/`), tools run with a 20 s timeout, and a missing file or tool means \"skipped\" or \"not applicable\", never a failed scan or a guessed finding. Nothing is modified. Pack checks can only run commands from a fixed read-only allowlist (`sshd -T`, `nginx -T`, `systemctl show`, `docker inspect`, ...). Evidence is redacted: values of password/token/secret-like keys, private keys, URL credentials and known token formats are masked. The only check that executes inside something else is `container:php-upload-progress` (`docker exec ... php -r`), which is why it is opt-in.\n")
	return b.String()
}
