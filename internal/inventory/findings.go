package inventory

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/finding"
)

// Findings turns OSV hits into standard CVE findings: one per
// (vulnerability, component, path), ID "<CVE or OSV id>:<ecosystem>/<name>@<path>".
// Records that alias each other (GHSA + PYSEC for one CVE) collapse into
// one finding.
func Findings(hits []Hit, now time.Time) []finding.Finding {
	byID := map[string]int{}
	var out []finding.Finding
	for _, h := range hits {
		if h.Vuln == nil {
			continue
		}
		vid := canonicalID(h.Vuln)
		fixed := fixedVersion(h.Vuln, h.Component)
		sev, score := vulnSeverity(h.Vuln)
		paths := h.Component.Paths
		if len(paths) == 0 {
			paths = []string{""}
		}
		for _, p := range paths {
			id := fmt.Sprintf("%s:%s/%s@%s", vid, h.Component.Ecosystem, h.Component.Name, p)
			f := finding.Finding{
				ID:          id,
				Category:    finding.CategoryCVE,
				Severity:    sev,
				Title:       fmt.Sprintf("%s affects %s %s (%s)", vid, h.Component.Name, h.Component.Version, h.Component.Ecosystem),
				Evidence:    evidence(h, p),
				References:  references(h.Vuln),
				Remediation: remediation(h.Component, p, fixed),
				DetectedAt:  now,
				Package:     h.Component.Name,
				Installed:   h.Component.Version,
				FixedIn:     fixed,
				CVSS:        score,
				Source:      "osv",
			}
			if strings.HasPrefix(vid, "CVE-") {
				f.CVE = vid
			}
			if i, ok := byID[id]; ok {
				// Same CVE from another database: keep the richer record.
				if f.Severity.Rank() > out[i].Severity.Rank() || (out[i].FixedIn == "" && f.FixedIn != "") {
					f.Evidence = out[i].Evidence + "; also " + h.Vuln.ID
					out[i] = f
				} else if !strings.Contains(out[i].Evidence, h.Vuln.ID) {
					out[i].Evidence += "; also " + h.Vuln.ID
				}
				continue
			}
			byID[id] = len(out)
			out = append(out, f)
		}
	}
	return out
}

// canonicalID prefers the CVE alias, then the smallest of the record's
// own ID and aliases, so aliased records map to one finding.
func canonicalID(v *OSVVuln) string {
	ids := append([]string{v.ID}, v.Aliases...)
	sort.Strings(ids)
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return ids[0]
}

func evidence(h Hit, p string) string {
	c := h.Component
	var b strings.Builder
	fmt.Fprintf(&b, "path: %s; installed: %s %s (%s, %s, %s scope)", p, c.Name, c.Version, c.Ecosystem, c.Source, c.Scope)
	if c.Dev {
		b.WriteString("; development dependency")
	}
	if bin := c.Meta["binary"]; bin != "" && bin != p {
		fmt.Fprintf(&b, "; binary: %s", bin)
	}
	fmt.Fprintf(&b, "; osv: %s", h.Vuln.ID)
	if len(h.Vuln.Aliases) > 0 {
		fmt.Fprintf(&b, " (aliases %s)", strings.Join(h.Vuln.Aliases, ", "))
	}
	if s := strings.TrimSpace(h.Vuln.Summary); s != "" {
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		fmt.Fprintf(&b, "; %s", s)
	}
	return b.String()
}

func references(v *OSVVuln) []string {
	out := []string{"https://osv.dev/vulnerability/" + v.ID}
	for _, r := range v.References {
		if len(out) >= 8 {
			break
		}
		if r.Type == "ADVISORY" || r.Type == "FIX" || r.Type == "WEB" {
			out = append(out, r.URL)
		}
	}
	return out
}

// fixedVersion returns the lowest fixed version above the installed one
// among the record's ranges for this package (or the highest fix if none is
// above it, e.g. a pre-release mismatch).
func fixedVersion(v *OSVVuln, c Component) string {
	var fixes []string
	for _, a := range v.Affected {
		if a.Package.Ecosystem != c.Ecosystem || !samePkgName(c.Ecosystem, a.Package.Name, c.Name) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixes = append(fixes, strings.TrimPrefix(e.Fixed, "v"))
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}
	sort.Slice(fixes, func(i, j int) bool { return CompareVersions(fixes[i], fixes[j]) < 0 })
	for _, f := range fixes {
		if CompareVersions(f, c.Version) > 0 {
			return f
		}
	}
	return fixes[len(fixes)-1]
}

func samePkgName(eco, a, b string) bool {
	switch eco {
	case EcoPyPI:
		return normalizePyPI(a) == normalizePyPI(b)
	case EcoPackagist, EcoNuGet:
		return strings.EqualFold(a, b)
	}
	return a == b
}

// CompareVersions is a generic version ordering good enough to pick a fix
// (numeric segments compare numerically; a pre-release tag such as
// "-rc1", "a1", ".dev0" sorts before the release).
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var x, y vtok
		if i < len(ta) {
			x = ta[i]
		} else {
			x = vtok{num: true} // missing = 0 / release
		}
		if i < len(tb) {
			y = tb[i]
		} else {
			y = vtok{num: true}
		}
		if c := x.cmp(y); c != 0 {
			return c
		}
	}
	return 0
}

type vtok struct {
	num bool
	n   uint64
	s   string
}

func (x vtok) cmp(y vtok) int {
	switch {
	case x.num && y.num:
		switch {
		case x.n < y.n:
			return -1
		case x.n > y.n:
			return 1
		}
		return 0
	case x.num: // release/number beats pre-release text
		return 1
	case y.num:
		return -1
	}
	return strings.Compare(x.s, y.s)
}

func versionTokens(v string) []vtok {
	v = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata doesn't order
	}
	var out []vtok
	for i := 0; i < len(v); {
		ch := v[i]
		switch {
		case ch >= '0' && ch <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, _ := strconv.ParseUint(v[i:j], 10, 64)
			out = append(out, vtok{num: true, n: n})
			i = j
		case ch >= 'a' && ch <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			s := v[i:j]
			if s == "final" || s == "ga" || s == "release" {
				i = j
				continue
			}
			out = append(out, vtok{s: s})
			i = j
		default:
			i++
		}
	}
	// Trailing zeros are insignificant (1.0 == 1.0.0).
	for len(out) > 0 && out[len(out)-1].num && out[len(out)-1].n == 0 {
		out = out[:len(out)-1]
	}
	return out
}

// vulnSeverity maps GHSA-style database severity, else a CVSS v3 vector.
func vulnSeverity(v *OSVVuln) (finding.Severity, float64) {
	score := 0.0
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if sc, ok := CVSS3Score(s.Score); ok {
				score = sc
			}
		}
	}
	if s, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return finding.SeverityCritical, score
		case "HIGH":
			return finding.SeverityHigh, score
		case "MODERATE", "MEDIUM":
			return finding.SeverityMedium, score
		case "LOW":
			return finding.SeverityLow, score
		}
	}
	switch {
	case score >= 9:
		return finding.SeverityCritical, score
	case score >= 7:
		return finding.SeverityHigh, score
	case score >= 4:
		return finding.SeverityMedium, score
	case score > 0:
		return finding.SeverityLow, score
	}
	return finding.SeverityUnknown, score
}

// CVSS3Score computes the CVSS v3.x base score of a vector string.
func CVSS3Score(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	w := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	get := func(k string) (float64, bool) {
		x, ok := w[k][m[k]]
		return x, ok
	}
	av, ok1 := get("AV")
	ac, ok2 := get("AC")
	ui, ok3 := get("UI")
	c, ok4 := get("C")
	i, ok5 := get("I")
	a, ok6 := get("A")
	scope := m["S"]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || (scope != "U" && scope != "C") {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	if pr == 0 {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = math.Min(impact+expl, 10)
	} else {
		base = math.Min(1.08*(impact+expl), 10)
	}
	return roundUp1(base), true
}

// roundUp1 is the CVSS v3.1 Roundup function.
func roundUp1(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// remediation says what to upgrade, where, and with which tool.
func remediation(c Component, p, fixed string) string {
	target := "a fixed version"
	if fixed != "" {
		target = ">= " + fixed
	}
	where, file := projectDir(p)
	pin := c.Name
	if fixed != "" {
		pin = c.Name + "@" + fixed
	}
	var how string
	switch c.Ecosystem {
	case EcoNPM:
		switch {
		case file == "yarn.lock":
			how = "yarn upgrade " + pin + " (yarn up for Yarn 2+)"
		case file == "pnpm-lock.yaml":
			how = "pnpm update " + pin
		case strings.Contains(p, "/node_modules/") && file == "package.json" && c.Scope == ScopeSystem:
			how = "npm install -g " + pin
		default:
			how = "npm install " + pin + ", or npm audit fix"
		}
	case EcoPyPI:
		spec := c.Name
		if fixed != "" {
			spec = fmt.Sprintf("'%s>=%s'", c.Name, fixed)
		}
		switch file {
		case "poetry.lock":
			how = "poetry update " + c.Name
		case "Pipfile.lock":
			how = "pipenv update " + c.Name
		default:
			if strings.HasPrefix(file, "requirements") {
				how = "raise the pin in " + file + ", then pip install -r " + file
			} else {
				how = "pip install --upgrade " + spec + " in the same environment"
			}
		}
	case EcoPackagist:
		how = "composer update " + c.Name + " --with-dependencies"
		if c.Name == "pterodactyl/panel" {
			how = "follow the Pterodactyl panel upgrade guide"
		}
	case EcoMaven:
		how = "update the dependency in pom.xml / build.gradle and redeploy, or replace the jar"
	case EcoGo:
		if c.Name == "stdlib" {
			return fmt.Sprintf("rebuild %s with Go %s (go toolchain upgrade), or install an upstream release built with it", p, target)
		}
		how = fmt.Sprintf("go get %s && go build, or install an upstream release of %s that includes it", pin, p)
	case EcoCrates:
		if file == "Cargo.lock" {
			how = "cargo update -p " + c.Name
		} else {
			how = "rebuild with cargo update -p " + c.Name + ", or install an upstream release"
		}
	case EcoRubyGems:
		if file == "Gemfile.lock" || file == "gems.locked" {
			how = "bundle update " + c.Name
		} else {
			how = "gem update " + c.Name
		}
	case EcoNuGet:
		how = "dotnet add package " + c.Name + " --version " + strings.TrimPrefix(target, ">= ") + ", rebuild and redeploy"
	}
	s := fmt.Sprintf("upgrade %s to %s in %s", c.Name, target, where)
	if how != "" {
		s += " (" + how + ")"
	}
	return s
}

// projectDir maps a component path to the directory to run the fix in, and
// the lockfile name when there is one.
func projectDir(p string) (dir, file string) {
	if i := strings.Index(p, "!"); i >= 0 {
		p = p[:i] // inside an archive: the outer archive is what's deployed
		return p, path.Base(p)
	}
	if i := strings.Index(p, "/META-INF/maven/"); i >= 0 {
		return p[:i], "" // exploded archive: its root directory
	}
	if i := strings.Index(p, "/node_modules/"); i >= 0 {
		return p[:i], path.Base(p)
	}
	for _, marker := range []string{"/site-packages/", "/dist-packages/"} {
		if i := strings.Index(p, marker); i >= 0 {
			return p[:i+len(marker)-1], ""
		}
	}
	if strings.HasSuffix(p, "/vendor/composer/installed.json") {
		return strings.TrimSuffix(p, "/vendor/composer/installed.json"), "installed.json"
	}
	base := path.Base(p)
	switch {
	case strings.Contains(base, ".") || strings.HasPrefix(base, "requirements"):
		return path.Dir(p), base
	}
	return p, "" // a binary
}
