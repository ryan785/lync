package rules

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/checks"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// DefaultCheckDirs are searched for local packs (*.yaml) when
// Options.CheckDirs is nil. Files must be root-owned and not
// group/world-writable.
var DefaultCheckDirs = []string{"/etc/lync/checks.d"}

// ---- registry ---------------------------------------------------------------

var declReg = struct {
	sync.RWMutex
	packs  []*Pack
	byID   map[string]*Check
	errs   []error
	loaded map[string]bool // external pack files already registered
}{byID: map[string]*Check{}, loaded: map[string]bool{}}

func init() {
	es, err := fs.ReadDir(checks.Packs, "packs")
	if err != nil {
		declReg.errs = append(declReg.errs, err)
		return
	}
	for _, e := range es {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := fs.ReadFile(checks.Packs, "packs/"+e.Name())
		if err != nil {
			declReg.errs = append(declReg.errs, err)
			continue
		}
		p, err := parsePack(e.Name(), b)
		if err == nil {
			err = addPack(p)
		}
		if err != nil {
			declReg.errs = append(declReg.errs, err)
		}
	}
}

// addPack registers a parsed pack (all checks or none).
func addPack(p *Pack) error {
	declReg.Lock()
	defer declReg.Unlock()
	for _, c := range p.Checks {
		if _, dup := declReg.byID[c.ID]; dup {
			return fmt.Errorf("%s: check id %s already defined", p.source, c.ID)
		}
		catalogMu.Lock()
		_, dup := catalog[c.ID]
		catalogMu.Unlock()
		if dup {
			return fmt.Errorf("%s: check id %s collides with a built-in check", p.source, c.ID)
		}
	}
	for _, other := range declReg.packs {
		if other.Name == p.Name {
			return fmt.Errorf("%s: pack %s already defined in %s", p.source, p.Name, other.source)
		}
	}
	declReg.packs = append(declReg.packs, p)
	sort.Slice(declReg.packs, func(i, j int) bool { return declReg.packs[i].Name < declReg.packs[j].Name })
	for _, c := range p.Checks {
		declReg.byID[c.ID] = c
		register(CheckInfo{
			ID: c.ID, Rule: "checks", Pack: p.Name, Severity: c.sev, Title: c.Title, Description: firstNonEmpty(c.Description, c.Title),
			DefaultOff: c.DefaultOff, Tags: c.Tags, Applies: c.AppliesSummary(), Level: c.level.String(), aliases: p.Aliases,
		})
	}
	return nil
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// PackErrors returns built-in pack load errors (tests require none).
func PackErrors() []error {
	declReg.RLock()
	defer declReg.RUnlock()
	return append([]error(nil), declReg.errs...)
}

// Packs returns every registered pack sorted by name.
func Packs() []*Pack {
	declReg.RLock()
	defer declReg.RUnlock()
	return append([]*Pack(nil), declReg.packs...)
}

// LookupCheck returns a declarative check by ID.
func LookupCheck(id string) (*Check, bool) {
	declReg.RLock()
	defer declReg.RUnlock()
	c, ok := declReg.byID[id]
	return c, ok
}

// LoadCheckDirs registers local packs from dirs (once per file). Unsafe or
// invalid files are reported and skipped; built-in checks are never
// replaced.
func LoadCheckDirs(dirs []string) []error {
	var errs []error
	for _, d := range dirs {
		es, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range es {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				continue
			}
			f := filepath.Join(d, e.Name())
			declReg.RLock()
			done := declReg.loaded[f]
			declReg.RUnlock()
			if done {
				continue
			}
			declReg.Lock()
			declReg.loaded[f] = true
			declReg.Unlock()
			if err := safePackFile(f); err != nil {
				errs = append(errs, err)
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			p, err := parsePack(f, b)
			if err == nil {
				err = addPack(p)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

// safePackFile refuses pack files (and their directory) that a non-root
// user could have written: a pack decides which commands lyncd runs.
func safePackFile(f string) error {
	for _, p := range []string{filepath.Dir(f), f} {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		uid, _, ok := fileOwner(fi)
		if !ok {
			continue // platform without POSIX owners (tests on Windows)
		}
		if uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: ignored, must be owned by root and not group/world-writable", p)
		}
	}
	return nil
}

// ---- rule -------------------------------------------------------------------

// DeclarativeRule evaluates every registered pack.
type DeclarativeRule struct {
	mu   sync.Mutex
	last []finding.PackCoverage
}

func NewDeclarativeRule() *DeclarativeRule { return &DeclarativeRule{} }

func (r *DeclarativeRule) Name() string { return "checks" }

// Coverage returns the per-pack summary of the last Run.
func (r *DeclarativeRule) Coverage() []finding.PackCoverage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]finding.PackCoverage(nil), r.last...)
}

type checkResult struct {
	status   string // na | pass | fail | skip | off
	reason   string
	findings []finding.Finding
}

func (r *DeclarativeRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	dirs := opts.CheckDirs
	if dirs == nil {
		dirs = DefaultCheckDirs
	}
	for _, err := range LoadCheckDirs(dirs) {
		log.Warn("check pack not loaded", "err", err)
	}
	env := newEvalEnv(opts.host(), facts, opts)
	packs := Packs()
	type job struct {
		pi, ci int
		c      *Check
	}
	results := make([][]checkResult, len(packs))
	var jobs []job
	for pi, p := range packs {
		results[pi] = make([]checkResult, len(p.Checks))
		for ci, c := range p.Checks {
			jobs = append(jobs, job{pi, ci, c})
		}
	}
	level := opts.Level
	if level == 0 {
		level = LevelMedium
	}
	ch := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				switch {
				case !opts.Toggles.CheckEnabled(j.c.ID):
					results[j.pi][j.ci] = checkResult{status: "off", reason: "disabled by config"}
				case j.c.level > level:
					results[j.pi][j.ci] = checkResult{status: "off", reason: "level " + j.c.level.String()}
				default:
					results[j.pi][j.ci] = env.evalCheckSafe(ctx, j.c)
				}
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()

	var out []finding.Finding
	var cov []finding.PackCoverage
	for pi, p := range packs {
		pc := finding.PackCoverage{Pack: p.Name, Title: p.Title, Checks: len(p.Checks)}
		for ci, res := range results[pi] {
			switch res.status {
			case "off":
				pc.Disabled++
			case "na":
				pc.NotApplicable++
			case "pass":
				pc.Applicable++
				pc.Passed++
			case "fail":
				pc.Applicable++
				pc.Failed++
				out = append(out, res.findings...)
			case "skip":
				pc.Applicable++
				pc.Skipped++
				pc.Skips = append(pc.Skips, finding.CheckSkip{Check: p.Checks[ci].ID, Reason: res.reason})
				audit.Log("CHECK", "%s skipped: %s", p.Checks[ci].ID, res.reason)
			}
		}
		cov = append(cov, pc)
	}
	r.mu.Lock()
	r.last = cov
	r.mu.Unlock()
	return out
}

func (env *evalEnv) evalCheckSafe(ctx context.Context, c *Check) (res checkResult) {
	defer func() {
		if v := recover(); v != nil {
			res = checkResult{status: "skip", reason: fmt.Sprintf("internal error: %v", v)}
		}
	}()
	return env.evalCheck(ctx, c)
}

// ---- environment and gates --------------------------------------------------

type evalEnv struct {
	h     *Host
	facts *collector.Facts
	opts  Options
	pkgs  map[string]bool
}

func newEvalEnv(h *Host, facts *collector.Facts, opts Options) *evalEnv {
	if facts == nil {
		facts = &collector.Facts{}
	}
	env := &evalEnv{h: h, facts: facts, opts: opts, pkgs: map[string]bool{}}
	for _, p := range facts.Packages {
		env.pkgs[p.Name] = true
	}
	return env
}

var binDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system"}

var rhelIDs = map[string]bool{"rhel": true, "centos": true, "rocky": true, "almalinux": true, "ol": true, "scientific": true, "amzn": true, "cloudlinux": true, "eurolinux": true}

func (env *evalEnv) osMatch(want string) bool {
	want = strings.ToLower(want)
	os := env.facts.OS
	if os.ID == "" {
		return false
	}
	if os.ID == want {
		return true
	}
	like := map[string]bool{}
	for _, l := range os.IDLike {
		like[l] = true
	}
	switch want {
	case "rhel":
		return rhelIDs[os.ID] || like["rhel"] || like["centos"]
	case "debian":
		return like["debian"] || like["ubuntu"]
	case "suse":
		return strings.Contains(os.ID, "suse") || os.ID == "sles" || like["suse"]
	}
	return like[want]
}

func (env *evalEnv) osMatchAny(ws []string) bool {
	if len(ws) == 0 {
		return true
	}
	for _, w := range ws {
		if env.osMatch(w) {
			return true
		}
	}
	return false
}

func (env *evalEnv) osVersionCmp(v string) int { return versionCmp(env.facts.OS.VersionID, v) }

func (env *evalEnv) unitActive(ctx context.Context, u string) bool {
	if !strings.Contains(u, ".") {
		u += ".service"
	}
	out, _ := env.runCached(ctx, "systemctl", "is-active", u)
	return strings.TrimSpace(out) == "active"
}

func (env *evalEnv) unitPresent(u string) bool {
	if !strings.Contains(u, ".") {
		u += ".service"
	}
	for _, d := range unitDirs {
		if env.h.Exists(d + "/" + u) {
			return true
		}
	}
	return false
}

func (env *evalEnv) binaryPresent(b string) bool {
	for _, d := range binDirs {
		if env.h.Exists(d + "/" + b) {
			return true
		}
	}
	return false
}

// gate evaluates a gate; the reason explains a false result.
func (env *evalEnv) gate(ctx context.Context, g *Gate) (bool, string) {
	if g == nil {
		return true, ""
	}
	anyOf := func(label string, vs []string, f func(string) bool) (bool, string) {
		if len(vs) == 0 {
			return true, ""
		}
		for _, v := range vs {
			if f(v) {
				return true, ""
			}
		}
		return false, label + " " + strings.Join(vs, "|") + " not found"
	}
	checks := []func() (bool, string){
		func() (bool, string) {
			return anyOf("package", g.Package, func(p string) bool { return env.pkgs[p] })
		},
		func() (bool, string) { return anyOf("binary", g.Binary, env.binaryPresent) },
		func() (bool, string) { return anyOf("unit", g.Unit, env.unitPresent) },
		func() (bool, string) {
			return anyOf("active unit", g.UnitActive, func(u string) bool { return env.unitActive(ctx, u) })
		},
		func() (bool, string) {
			return anyOf("file", g.File, func(f string) bool { return len(env.expand([]string{f})) > 0 })
		},
		func() (bool, string) {
			return anyOf("process", g.Process, func(n string) bool {
				for _, p := range env.processes() {
					if p.comm == n {
						return true
					}
				}
				return false
			})
		},
		func() (bool, string) {
			if len(g.Listening) == 0 {
				return true, ""
			}
			ls, _ := env.h.Listeners(ctx)
			for _, port := range g.Listening {
				if listeningOn(ls, "", port) {
					return true, ""
				}
			}
			return false, fmt.Sprintf("nothing listening on %v", []int(g.Listening))
		},
		func() (bool, string) {
			if env.osMatchAny(g.OS) {
				return true, ""
			}
			return false, "os is " + env.facts.OS.ID + ", check is for " + strings.Join(g.OS, "|")
		},
		func() (bool, string) {
			if g.OSVersionGE != "" && env.osVersionCmp(g.OSVersionGE) < 0 {
				return false, "os version " + env.facts.OS.VersionID + " < " + g.OSVersionGE
			}
			if g.OSVersionLT != "" && (env.facts.OS.VersionID == "" || env.osVersionCmp(g.OSVersionLT) >= 0) {
				return false, "os version " + env.facts.OS.VersionID + " >= " + g.OSVersionLT
			}
			return true, ""
		},
	}
	for _, c := range checks {
		if ok, why := c(); !ok {
			return false, why
		}
	}
	for _, s := range g.All {
		if ok, why := env.gate(ctx, s); !ok {
			return false, why
		}
	}
	if len(g.Any) > 0 {
		var whys []string
		hit := false
		for _, s := range g.Any {
			ok, why := env.gate(ctx, s)
			if ok {
				hit = true
				break
			}
			whys = append(whys, why)
		}
		if !hit {
			return false, strings.Join(whys, "; ")
		}
	}
	if g.Not != nil {
		if ok, _ := env.gate(ctx, g.Not); ok {
			return false, "excluded: " + g.Not.Summary()
		}
	}
	return true, ""
}

// ---- conditions -------------------------------------------------------------

var truthy = map[string]bool{"1": true, "on": true, "yes": true, "true": true}

func parseNum(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if b, ok := map[string]float64{"on": 1, "off": 0, "yes": 1, "no": 0, "true": 1, "false": 0}[strings.ToLower(s)]; ok {
		return b, true
	}
	n, err := strconv.ParseFloat(s, 64)
	return n, err == nil
}

func listTokens(s string) map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		m[t] = true
	}
	return m
}

// eval returns (holds, known). A missing field or a non-numeric value for
// a numeric operator is unknown, never a failure.
func (c cond) eval(o obs) (bool, bool) {
	v, present := o[c.field]
	if !present {
		// An absent field is empty; every other operator can't decide.
		switch c.op {
		case "empty":
			return true, true
		case "not_empty":
			return false, true
		}
		return false, false
	}
	lv := strings.ToLower(strings.TrimSpace(v))
	switch c.op {
	case "eq":
		return lv == strings.ToLower(c.arg), true
	case "ne":
		return lv != strings.ToLower(c.arg), true
	case "in", "not_in":
		hit := false
		for _, a := range c.args {
			hit = hit || lv == a
		}
		return hit == (c.op == "in"), true
	case "regex":
		return c.re.MatchString(v), true
	case "not_regex":
		return !c.re.MatchString(v), true
	case "contains":
		return strings.Contains(lv, strings.ToLower(c.arg)), true
	case "not_contains":
		return !strings.Contains(lv, strings.ToLower(c.arg)), true
	case "empty":
		return lv == "", true
	case "not_empty":
		return lv != "", true
	case "lt", "le", "gt", "ge":
		if lv == "" {
			return false, true // unset never satisfies a numeric bound
		}
		n, ok := parseNum(v)
		if !ok {
			return false, false
		}
		switch c.op {
		case "lt":
			return n < c.num, true
		case "le":
			return n <= c.num, true
		case "gt":
			return n > c.num, true
		}
		return n >= c.num, true
	case "version_lt", "version_le", "version_gt", "version_ge":
		if lv == "" {
			return false, false
		}
		r := versionCmp(v, c.arg)
		switch c.op {
		case "version_lt":
			return r < 0, true
		case "version_le":
			return r <= 0, true
		case "version_gt":
			return r > 0, true
		}
		return r >= 0, true
	case "perm_max", "bits_all", "bits_none", "bits_any":
		n, err := strconv.ParseUint(lv, 8, 32)
		if err != nil {
			return false, false
		}
		switch c.op {
		case "perm_max":
			return n&^c.bits == 0, true
		case "bits_all":
			return n&c.bits == c.bits, true
		case "bits_none":
			return n&c.bits == 0, true
		}
		return n&c.bits != 0, true
	case "has_all", "has_any", "has_none":
		toks := listTokens(v)
		cnt := 0
		for _, a := range c.args {
			if toks[a] {
				cnt++
			}
		}
		switch c.op {
		case "has_all":
			return cnt == len(c.args), true
		case "has_any":
			return cnt > 0, true
		}
		return cnt == 0, true
	}
	return false, false
}

func (g condGroup) eval(o obs) (bool, bool) {
	known := true
	for _, c := range g {
		ok, k := c.eval(o)
		if k && ok {
			return true, true
		}
		known = known && k
	}
	return false, known
}

func (g condGroup) String() string {
	var parts []string
	for _, c := range g {
		parts = append(parts, c.text)
	}
	return strings.Join(parts, " or ")
}

// ---- evaluation -------------------------------------------------------------

func (env *evalEnv) evalCheck(ctx context.Context, c *Check) checkResult {
	if ok, why := env.gate(ctx, c.pack.AppliesIf); !ok {
		return checkResult{status: "na", reason: why}
	}
	if ok, why := env.gate(ctx, c.AppliesIf); !ok {
		return checkResult{status: "na", reason: why}
	}
	pr := env.runProbe(ctx, &c.Probe)
	if pr.skip != "" {
		return checkResult{status: "skip", reason: pr.skip}
	}
	var selected []obs
	for _, o := range pr.obs {
		keep := true
		for _, w := range c.where {
			if ok, known := w.eval(o); !ok || !known {
				keep = false
				break
			}
		}
		if keep {
			selected = append(selected, o)
		}
	}
	if len(selected) == 0 {
		switch c.Missing {
		case "fail":
			o := obs{fLoc: "not found"}
			ev := firstNonEmpty(c.MissingEvidence, "nothing matched: "+c.Probe.describe())
			return checkResult{status: "fail", findings: []finding.Finding{env.mkDeclFinding(ctx, c, o, ev)}}
		case "skip":
			return checkResult{status: "skip", reason: "nothing to evaluate: " + c.Probe.describe()}
		}
		return checkResult{status: "pass"}
	}
	byID := map[string]*finding.Finding{}
	var order []string
	unknown := 0
	for _, o := range selected {
		var failed []condGroup
		if !c.ExpectNone {
			unk := false
			for _, e := range c.expect {
				ok, known := e.eval(o)
				if !known {
					unk = true
					break
				}
				if !ok {
					failed = append(failed, e)
				}
			}
			if unk {
				unknown++
				continue
			}
			if len(failed) == 0 {
				continue
			}
		}
		ev := env.evidence(c, o, failed)
		f := env.mkDeclFinding(ctx, c, o, ev)
		if prev, ok := byID[f.ID]; ok {
			if len(prev.Evidence) < 2000 && !strings.Contains(prev.Evidence, f.Evidence) {
				prev.Evidence += "; " + f.Evidence
			}
			if f.Severity.Rank() > prev.Severity.Rank() {
				prev.Severity = f.Severity
			}
			continue
		}
		byID[f.ID] = &f
		order = append(order, f.ID)
	}
	if len(order) == 0 {
		if unknown == len(selected) {
			return checkResult{status: "skip", reason: "values could not be evaluated: " + c.Probe.describe()}
		}
		return checkResult{status: "pass"}
	}
	res := checkResult{status: "fail"}
	for _, id := range order {
		res.findings = append(res.findings, *byID[id])
	}
	return res
}

func (p *Probe) describe() string {
	switch {
	case p.Key != "":
		return p.Type + " " + p.Format + " " + p.Key
	case len(p.Name) > 0:
		return p.Type + " " + strings.Join(p.Name, ",")
	case len(p.Paths) > 0:
		return p.Type + " " + strings.Join(p.Paths, ",")
	case len(p.Cmd) > 0:
		return strings.Join(p.Cmd, " ")
	}
	return p.Type
}

var placeholderRE = regexp.MustCompile(`\{([a-zA-Z0-9_.\[\]-]+)\}`)

// tpl fills {field} placeholders from an observation (secret probes never
// substitute "value").
func tpl(s string, o obs, secret bool) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		k := m[1 : len(m)-1]
		if k == "key" {
			k = fKey
		}
		v, ok := o[k]
		if !ok {
			return m
		}
		if secret && (k == "value" || k == "line" || k == "output") {
			return "<redacted>"
		}
		return v
	})
}

func (env *evalEnv) evidence(c *Check, o obs, failed []condGroup) string {
	if c.Evidence != "" {
		return redact(tpl(c.Evidence, o, c.Probe.Secret))
	}
	conds := failed
	if c.ExpectNone {
		conds = c.where
	}
	var parts []string
	seen := map[string]bool{}
	for _, g := range conds {
		for _, cd := range g {
			if seen[cd.field] {
				continue
			}
			seen[cd.field] = true
			v, ok := o[cd.field]
			if !ok {
				continue
			}
			if c.Probe.Secret && (cd.field == "value" || cd.field == "line" || cd.field == "output") {
				v = "<redacted>"
			}
			if v == "" {
				v = `""`
			}
			parts = append(parts, cd.field+"="+truncate(v, 200))
		}
	}
	ev := o[fLoc]
	if len(parts) > 0 {
		ev += ": " + strings.Join(parts, ", ")
	}
	if !c.ExpectNone && len(failed) > 0 {
		var exp []string
		for _, g := range failed {
			exp = append(exp, g.String())
		}
		ev += " (expected " + strings.Join(exp, "; ") + ")"
	}
	return redact(ev)
}

func (env *evalEnv) mkDeclFinding(ctx context.Context, c *Check, o obs, evidence string) finding.Finding {
	sev := c.sev
	for _, r := range c.SeverityIf {
		if r.cond != nil {
			if ok, known := r.cond.eval(o); !ok || !known {
				continue
			}
		}
		if r.If != nil {
			if ok, _ := env.gate(ctx, r.If); !ok {
				continue
			}
		}
		sev = r.sev
		break
	}
	id := c.ID
	if k := o[fKey]; k != "" {
		id += ":" + k
	}
	fix := strings.TrimSpace(tpl(c.Remediation, o, c.Probe.Secret))
	if c.Fix != "" {
		fix += " Fix: " + tpl(c.Fix, o, c.Probe.Secret)
	}
	refs := append(append([]string{}, c.References...), c.pack.References...)
	return finding.Finding{
		ID: id, Category: c.cat, Severity: sev,
		Title:       redact(tpl(c.Title, o, c.Probe.Secret)),
		Evidence:    evidence,
		Remediation: fix,
		References:  refs,
		DetectedAt:  env.h.now(),
		Source:      "lync-rules",
		Check:       c.ID,
		Pack:        c.pack.Name,
	}
}

// ---- redaction --------------------------------------------------------------

var (
	redactKVRE  = regexp.MustCompile(`(?i)([A-Za-z0-9_.\[\]-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?key|requirepass|masterauth|community|psk|pwd)[A-Za-z0-9_.\[\]-]*)(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|[^\s,;)]+)`)
	redactPEMRE = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
	redactURLRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):[^@\s/]+@`)
	redactTokRE = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})`)
	notSecretRE = regexp.MustCompile(`(?i)^(yes|no|on|off|true|false|none|null|nil|enabled?|disabled?|required|optional|prohibit-password|without-password|forced-commands-only|<redacted>|"?"?|''|[0-9]{1,3}|[/$<~].*)$`)
)

// redact masks secret-looking values in evidence: key=value pairs whose
// key names a secret, private keys, URL credentials and known token formats.
func redact(s string) string {
	s = redactPEMRE.ReplaceAllString(s, "<redacted private key>")
	s = redactURLRE.ReplaceAllString(s, "$1:<redacted>@")
	s = redactTokRE.ReplaceAllString(s, "<redacted token>")
	var b strings.Builder
	last := 0
	for _, m := range redactKVRE.FindAllStringSubmatchIndex(s, -1) {
		key, sep, val := s[m[2]:m[3]], s[m[4]:m[5]], s[m[6]:m[7]]
		// A key that is the tail of a path (/etc/pam.d/common-password: ...)
		// names a file, not a secret.
		if notSecretRE.MatchString(val) || (m[0] > 0 && s[m[0]-1] == '/') {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(key + sep + "<redacted>")
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}
