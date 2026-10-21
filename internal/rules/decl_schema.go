package rules

// Declarative checks: the data model. A pack is one YAML file holding a
// list of checks for one service or area (sshd, nginx, sysctl...). Each
// check gates itself (applies_if), runs one read-only probe, filters the
// probe's observations (where) and asserts the safe state (expect) on
// each. Every check carries test vectors that the generic test in
// decl_test.go runs. docs/EXTENDING.md documents the format.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ryan785/lync/internal/finding"
)

// strList accepts a scalar or a sequence.
type strList []string

func (s *strList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = strList{n.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := n.Decode(&l); err != nil {
			return err
		}
		*s = l
		return nil
	}
	return fmt.Errorf("line %d: want a string or a list of strings", n.Line)
}

// intList accepts a scalar or a sequence of integers.
type intList []int

func (s *intList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v int
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = intList{v}
		return nil
	case yaml.SequenceNode:
		var l []int
		if err := n.Decode(&l); err != nil {
			return err
		}
		*s = l
		return nil
	}
	return fmt.Errorf("line %d: want an integer or a list of integers", n.Line)
}

// Pack is one YAML file.
type Pack struct {
	Name        string   `yaml:"pack"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Aliases     strList  `yaml:"aliases"` // legacy rule names accepted by rules.disable
	Category    string   `yaml:"category"`
	AppliesIf   *Gate    `yaml:"applies_if"`
	References  strList  `yaml:"references"`
	TestBase    *Vector  `yaml:"test_base"`
	Checks      []*Check `yaml:"checks"`

	source string // file name, for errors and `lync checks --explain`
}

// Gate decides whether a check applies to this host. Fields set in one
// gate must all hold; values inside a field are alternatives.
type Gate struct {
	All         []*Gate `yaml:"all"`
	Any         []*Gate `yaml:"any"`
	Not         *Gate   `yaml:"not"`
	Package     strList `yaml:"package"`     // installed package (exact name)
	Binary      strList `yaml:"binary"`      // executable in a standard bin dir
	Unit        strList `yaml:"unit"`        // systemd unit file present
	UnitActive  strList `yaml:"unit_active"` // systemctl is-active == active
	File        strList `yaml:"file"`        // path/glob exists
	Listening   intList `yaml:"listening"`   // any socket on this port
	Process     strList `yaml:"process"`     // running process comm (exact)
	OS          strList `yaml:"os"`          // family (rhel, debian, ubuntu, alpine, suse, fedora) or os-release ID
	OSVersionGE string  `yaml:"os_version_ge"`
	OSVersionLT string  `yaml:"os_version_lt"`
}

// OSDefault is a per-distro/version default for a config key.
type OSDefault struct {
	OS        strList `yaml:"os"`
	VersionGE string  `yaml:"version_ge"`
	VersionLT string  `yaml:"version_lt"`
	Value     string  `yaml:"value"`
}

// Probe is what a check reads. Which fields matter depends on Type; see
// probeDocs (decl_probes.go) and docs/EXTENDING.md.
type Probe struct {
	Type       string      `yaml:"type"`
	Paths      strList     `yaml:"path"`
	Format     string      `yaml:"format"`
	Key        string      `yaml:"key"`
	Keys       strList     `yaml:"keys"`
	Section    string      `yaml:"section"`
	Default    *string     `yaml:"default"`
	Defaults   []OSDefault `yaml:"defaults"`
	PerFile    bool        `yaml:"per_file"`
	Split      string      `yaml:"split"`
	Regex      string      `yaml:"regex"`
	Combine    bool        `yaml:"combine"`
	Name       strList     `yaml:"name"`
	Properties strList     `yaml:"properties"`
	Cmd        strList     `yaml:"cmd"`
	Lines      bool        `yaml:"lines"`
	LineRegex  string      `yaml:"line_regex"`
	Ports      intList     `yaml:"ports"`
	Proto      string      `yaml:"proto"`
	Process    string      `yaml:"process"`
	Roots      strList     `yaml:"roots"`
	Match      strList     `yaml:"match"`
	Prune      strList     `yaml:"prune"`
	MaxDepth   int         `yaml:"max_depth"`
	MaxEntries int         `yaml:"max_entries"`
	FileType   string      `yaml:"file_type"`
	From       strList     `yaml:"from"`
	Runtime    string      `yaml:"runtime"`
	Secret     bool        `yaml:"secret"`
	NoFollow   bool        `yaml:"no_follow"`
	MaxBytes   int64       `yaml:"max_bytes"`

	re     *regexp.Regexp
	lineRE *regexp.Regexp
}

// SevRule overrides the severity for observations matching When (and/or
// hosts matching If).
type SevRule struct {
	When     string `yaml:"when"`
	If       *Gate  `yaml:"if"`
	Severity string `yaml:"severity"`

	cond condGroup
	sev  finding.Severity
}

// Vector is a test fixture: a tiny fake host.
type Vector struct {
	Name     string            `yaml:"name"`
	Files    map[string]string `yaml:"files"`
	Meta     map[string]string `yaml:"meta"`  // path: "[dls]0644 uid gid"
	Links    map[string]string `yaml:"links"` // symlink path: target
	Cmds     map[string]string `yaml:"cmds"`  // "name arg..." : stdout
	Packages map[string]string `yaml:"packages"`
	OS       string            `yaml:"os"` // "rocky:9.4"
	Severity string            `yaml:"severity"`
	Findings int               `yaml:"findings"` // expected count (fail vectors; 0 = at least one)
}

type vectorList []*Vector

func (v *vectorList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		var one Vector
		if err := n.Decode(&one); err != nil {
			return err
		}
		*v = vectorList{&one}
		return nil
	}
	var l []*Vector
	if err := n.Decode(&l); err != nil {
		return err
	}
	*v = l
	return nil
}

// Tests are a check's embedded vectors: pass = applicable and no finding,
// fail = at least one finding, na = gated out, skip = probe can't decide.
type Tests struct {
	Pass vectorList `yaml:"pass"`
	Fail vectorList `yaml:"fail"`
	NA   vectorList `yaml:"na"`
	Skip vectorList `yaml:"skip"`
}

// Check is one declarative check.
type Check struct {
	ID              string    `yaml:"id"`
	Title           string    `yaml:"title"`
	Description     string    `yaml:"description"`
	Severity        string    `yaml:"severity"`
	Level           string    `yaml:"level"`
	Category        string    `yaml:"category"`
	Tags            strList   `yaml:"tags"`
	AppliesIf       *Gate     `yaml:"applies_if"`
	Probe           Probe     `yaml:"probe"`
	Where           strList   `yaml:"where"`
	Expect          strList   `yaml:"expect"`
	ExpectNone      bool      `yaml:"expect_none"`
	Missing         string    `yaml:"missing"`
	MissingEvidence string    `yaml:"missing_evidence"`
	SeverityIf      []SevRule `yaml:"severity_if"`
	Evidence        string    `yaml:"evidence"`
	Remediation     string    `yaml:"remediation"`
	Fix             string    `yaml:"fix"`
	References      strList   `yaml:"references"`
	DefaultOff      bool      `yaml:"default_off"`
	Tests           Tests     `yaml:"tests"`

	pack   *Pack
	sev    finding.Severity
	level  Level
	cat    finding.Category
	where  []condGroup
	expect []condGroup
}

// ---- conditions -------------------------------------------------------------

// cond is "<field> <op> [arg]".
type cond struct {
	text  string
	field string
	op    string
	arg   string
	args  []string
	re    *regexp.Regexp
	num   float64
	bits  uint64
}

// condGroup is a list of alternatives ("a || b").
type condGroup []cond

var condOps = map[string]int{ // op -> arity (0 unary, 1 binary)
	"eq": 1, "ne": 1, "in": 1, "not_in": 1, "regex": 1, "not_regex": 1,
	"lt": 1, "le": 1, "gt": 1, "ge": 1,
	"version_lt": 1, "version_le": 1, "version_gt": 1, "version_ge": 1,
	"perm_max": 1, "bits_all": 1, "bits_none": 1, "bits_any": 1,
	"contains": 1, "not_contains": 1, "has_all": 1, "has_any": 1, "has_none": 1,
	"empty": 0, "not_empty": 0,
}

func parseCondGroup(s string) (condGroup, error) {
	var g condGroup
	for _, part := range strings.Split(s, "||") {
		c, err := parseCond(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		g = append(g, c)
	}
	return g, nil
}

func parseCond(s string) (cond, error) {
	c := cond{text: s}
	f := strings.Fields(s)
	if len(f) < 2 {
		return c, fmt.Errorf("condition %q: want \"<field> <op> [value]\"", s)
	}
	c.field, c.op = f[0], f[1]
	arity, ok := condOps[c.op]
	if !ok {
		return c, fmt.Errorf("condition %q: unknown operator %q", s, c.op)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(s, c.field)), c.op))
	if arity == 0 {
		if rest != "" {
			return c, fmt.Errorf("condition %q: %s takes no value", s, c.op)
		}
		return c, nil
	}
	if rest == "" && c.op != "eq" && c.op != "ne" {
		return c, fmt.Errorf("condition %q: missing value", s)
	}
	if len(rest) >= 2 && (rest[0] == '\'' || rest[0] == '"') && rest[len(rest)-1] == rest[0] {
		rest = rest[1 : len(rest)-1]
	}
	c.arg = rest
	switch c.op {
	case "in", "not_in", "has_all", "has_any", "has_none":
		for _, a := range strings.Split(rest, ",") {
			if a = strings.TrimSpace(a); a != "" {
				c.args = append(c.args, strings.ToLower(a))
			}
		}
	case "regex", "not_regex":
		re, err := regexp.Compile(rest)
		if err != nil {
			return c, fmt.Errorf("condition %q: %v", s, err)
		}
		c.re = re
	case "lt", "le", "gt", "ge":
		n, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			return c, fmt.Errorf("condition %q: %q is not a number", s, rest)
		}
		c.num = n
	case "perm_max", "bits_all", "bits_none", "bits_any":
		n, err := strconv.ParseUint(rest, 8, 32)
		if err != nil {
			return c, fmt.Errorf("condition %q: %q is not an octal mask", s, rest)
		}
		c.bits = n
	}
	return c, nil
}

// ---- compile / validate -----------------------------------------------------

var (
	checkIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(:[a-zA-Z0-9][a-zA-Z0-9._/@+-]*)+$`)
	packNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	validSev   = map[string]finding.Severity{
		"critical": finding.SeverityCritical, "high": finding.SeverityHigh, "medium": finding.SeverityMedium,
		"low": finding.SeverityLow, "info": finding.SeverityInfo,
	}
	validCat = map[string]finding.Category{
		"": finding.CategoryConfig, "config": finding.CategoryConfig, "hardening": finding.CategoryHardening,
		"filesystem": finding.CategoryFilesystem, "network": finding.CategoryNetwork, "tls": finding.CategoryTLS,
		"runtime": finding.CategoryRuntime, "eol": finding.CategoryEOL,
	}
)

func parseSeverity(s string) (finding.Severity, bool) {
	v, ok := validSev[strings.ToLower(strings.TrimSpace(s))]
	return v, ok
}

// parsePack decodes and validates one pack file.
func parsePack(name string, data []byte) (*Pack, error) {
	var p Pack
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	p.source = name
	if err := p.compile(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &p, nil
}

func (p *Pack) compile() error {
	if !packNameRE.MatchString(p.Name) {
		return fmt.Errorf("pack name %q: want lowercase letters, digits and dashes", p.Name)
	}
	if p.Title == "" {
		return fmt.Errorf("pack %s: missing title", p.Name)
	}
	if _, ok := validCat[p.Category]; !ok {
		return fmt.Errorf("pack %s: unknown category %q", p.Name, p.Category)
	}
	if err := p.AppliesIf.validate(); err != nil {
		return fmt.Errorf("pack %s applies_if: %w", p.Name, err)
	}
	seen := map[string]bool{}
	for i, c := range p.Checks {
		if c == nil {
			return fmt.Errorf("pack %s: empty check #%d", p.Name, i+1)
		}
		c.pack = p
		if err := c.compile(); err != nil {
			return fmt.Errorf("check %s: %w", c.ID, err)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate check id %s", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

func (c *Check) compile() error {
	if !checkIDRE.MatchString(c.ID) {
		return fmt.Errorf("id %q: want <area>:<name> (lowercase, no spaces)", c.ID)
	}
	if c.Title == "" || c.Remediation == "" {
		return fmt.Errorf("title and remediation are required")
	}
	sev, ok := parseSeverity(c.Severity)
	if !ok {
		return fmt.Errorf("severity %q: want critical|high|medium|low|info", c.Severity)
	}
	c.sev = sev
	switch strings.ToLower(c.Level) {
	case "", "medium":
		c.level = LevelMedium
	case "basic":
		c.level = LevelBasic
	case "strict":
		c.level = LevelStrict
	default:
		return fmt.Errorf("level %q: want basic|medium|strict", c.Level)
	}
	catName := c.Category
	if catName == "" {
		catName = c.pack.Category
	}
	cat, ok := validCat[catName]
	if !ok {
		return fmt.Errorf("unknown category %q", catName)
	}
	c.cat = cat
	switch c.Missing {
	case "", "pass", "fail", "skip":
	default:
		return fmt.Errorf("missing %q: want pass|fail|skip", c.Missing)
	}
	if err := c.AppliesIf.validate(); err != nil {
		return fmt.Errorf("applies_if: %w", err)
	}
	if err := c.Probe.compile(); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	for _, w := range c.Where {
		g, err := parseCondGroup(w)
		if err != nil {
			return fmt.Errorf("where: %w", err)
		}
		c.where = append(c.where, g)
	}
	for _, e := range c.Expect {
		g, err := parseCondGroup(e)
		if err != nil {
			return fmt.Errorf("expect: %w", err)
		}
		c.expect = append(c.expect, g)
	}
	if c.ExpectNone == (len(c.expect) > 0) {
		return fmt.Errorf("exactly one of expect / expect_none is required")
	}
	for i := range c.SeverityIf {
		r := &c.SeverityIf[i]
		s, ok := parseSeverity(r.Severity)
		if !ok {
			return fmt.Errorf("severity_if: bad severity %q", r.Severity)
		}
		r.sev = s
		if r.When != "" {
			g, err := parseCondGroup(r.When)
			if err != nil {
				return fmt.Errorf("severity_if: %w", err)
			}
			r.cond = g
		} else if r.If == nil {
			return fmt.Errorf("severity_if: needs when or if")
		}
		if err := r.If.validate(); err != nil {
			return fmt.Errorf("severity_if: %w", err)
		}
	}
	return nil
}

func (g *Gate) validate() error {
	if g == nil {
		return nil
	}
	for _, s := range append(append([]*Gate{}, g.All...), g.Any...) {
		if err := s.validate(); err != nil {
			return err
		}
	}
	if err := g.Not.validate(); err != nil {
		return err
	}
	for _, f := range g.File {
		if !strings.HasPrefix(f, "/") {
			return fmt.Errorf("file gate %q: want an absolute path", f)
		}
	}
	return nil
}

// Summary renders a gate for `lync checks` ("package nginx; unit nginx.service").
func (g *Gate) Summary() string {
	if g == nil {
		return ""
	}
	var parts []string
	add := func(label string, vs []string) {
		if len(vs) > 0 {
			parts = append(parts, label+" "+strings.Join(vs, "|"))
		}
	}
	add("package", g.Package)
	add("binary", g.Binary)
	add("unit", g.Unit)
	add("active", g.UnitActive)
	add("file", g.File)
	add("process", g.Process)
	add("os", g.OS)
	if len(g.Listening) > 0 {
		var ps []string
		for _, p := range g.Listening {
			ps = append(ps, strconv.Itoa(p))
		}
		add("port", ps)
	}
	if g.OSVersionGE != "" {
		parts = append(parts, "os>="+g.OSVersionGE)
	}
	if g.OSVersionLT != "" {
		parts = append(parts, "os<"+g.OSVersionLT)
	}
	for _, s := range g.All {
		if t := s.Summary(); t != "" {
			parts = append(parts, t)
		}
	}
	if len(g.Any) > 0 {
		var alts []string
		for _, s := range g.Any {
			alts = append(alts, s.Summary())
		}
		parts = append(parts, "("+strings.Join(alts, " or ")+")")
	}
	if g.Not != nil {
		parts = append(parts, "not("+g.Not.Summary()+")")
	}
	return strings.Join(parts, "; ")
}

// AppliesSummary is the combined pack + check gate.
func (c *Check) AppliesSummary() string {
	var parts []string
	if s := c.pack.AppliesIf.Summary(); s != "" {
		parts = append(parts, s)
	}
	if s := c.AppliesIf.Summary(); s != "" {
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "always"
	}
	return strings.Join(parts, "; ")
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
