package upstream

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a release version (major.minor.patch). Upstream runtime
// releases carry no pre-release tags in the data Lync reads, so none are
// modelled.
type Version [3]int

// ParseVersion parses "v22.23.4" / "22.23.4". All three parts are required.
func ParseVersion(s string) (Version, bool) {
	var v Version
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// Major returns the major version.
func (v Version) Major() int { return v[0] }

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for i := 0; i < 3; i++ {
		switch {
		case v[i] < o[i]:
			return -1
		case v[i] > o[i]:
			return 1
		}
	}
	return 0
}

// comparator is one primitive constraint: op is one of < <= > >= =.
type comparator struct {
	op string
	v  Version
}

func (c comparator) ok(v Version) bool {
	d := v.Compare(c.v)
	switch c.op {
	case "<":
		return d < 0
	case "<=":
		return d <= 0
	case ">":
		return d > 0
	case ">=":
		return d >= 0
	}
	return d == 0
}

// Range is a parsed node-semver range: a union ("||") of intersections
// of comparators. It supports the subset the Node.js security working
// group uses: "*", x-ranges ("22.x", "22", "22.1.x"), caret ("^22.23.4"),
// tilde ("~22.1"), primitive comparators with or without a space after
// the operator (">=24.0.0 <24.22.1", "<= 10"), hyphen ranges
// ("1.2.3 - 2.3.4") and bare versions.
type Range struct {
	raw  string
	sets [][]comparator // empty inner slice = matches everything
}

// String returns the source text.
func (r Range) String() string { return r.raw }

// Empty reports whether the range was blank (matches nothing).
func (r Range) Empty() bool { return len(r.sets) == 0 }

// ParseRange parses a range. A blank string yields an empty Range that
// matches nothing (an advisory without a patched range has no fix).
func ParseRange(s string) (Range, error) {
	r := Range{raw: strings.TrimSpace(s)}
	if r.raw == "" {
		return r, nil
	}
	for _, alt := range strings.Split(r.raw, "||") {
		set, err := parseSet(strings.TrimSpace(alt))
		if err != nil {
			return Range{}, fmt.Errorf("range %q: %w", s, err)
		}
		r.sets = append(r.sets, set)
	}
	return r, nil
}

// Satisfies reports whether v is inside the range.
func (r Range) Satisfies(v Version) bool {
	for _, set := range r.sets {
		ok := true
		for _, c := range set {
			if !c.ok(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// LowestAbove returns the smallest lower bound of any alternative of r
// that is on the given major and greater than v: for a patched range
// "^22.23.4 || ^24.22.1" and v=22.22.0 that is 22.23.4. ok is false when
// no alternative starts on that major above v (no fix on this line).
func (r Range) LowestAbove(major int, v Version) (Version, bool) {
	var best Version
	found := false
	for _, set := range r.sets {
		lo, ok := lowerBound(set)
		if !ok || lo.Major() != major || lo.Compare(v) <= 0 {
			continue
		}
		if !found || lo.Compare(best) < 0 {
			best, found = lo, true
		}
	}
	return best, found
}

// FixesOnMajor lists the lower bounds of every alternative on major (the
// release lines a patched range names), lowest first.
func (r Range) FixesOnMajor(major int) []Version {
	var out []Version
	for _, set := range r.sets {
		if lo, ok := lowerBound(set); ok && lo.Major() == major {
			out = append(out, lo)
		}
	}
	return out
}

// lowerBound is the greatest >= / > / = bound of an intersection. A ">"
// bound is returned as is (the release itself is excluded, but no
// security-wg range uses one for patched versions).
func lowerBound(set []comparator) (Version, bool) {
	var lo Version
	found := false
	for _, c := range set {
		switch c.op {
		case ">=", ">", "=":
			if !found || c.v.Compare(lo) > 0 {
				lo, found = c.v, true
			}
		}
	}
	return lo, found
}

// partial is a possibly incomplete version: n parts given (0..3), the
// rest wildcards.
type partial struct {
	v Version
	n int
}

func parsePartial(s string) (partial, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "="), "v")
	var p partial
	if s == "" || s == "*" || s == "x" || s == "X" {
		return p, nil
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return p, fmt.Errorf("bad version %q", s)
	}
	for i, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			break
		}
		// Drop pre-release / build suffixes ("1.2.3-rc.1"): not used by
		// the data, and treating them as the release is the safe side.
		if j := strings.IndexAny(part, "-+"); j >= 0 && i == len(parts)-1 {
			part = part[:j]
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return p, fmt.Errorf("bad version %q", s)
		}
		p.v[i] = n
		p.n = i + 1
	}
	return p, nil
}

// next returns the first version above the partial's wildcard span:
// "22" -> 23.0.0, "22.1" -> 22.2.0. Only valid for n in 1..2.
func (p partial) next() Version {
	v := p.v
	v[p.n-1]++
	for i := p.n; i < 3; i++ {
		v[i] = 0
	}
	return v
}

var rangeOps = []string{">=", "<=", ">", "<", "=", "^", "~"}

func parseSet(s string) ([]comparator, error) {
	if s == "" || s == "*" || s == "x" || s == "X" {
		return []comparator{}, nil
	}
	fields := strings.Fields(s)
	// Hyphen range: "a - b".
	if len(fields) == 3 && fields[1] == "-" {
		lo, err := parsePartial(fields[0])
		if err != nil {
			return nil, err
		}
		hi, err := parsePartial(fields[2])
		if err != nil {
			return nil, err
		}
		set := []comparator{{">=", lo.v}}
		switch {
		case hi.n == 0:
		case hi.n == 3:
			set = append(set, comparator{"<=", hi.v})
		default:
			set = append(set, comparator{"<", hi.next()})
		}
		return set, nil
	}
	// Join an operator written apart from its version ("<= 10").
	var toks []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if isOpOnly(f) && i+1 < len(fields) {
			f += fields[i+1]
			i++
		}
		toks = append(toks, f)
	}
	set := []comparator{}
	for _, t := range toks {
		cs, err := parseComparator(t)
		if err != nil {
			return nil, err
		}
		set = append(set, cs...)
	}
	return set, nil
}

func isOpOnly(s string) bool {
	for _, op := range rangeOps {
		if s == op {
			return true
		}
	}
	return false
}

func parseComparator(t string) ([]comparator, error) {
	op := ""
	for _, o := range rangeOps {
		if strings.HasPrefix(t, o) {
			op = o
			break
		}
	}
	p, err := parsePartial(strings.TrimPrefix(t, op))
	if err != nil {
		return nil, err
	}
	if p.n == 0 { // "*", ">=*", ...
		if op == "<" || op == ">" {
			return []comparator{{"<", Version{}}}, nil // matches nothing
		}
		return nil, nil
	}
	switch op {
	case "", "=":
		if p.n == 3 {
			return []comparator{{"=", p.v}}, nil
		}
		return []comparator{{">=", p.v}, {"<", p.next()}}, nil
	case ">=":
		return []comparator{{">=", p.v}}, nil
	case ">":
		if p.n == 3 {
			return []comparator{{">", p.v}}, nil
		}
		return []comparator{{">=", p.next()}}, nil
	case "<":
		return []comparator{{"<", p.v}}, nil
	case "<=":
		if p.n == 3 {
			return []comparator{{"<=", p.v}}, nil
		}
		return []comparator{{"<", p.next()}}, nil
	case "~":
		hi := p.next()
		if p.n >= 2 {
			hi = partial{v: p.v, n: 2}.next()
		}
		return []comparator{{">=", p.v}, {"<", hi}}, nil
	case "^":
		// The upper bound bumps the first non-zero part given (node-semver).
		hi := Version{p.v[0] + 1}
		switch {
		case p.v[0] > 0 || p.n == 1:
		case p.v[1] > 0 || p.n == 2:
			hi = Version{0, p.v[1] + 1, 0}
		default:
			hi = Version{0, 0, p.v[2] + 1}
		}
		return []comparator{{">=", p.v}, {"<", hi}}, nil
	}
	return nil, fmt.Errorf("bad comparator %q", t)
}
