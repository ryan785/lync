package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
	"github.com/ryan785/lync/internal/rules"
)

// Node.js data sources. All three are small static files.
const (
	NodeIndexURL    = "https://nodejs.org/dist/index.json"
	NodeVulnURL     = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
	NodeScheduleURL = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
)

// Check IDs (registered in internal/rules so they can be toggled).
const (
	CheckNodeRelease = "upstream:node-security-release"
	CheckNodeCVE     = "upstream:node-cve"
)

// NodeSourceName is the data-source name: in feed.sources, in the
// report's data_sources and in the run log.
const NodeSourceName = "nodejs"

// Node is the Node.js provider.
type Node struct {
	Fetcher *Fetcher
	// Endpoint overrides (tests).
	IndexURL, VulnURL, ScheduleURL string

	releases []nodeRelease
	vulns    []nodeVuln
	eol      map[string]string
	loaded   bool // release index available (fresh or cached)
}

type nodeRelease struct {
	Version  Version
	Date     string
	Security bool
	LTS      string
}

type nodeVuln struct {
	Key         string
	CVEs        []string
	Vulnerable  Range
	Patched     Range
	Severity    string
	Description string
	Ref         string
}

// NewNode returns a provider caching under cacheDir.
func NewNode(cacheDir string) *Node {
	return &Node{Fetcher: &Fetcher{Dir: cacheDir}}
}

func (n *Node) Name() string { return NodeSourceName }

func (n *Node) urls() (string, string, string) {
	i, v, s := NodeIndexURL, NodeVulnURL, NodeScheduleURL
	if n.IndexURL != "" {
		i = n.IndexURL
	}
	if n.VulnURL != "" {
		v = n.VulnURL
	}
	if n.ScheduleURL != "" {
		s = n.ScheduleURL
	}
	return i, v, s
}

// NodeChecksEnabled reports whether any Node check is on under the toggles.
func NodeChecksEnabled(t rules.Toggles) bool {
	if !t.RuleEnabled("runtimes") {
		return false
	}
	return t.CheckEnabled(CheckNodeRelease) || t.CheckEnabled(CheckNodeCVE) || t.CheckEnabled("runtime:eol-node")
}

// ---- data -------------------------------------------------------------------

// Fetch refreshes index.json, the security-wg core index and schedule.json.
// A file that cannot be refreshed but is cached is used stale (partial);
// without the release index the provider has nothing to match (failed).
func (n *Node) Fetch(ctx context.Context) feed.SourceStat {
	n.releases, n.vulns, n.eol, n.loaded = nil, nil, nil, false
	st := feed.SourceStat{Name: NodeSourceName, Kind: "lookup", Status: feed.StatusOK}
	f := n.Fetcher
	r0, h0, b0 := f.Requests, f.CacheHits, f.Bytes
	iu, vu, su := n.urls()
	var problems []string
	note := func(what string, r fetchResult, perr error) {
		switch {
		case r.Err != nil && r.Stale:
			problems = append(problems, fmt.Sprintf("%s: %v (using copy from %s)", what, r.Err, r.Fetched.UTC().Format(time.RFC3339)))
		case r.Err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", what, r.Err))
		case perr != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", what, perr))
		}
	}

	ri := f.Get(ctx, "node-index.json", iu)
	var perr error
	if ri.Data != nil {
		n.releases, perr = parseNodeIndex(ri.Data)
		n.loaded = perr == nil
	}
	note("release index", ri, perr)

	rv := f.Get(ctx, "node-security-wg.json", vu)
	perr = nil
	if rv.Data != nil {
		n.vulns, perr = parseNodeVulns(rv.Data)
	}
	note("security-wg", rv, perr)

	rs := f.Get(ctx, "node-schedule.json", su)
	perr = nil
	if rs.Data != nil {
		n.eol, perr = parseNodeSchedule(rs.Data)
	}
	note("release schedule", rs, perr)

	st.Requests = f.Requests - r0
	st.CacheHits = f.CacheHits - h0
	st.Bytes = f.Bytes - b0
	st.Records = len(n.releases) + len(n.vulns)
	detail := fmt.Sprintf("%d releases, %d core advisories", len(n.releases), len(n.vulns))
	if len(problems) > 0 {
		st.Status = feed.StatusPartial
		if !n.loaded {
			st.Status = feed.StatusFailed
		}
		detail += "; " + strings.Join(problems, "; ")
	}
	st.Detail = detail
	return st
}

// EOL returns major -> end-of-life date from schedule.json ("22" ->
// "2027-04-30"); nil when the schedule was not loaded.
func (n *Node) EOL() map[string]string { return n.eol }

func parseNodeIndex(data []byte) ([]nodeRelease, error) {
	var raw []struct {
		Version  string          `json:"version"`
		Date     string          `json:"date"`
		Security bool            `json:"security"`
		LTS      json.RawMessage `json:"lts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	out := make([]nodeRelease, 0, len(raw))
	for _, r := range raw {
		v, ok := ParseVersion(r.Version)
		if !ok {
			continue
		}
		var lts string
		_ = json.Unmarshal(r.LTS, &lts) // false for non-LTS lines
		out = append(out, nodeRelease{Version: v, Date: r.Date, Security: r.Security, LTS: lts})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parse index.json: no releases")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version.Compare(out[j].Version) < 0 })
	return out, nil
}

func parseNodeVulns(data []byte) ([]nodeVuln, error) {
	var raw map[string]struct {
		CVE         []string `json:"cve"`
		Vulnerable  string   `json:"vulnerable"`
		Patched     string   `json:"patched"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Ref         string   `json:"ref"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse security-wg index: %w", err)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, ea := strconv.Atoi(keys[i])
		b, eb := strconv.Atoi(keys[j])
		if ea == nil && eb == nil {
			return a < b
		}
		return keys[i] < keys[j]
	})
	var out []nodeVuln
	for _, k := range keys {
		e := raw[k]
		vr, err1 := ParseRange(e.Vulnerable)
		pr, err2 := ParseRange(e.Patched)
		if err1 != nil || err2 != nil {
			continue // one odd entry must not hide the rest
		}
		out = append(out, nodeVuln{Key: k, CVEs: e.CVE, Vulnerable: vr, Patched: pr,
			Severity: e.Severity, Description: e.Description, Ref: e.Ref})
	}
	return out, nil
}

func parseNodeSchedule(data []byte) (map[string]string, error) {
	var raw map[string]struct {
		End string `json:"end"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse schedule.json: %w", err)
	}
	out := map[string]string{}
	for k, v := range raw {
		if v.End == "" {
			continue
		}
		if _, err := time.Parse("2006-01-02", v.End); err != nil {
			continue
		}
		out[strings.TrimPrefix(k, "v")] = v.End
	}
	return out, nil
}

// ---- detection --------------------------------------------------------------

var (
	nodePathVersionRE = regexp.MustCompile(`/v?(\d+\.\d+\.\d+)(?:/installation)?/bin/node$`)
	nodeTarballRE     = regexp.MustCompile(`/node-v(\d+\.\d+\.\d+)-[^/]+/bin/node$`)
	nodeVersionOutRE  = regexp.MustCompile(`^v(\d+\.\d+\.\d+)`)
	nodeImageTagRE    = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:$|-)`)
)

// nodeGlobs are where version managers and tarball installs put node.
var (
	nodeHomeGlobs = []string{
		".nvm/versions/node/*/bin/node",
		".local/share/fnm/node-versions/*/installation/bin/node",
		".fnm/node-versions/*/installation/bin/node",
		".volta/tools/image/node/*/bin/node",
		".asdf/installs/nodejs/*/bin/node",
		".local/share/mise/installs/node/*/bin/node",
	}
	nodeGlobalGlobs = []string{
		"/usr/local/bin/node",
		"/usr/local/n/versions/node/*/bin/node",
		"/usr/local/nvm/versions/node/*/bin/node",
		"/usr/local/lib/nodejs/*/bin/node",
		"/opt/*/bin/node",
		"/opt/nvm/versions/node/*/bin/node",
	}
)

// nodeVia names how an install got there, from its path.
func nodeVia(p string) string {
	switch {
	case strings.Contains(p, "/.nvm/") || strings.Contains(p, "/nvm/versions/"):
		return "nvm"
	case strings.Contains(p, "/fnm/node-versions/") || strings.Contains(p, "/.fnm/"):
		return "fnm"
	case strings.Contains(p, "/.volta/"):
		return "volta"
	case strings.Contains(p, "/.asdf/"):
		return "asdf"
	case strings.Contains(p, "/mise/installs/"):
		return "mise"
	case strings.HasPrefix(p, "/usr/local/n/"):
		return "n"
	case strings.HasPrefix(p, "/snap/"):
		return "snap"
	}
	return "tarball"
}

// NodeSourcePackages returns installed nodejs packages built by NodeSource
// (deb "22.22.0-1nodesource1", rpm release "1nodesource"). Their versions
// are upstream Node versions, so distro advisories don't describe them.
func NodeSourcePackages(facts *collector.Facts) []collector.Package {
	if facts == nil {
		return nil
	}
	var out []collector.Package
	for _, p := range facts.Packages {
		if p.Name == "nodejs" && strings.Contains(strings.ToLower(p.Version+"-"+p.Release), "nodesource") {
			out = append(out, p)
		}
	}
	return out
}

// WithoutNodeSource returns facts minus NodeSource nodejs packages, for
// the distro CVE lookup and matcher (their versions are upstream Node
// versions, which distro advisories would misjudge). facts itself is
// returned when there is nothing to drop.
func WithoutNodeSource(facts *collector.Facts) *collector.Facts {
	if len(NodeSourcePackages(facts)) == 0 {
		return facts
	}
	cp := *facts
	cp.Packages = make([]collector.Package, 0, len(facts.Packages))
	for _, p := range facts.Packages {
		if p.Name == "nodejs" && strings.Contains(strings.ToLower(p.Version+"-"+p.Release), "nodesource") {
			continue
		}
		cp.Packages = append(cp.Packages, p)
	}
	return &cp
}

// upstreamNodeVersion turns a NodeSource package version into the Node
// version: "2:22.22.0-1nodesource1" -> "22.22.0".
func upstreamNodeVersion(p collector.Package) string {
	v := p.Version
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		v = v[:i]
	}
	return v
}

// Detect finds non-distro Node.js binaries: running processes, version
// manager directories under every home, /usr/local and /opt tarballs and
// NodeSource packages (container images: NodeImageInstalls). Distro
// /usr/bin/node stays with the distro advisories.
func (n *Node) Detect(ctx context.Context, env Env) []Install {
	h := env.Host
	byPath := map[string]*Install{}
	var order []string
	add := func(in Install) {
		if cur, ok := byPath[in.Path]; ok {
			if cur.PID == "" {
				cur.PID = in.PID
			}
			return
		}
		cp := in
		byPath[in.Path] = &cp
		order = append(order, in.Path)
	}

	nodesource := NodeSourcePackages(env.Facts)
	nsPaths := map[string]collector.Package{}
	for _, p := range nodesource {
		for _, bin := range []string{"/usr/bin/node", "/usr/bin/nodejs"} {
			nsPaths[bin] = p
		}
	}
	consider := func(p, pid string) {
		real := realPath(h, p)
		if pkg, ok := nsPaths[real]; ok {
			add(Install{Runtime: "node", Path: "/usr/bin/node", Version: upstreamNodeVersion(pkg), Via: "nodesource",
				PID: pid, Package: pkg.Name})
			return
		}
		if distroPath(real) {
			return // distro build: covered by the distro's advisories
		}
		if pid == "" && !h.Exists(real) {
			return
		}
		ver := nodeVersionFromPath(real)
		if ver == "" {
			o, err := h.Run(ctx, real, "--version")
			if err != nil && o == "" {
				return
			}
			if m := nodeVersionOutRE.FindStringSubmatch(strings.TrimSpace(o)); m != nil {
				ver = m[1]
			}
		}
		if ver == "" {
			return
		}
		add(Install{Runtime: "node", Path: real, Version: ver, Via: nodeVia(real), PID: pid})
	}

	exes := rules.ProcessExes(h)
	procs := make([]string, 0, len(exes))
	for p := range exes {
		if b := path.Base(p); b == "node" || b == "nodejs" {
			procs = append(procs, p)
		}
	}
	sort.Strings(procs)
	for _, p := range procs {
		consider(p, exes[p])
	}
	for _, hm := range homes(h) {
		for _, g := range nodeHomeGlobs {
			for _, p := range h.Glob(hm + "/" + g) {
				consider(p, "")
			}
		}
	}
	for _, g := range nodeGlobalGlobs {
		for _, p := range h.Glob(g) {
			consider(p, "")
		}
	}
	for _, p := range nodesource {
		if _, ok := byPath["/usr/bin/node"]; !ok {
			add(Install{Runtime: "node", Path: "/usr/bin/node", Version: upstreamNodeVersion(p), Via: "nodesource", Package: p.Name})
		}
	}

	out := make([]Install, 0, len(order))
	for _, p := range order {
		out = append(out, *byPath[p])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// NodeImageInstalls turns the application inventory's container images
// named node with a full version tag (node:22.22.0, node:22.22.0-alpine)
// into installs. Floating tags (node:22, node:lts) are skipped: their
// patch level is unknown.
func NodeImageInstalls(comps []inventory.Component) []Install {
	var out []Install
	seen := map[string]bool{}
	for _, c := range comps {
		if c.Ecosystem != inventory.EcoContainerImage || path.Base(c.Name) != "node" {
			continue
		}
		m := nodeImageTagRE.FindStringSubmatch(c.Version)
		if m == nil {
			continue
		}
		ref := c.Name + ":" + c.Version
		if seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, Install{Runtime: "node", Path: "image:" + ref, Version: m[1], Via: "container", Image: ref,
			Containers: append([]string(nil), c.Paths...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func nodeVersionFromPath(p string) string {
	if m := nodePathVersionRE.FindStringSubmatch(p); m != nil {
		return m[1]
	}
	if m := nodeTarballRE.FindStringSubmatch(p); m != nil {
		return m[1]
	}
	return ""
}

// ---- matching ---------------------------------------------------------------

// Match emits, per install:
//   - one upstream:node-cve finding per security-wg CVE whose vulnerable
//     range contains the version and whose patched range does not, with
//     FixedIn = the first patched release on the install's major line;
//   - upstream:node-security-release when a newer release on the same
//     major is flagged security in index.json. When CVE findings exist it
//     is emitted only for a security release newer than every CVE fix
//     that no security-wg entry names as a fix yet (the release-day gap
//     before the CVE list is updated).
func (n *Node) Match(ctx context.Context, env Env, installs []Install, enrich Enricher) []finding.Finding {
	if !n.loaded {
		return nil
	}
	relOn := env.Toggles.CheckEnabled(CheckNodeRelease)
	cveOn := env.Toggles.CheckEnabled(CheckNodeCVE)
	type hit struct {
		in  Install
		v   Version
		vul nodeVuln
		cve string
		fix Version
	}
	var hits []hit
	var out []finding.Finding
	var relFindings []finding.Finding
	for _, in := range installs {
		v, ok := ParseVersion(in.Version)
		if !ok {
			continue
		}
		major := v.Major()
		seen := map[string]bool{}
		ncve := 0
		var maxFix Version
		for _, e := range n.vulns {
			if e.Patched.Empty() || !e.Vulnerable.Satisfies(v) || e.Patched.Satisfies(v) {
				continue
			}
			fix, ok := e.Patched.LowestAbove(major, v)
			if !ok {
				continue // no fix on this major (EOL line: runtime:eol-node covers it)
			}
			if fix.Compare(maxFix) > 0 {
				maxFix = fix
			}
			for _, id := range e.CVEs {
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				ncve++
				if cveOn {
					hits = append(hits, hit{in: in, v: v, vul: e, cve: id, fix: fix})
				}
			}
		}

		// Security releases newer than the install on its line.
		var sec []nodeRelease
		var latest nodeRelease
		for _, r := range n.releases {
			if r.Version.Major() != major || r.Version.Compare(v) <= 0 {
				continue
			}
			latest = r
			if r.Security {
				sec = append(sec, r)
			}
		}
		if !relOn || len(sec) == 0 {
			continue
		}
		covered := map[Version]bool{}
		for _, e := range n.vulns {
			for _, f := range e.Patched.FixesOnMajor(major) {
				covered[f] = true
			}
		}
		target := sec[len(sec)-1]
		if ncve > 0 && cveOn {
			// Upgrading to the highest CVE fix also brings every older
			// security release; only a newer one that no security-wg
			// entry names as a fix is still unexplained.
			var gap []nodeRelease
			for _, r := range sec {
				if r.Version.Compare(maxFix) > 0 && !covered[r.Version] {
					gap = append(gap, r)
				}
			}
			if len(gap) == 0 {
				continue // the CVE findings describe every missed security release
			}
			target = gap[len(gap)-1]
		}
		relFindings = append(relFindings, n.releaseFinding(env, in, v, target, latest, len(sec), ncve))
	}

	var ids []string
	idSeen := map[string]bool{}
	for _, h := range hits {
		if !idSeen[h.cve] {
			idSeen[h.cve] = true
			ids = append(ids, h.cve)
		}
	}
	var nvd map[string]feed.Vulnerability
	if enrich != nil && len(ids) > 0 {
		nvd = enrich(ctx, ids)
	}
	for _, h := range hits {
		out = append(out, n.cveFinding(env, h.in, h.v, h.vul, h.cve, h.fix, nvd[h.cve]))
	}
	return append(out, relFindings...)
}

func (n *Node) releaseFinding(env Env, in Install, v Version, target, latest nodeRelease, nsec, ncve int) finding.Finding {
	lts := ""
	if target.LTS != "" {
		lts = ", LTS " + target.LTS
	}
	ev := fmt.Sprintf("%s; nodejs.org/dist/index.json marks %s (%s%s) as a security release", describe(in), "v"+target.Version.String(), target.Date, lts)
	if nsec > 1 {
		ev += fmt.Sprintf("; %d security releases on the %d.x line are newer than %s", nsec, v.Major(), v)
	}
	if ncve > 0 {
		ev += fmt.Sprintf("; %d CVE finding(s) from the security-wg list cover older fixes, but none of its entries names %s yet (release-day gap)", ncve, target.Version)
	} else {
		ev += "; the nodejs/security-wg CVE list has no entry for it yet"
	}
	return finding.Finding{
		ID:          CheckNodeRelease + ":" + in.Path,
		Category:    finding.CategoryCVE,
		Severity:    finding.SeverityHigh,
		Title:       fmt.Sprintf("Node %s is behind security release %s (%s)", v, target.Version, target.Date),
		Evidence:    ev,
		References:  []string{"https://nodejs.org/en/blog/vulnerability", "https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V" + strconv.Itoa(v.Major()) + ".md"},
		Remediation: nodeRemediation(in, latest.Version),
		DetectedAt:  env.Now,
		Package:     nodePackage(in),
		Installed:   in.Version,
		FixedIn:     target.Version.String(),
		Source:      "nodejs.org",
		Check:       CheckNodeRelease,
		Pack:        "runtimes",
	}
}

func (n *Node) cveFinding(env Env, in Install, v Version, e nodeVuln, cve string, fix Version, nv feed.Vulnerability) finding.Finding {
	sev := wgSeverity(e.Severity)
	score := 0.0
	src := "nodejs-security-wg"
	if nv.CVSS > 0 {
		score = nv.CVSS
		if s := wgSeverity(nv.Severity); s != finding.SeverityUnknown {
			sev = s
		} else if s := wgSeverity(feed.SeverityFromCVSS(nv.CVSS)); s != finding.SeverityUnknown {
			sev = s
		}
		src += "+nvd"
	}
	ev := fmt.Sprintf("%s; security-wg entry %s: vulnerable %q, patched %q", describe(in), e.Key, e.Vulnerable.String(), e.Patched.String())
	if e.Description != "" {
		ev += "; " + e.Description
	}
	refs := []string{"https://nvd.nist.gov/vuln/detail/" + cve}
	if e.Ref != "" {
		refs = append([]string{e.Ref}, refs...)
	}
	return finding.Finding{
		ID:          CheckNodeCVE + ":" + cve + ":" + in.Path,
		Category:    finding.CategoryCVE,
		Severity:    sev,
		Title:       fmt.Sprintf("%s affects Node.js %s (%s)", cve, v, in.Via),
		Evidence:    ev,
		References:  refs,
		Remediation: nodeRemediation(in, fix),
		DetectedAt:  env.Now,
		CVE:         cve,
		Package:     nodePackage(in),
		Installed:   in.Version,
		FixedIn:     fix.String(),
		CVSS:        score,
		Source:      src,
		Check:       CheckNodeCVE,
		Pack:        "runtimes",
	}
}

// nodePackage is the finding's Package: the distro package for NodeSource
// (so `apt/dnf upgrade nodejs` is the right action), "node" otherwise.
func nodePackage(in Install) string {
	if in.Package != "" {
		return in.Package
	}
	return "node"
}

func describe(in Install) string {
	var b strings.Builder
	if in.Image != "" {
		fmt.Fprintf(&b, "container image %s (Node %s)", in.Image, in.Version)
		if len(in.Containers) > 0 {
			fmt.Fprintf(&b, ", used by %s", strings.Join(in.Containers, ", "))
		}
		return b.String()
	}
	fmt.Fprintf(&b, "path: %s; installed: Node %s (%s", in.Path, in.Version, in.Via)
	if in.Package != "" {
		fmt.Fprintf(&b, " package %s", in.Package)
	}
	b.WriteString(")")
	if in.PID != "" {
		fmt.Fprintf(&b, "; running (pid %s, e.g.)", in.PID)
	} else {
		b.WriteString("; installed, no running process seen")
	}
	return b.String()
}

func nodeRemediation(in Install, to Version) string {
	t := to.String()
	restart := "; then restart the apps that use it (pm2 restart all / systemctl restart <unit>)"
	switch in.Via {
	case "nvm":
		return fmt.Sprintf("nvm install %s && nvm alias default %s (as the owning user)%s; nvm uninstall the old version when unused", t, t, restart)
	case "fnm":
		return fmt.Sprintf("fnm install %s && fnm default %s%s", t, t, restart)
	case "volta":
		return fmt.Sprintf("volta install node@%s (and update any \"volta\" pin in package.json)%s", t, restart)
	case "asdf":
		return fmt.Sprintf("asdf install nodejs %s && asdf global nodejs %s (or update .tool-versions)%s", t, t, restart)
	case "mise":
		return fmt.Sprintf("mise use -g node@%s%s", t, restart)
	case "n":
		return fmt.Sprintf("n %s%s", t, restart)
	case "snap":
		return "snap refresh node" + restart
	case "nodesource":
		return fmt.Sprintf("Update from the NodeSource repository: apt-get install --only-upgrade nodejs (Debian/Ubuntu) or dnf update nodejs (RHEL family) to %s or later%s", t, restart)
	case "container":
		return fmt.Sprintf("Rebuild/pull on node:%s (or a newer patch tag) and recreate the containers using %s", t, in.Image)
	}
	return fmt.Sprintf("Replace %s with the official v%s build (https://nodejs.org/dist/v%s/) or move it under a version manager%s", path.Dir(path.Dir(in.Path)), t, t, restart)
}

func wgSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "high", "important":
		return finding.SeverityHigh
	case "medium", "moderate":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	}
	return finding.SeverityUnknown
}
