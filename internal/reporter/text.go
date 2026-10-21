package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/matcher"
)

// textWidth is the column limit of the plain-text report. 100 columns
// reads well in less, a mail client and Notepad.
const textWidth = 100

// labelW is the width of the "Label     value" column in key/value rows.
const labelW = 12

var severityOrder = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
	finding.SeverityLow, finding.SeverityInfo, finding.SeverityUnknown,
}

// WriteTextFromJSON reads the canonical JSON report and renders it as a
// plain-text report (the text sibling of WritePDFFromJSON).
func WriteTextFromJSON(jsonPath, txtPath string) error {
	r, err := ReadJSON(jsonPath)
	if err != nil {
		return err
	}
	return WriteText(txtPath, r)
}

// WriteText renders a Report as plain UTF-8 text, wrapped at 100 columns.
func WriteText(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(RenderText(r)), 0o644)
}

// RenderText returns the plain-text report for r.
func RenderText(r *Report) string {
	t := &textDoc{}
	when := r.Generated
	if when.IsZero() {
		when = time.Now()
	}
	cves, others := splitFindings(r.Findings)

	t.textHeader(r, when)
	t.textSummary(r, cves, others)
	t.textFixFirst(r, cves, others)
	t.textAllFindings(r.Findings)
	if r.Inventory != nil {
		t.textInventory(r.Inventory)
	}
	if len(r.Coverage) > 0 {
		t.textCoverage(r.Coverage)
	}
	t.rule('=')
	ver := ""
	if r.LyncVersion != "" {
		ver = " by lync " + r.LyncVersion
	}
	t.para("", "Generated "+utc(when)+ver+". The JSON report is the canonical record.")
	t.para("", "Re-render: lync render <report.json> <out.txt|out.pdf>")
	return t.String()
}

// --- shared with the PDF ---------------------------------------------------

// incompleteText is the "CVE SECTION INCOMPLETE" banner text, or "" when
// the CVE data is complete (or the report predates data-source tracking).
func incompleteText(ds *feed.ScanSources) string {
	if ds == nil || ds.Complete {
		return ""
	}
	return "CVE SECTION INCOMPLETE: " + strings.Join(ds.IncompleteReasons, "; ")
}

// feedModeText describes how the CVE data was obtained.
func feedModeText(ds *feed.ScanSources) string {
	if ds.Mode == feed.ModeFull {
		return "full (bulk feed downloads)"
	}
	return "lookup (per-package / per-CVE API queries, no bulk download)"
}

// sourceLine is one data source's status line.
func sourceLine(s feed.SourceStat) string {
	line := fmt.Sprintf("%s (%s): %s", s.Name, s.Kind, s.Status)
	var parts []string
	if s.Requests > 0 {
		parts = append(parts, fmt.Sprintf("%d requests", s.Requests))
	}
	if s.CacheHits > 0 {
		parts = append(parts, fmt.Sprintf("%d cached", s.CacheHits))
	}
	if s.Records > 0 {
		parts = append(parts, fmt.Sprintf("%d records", s.Records))
	}
	if len(parts) > 0 {
		line += ", " + strings.Join(parts, ", ")
	}
	if s.Detail != "" {
		line += " - " + s.Detail
	}
	return line
}

// unfixedText explains DataSources.UnfixedCVEs.
func unfixedText(n int) string {
	return fmt.Sprintf("%d CVEs affect installed packages but have no fixed version published yet (not listed as findings; check them with `lync cve`).", n)
}

// --- sections ----------------------------------------------------------------

func (t *textDoc) textHeader(r *Report, when time.Time) {
	t.rule('=')
	t.line("LYNC SECURITY REPORT")
	t.rule('=')
	t.kv("Host", r.Host)
	t.kv("OS", r.OS.PrettyName)
	kernel := r.Kernel.Release
	if r.Kernel.Machine != "" && !strings.HasSuffix(kernel, r.Kernel.Machine) {
		kernel += " (" + r.Kernel.Machine + ")"
	}
	t.kv("Kernel", kernel)
	t.kv("Packages", strconv.Itoa(r.PkgCount)+" installed")
	if r.Impact.RunningServicesCount > 0 {
		t.kv("Services", strconv.Itoa(r.Impact.RunningServicesCount)+" running")
	}
	t.kv("Scanned", utc(when))
	if r.LyncVersion != "" {
		t.kv("Lync", r.LyncVersion)
	}
	ds := r.DataSources
	if ds == nil {
		t.kv("CVE data", "not recorded (report from an older version)")
		t.blank()
		return
	}
	t.kv("CVE data", feedModeText(ds))
	checked := utc(ds.CheckedAt)
	if ds.PackagesChecked > 0 {
		checked += fmt.Sprintf(", %d packages checked", ds.PackagesChecked)
	}
	if ds.Ecosystem != "" {
		checked += ", ecosystem " + ds.Ecosystem
	}
	t.kv("Checked", checked)
	for i, s := range ds.Sources {
		label := ""
		if i == 0 {
			label = "Sources"
		}
		t.kv(label, sourceLine(s))
	}
	if ds.UnfixedCVEs > 0 {
		t.kv("No fix yet", unfixedText(ds.UnfixedCVEs))
	}
	if msg := incompleteText(ds); msg != "" {
		t.blank()
		t.line(strings.Repeat("!", textWidth))
		t.para("!! ", msg)
		t.para("!! ", "A short or empty CVE list below does NOT mean the host is free of known vulnerabilities.")
		t.line(strings.Repeat("!", textWidth))
	}
	t.blank()
}

func (t *textDoc) textSummary(r *Report, cves, others []finding.Finding) {
	t.section("SUMMARY")
	counts := map[finding.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	var head, vals strings.Builder
	for _, s := range severityOrder {
		w := len(s) + 2
		fmt.Fprintf(&head, "%*s", w, string(s))
		fmt.Fprintf(&vals, "%*d", w, counts[s])
	}
	fmt.Fprintf(&head, "%7s", "Total")
	fmt.Fprintf(&vals, "%7d", len(r.Findings))
	t.line(head.String())
	t.line(vals.String())
	t.blank()

	pkgs := map[string]bool{}
	for _, f := range cves {
		if f.Package != "" {
			pkgs[f.Package] = true
		}
	}
	t.kv("Findings", fmt.Sprintf("%d vulnerability findings in %d packages/components, %d configuration and check findings",
		len(cves), len(pkgs), len(others)))
	imp := r.Impact
	if imp.HighestCVSS > 0 {
		hi := fmt.Sprintf("CVSS %.1f", imp.HighestCVSS)
		if imp.HighestCVSSCVE != "" {
			hi += ", " + imp.HighestCVSSCVE
		}
		if imp.HighestCVSSPackage != "" {
			hi += " (" + imp.HighestCVSSPackage + ")"
		}
		t.kv("Highest", hi)
	}
	if imp.NeedsReboot {
		list := imp.KernelCVEs
		more := ""
		if len(list) > 4 {
			more = fmt.Sprintf(", +%d more", len(list)-4)
			list = list[:4]
		}
		t.kv("Reboot", fmt.Sprintf("YES - %d kernel finding(s) (%s%s); reboot after updating the kernel",
			imp.KernelFindings, strings.Join(nonEmpty(list), ", "), more))
	} else {
		t.kv("Reboot", "no kernel findings")
	}
	if len(imp.ActiveServicesAffected) > 0 {
		t.kv("Services", strings.Join(imp.ActiveServicesAffected, ", ")+
			"  (running services whose package has findings)")
	} else {
		t.kv("Services", "no running service is provided by an affected package")
	}
	if len(r.Findings) == 0 {
		t.blank()
		if incompleteText(r.DataSources) != "" {
			t.para("", "No findings from the checks that completed. The CVE section is INCOMPLETE (see above), so this does not mean the host is free of known vulnerabilities.")
		} else {
			t.para("", "No vulnerabilities or configuration problems detected on this host.")
		}
	}
	t.blank()
}

// pkgGroup is the CVE findings of one package (or application component).
type pkgGroup struct {
	name      string
	installed string
	fixed     string // highest fixed version among the findings
	findings  []finding.Finding
	unfixed   int // findings without a fixed version
	worst     int
	kernel    bool
	app       bool   // application component (inventory), not an OS package
	node      bool   // upstream Node.js binary (name is its path)
	fix       string // remediation for app components
}

func (t *textDoc) textFixFirst(r *Report, cves, others []finding.Finding) {
	t.section("FIX FIRST")
	osGroups, appGroups, nodeGroups := groupByPackage(cves)
	var fixable, unfixable []*pkgGroup
	for _, g := range osGroups {
		if g.fixed != "" {
			fixable = append(fixable, g)
		} else {
			unfixable = append(unfixable, g)
		}
	}
	var urgent []finding.Finding
	for _, f := range others {
		if f.Severity.Rank() >= finding.SeverityHigh.Rank() {
			urgent = append(urgent, f)
		}
	}
	sortFindings(urgent)
	if len(cves) == 0 && incompleteText(r.DataSources) != "" {
		t.para("", "No package updates listed: the CVE section is INCOMPLETE (see above).")
		t.blank()
	}
	if len(fixable)+len(unfixable)+len(appGroups)+len(nodeGroups)+len(urgent) == 0 {
		if incompleteText(r.DataSources) == "" {
			t.para("", "Nothing to fix: no package updates and no critical or high configuration findings.")
		} else {
			t.para("", "No critical or high configuration findings.")
		}
		t.blank()
		return
	}
	step := 0
	if len(fixable) > 0 {
		step++
		n := 0
		for _, g := range fixable {
			n += len(g.findings) - g.unfixed
		}
		t.para("", fmt.Sprintf("%d) Update packages: %d vulnerability findings in %d packages, worst first", step, n, len(fixable)))
		t.blank()
		t.groupTable("   ", fixable)
		t.blank()
		names := make([]string, 0, len(fixable))
		reboot := false
		for _, g := range fixable {
			names = append(names, g.name)
			reboot = reboot || g.kernel
		}
		sort.Strings(names)
		if cmd := updateCommand(r.OS, names); cmd != "" {
			t.para("   ", "Run as root:")
			t.command("     ", cmd)
		} else {
			t.para("   ", "Update these packages with the system package manager: "+strings.Join(names, " "))
		}
		if reboot {
			t.para("   ", "Then reboot: a kernel update only takes effect after a reboot.")
		}
		t.blank()
	}
	if len(unfixable) > 0 {
		t.para("   ", "No fix available yet (no fixed version published; watch for updates or mitigate):")
		t.groupTable("     ", unfixable)
		t.blank()
	}
	if len(nodeGroups) > 0 {
		step++
		t.para("", fmt.Sprintf("%d) Upgrade Node.js (%d installs outside the distro packages: nvm, tarballs, NodeSource, images)", step, len(nodeGroups)))
		t.blank()
		t.groupTable("   ", nodeGroups)
		t.blank()
	}
	if len(appGroups) > 0 {
		step++
		t.para("", fmt.Sprintf("%d) Update application components (installed outside the package manager)", step))
		t.blank()
		t.groupTable("   ", appGroups)
		t.blank()
	}
	if len(urgent) > 0 {
		step++
		t.para("", fmt.Sprintf("%d) Critical and high configuration findings (%d)", step, len(urgent)))
		t.blank()
		for _, f := range urgent {
			t.para("   ", fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), titleOf(f)))
			t.kvIndent("     ", "ID", f.ID)
			if f.Remediation != "" {
				t.kvIndent("     ", "Fix", f.Remediation)
			}
		}
		t.blank()
	}
}

// groupTable prints one row per package group, aligned in columns. A
// row too long for the page continues on a second line under the
// version column, and doesn't widen the columns of the other rows.
func (t *textDoc) groupTable(indent string, gs []*pkgGroup) {
	nw, vw := 4, 4
	for _, g := range gs {
		nw = max(nw, min(utf8.RuneCountInString(g.name), 32))
	}
	in := utf8.RuneCountInString(indent)
	for _, g := range gs {
		v := utf8.RuneCountInString(g.versions())
		if in+nw+2+v+2+utf8.RuneCountInString(g.summary()) <= textWidth {
			vw = max(vw, v)
		}
	}
	for _, g := range gs {
		left := indent + padRight(g.name, nw) + "  " + padRight(g.versions(), vw) + "  "
		right := g.summary()
		if utf8.RuneCountInString(left)+utf8.RuneCountInString(right) <= textWidth {
			t.line(strings.TrimRight(left+right, " "))
		} else {
			t.line(strings.TrimRight(left, " "))
			t.para(strings.Repeat(" ", in+nw+2), right)
		}
		if (g.app || g.node) && g.fix != "" {
			t.kvIndent(strings.Repeat(" ", in+2), "Fix", g.fix)
		}
	}
}

func (g *pkgGroup) versions() string {
	inst := g.installed
	if inst == "" {
		inst = "?"
	}
	if g.fixed == "" {
		return inst
	}
	return inst + " -> " + g.fixed
}

func (g *pkgGroup) summary() string {
	allCVE := true
	for _, f := range g.findings {
		if f.CVE == "" {
			allCVE = false
		}
	}
	n := len(g.findings) - g.unfixed
	if g.fixed == "" {
		n = len(g.findings)
	}
	noun := "issue"
	if allCVE {
		noun = "CVE"
	}
	if n != 1 {
		noun += "s"
	}
	verb := "fixes"
	if g.fixed == "" {
		verb = "affected by"
	}
	s := fmt.Sprintf("%s %d %s (%s)", verb, n, noun, severityBreakdown(g.findings))
	if g.fixed != "" && g.unfixed > 0 {
		s += fmt.Sprintf(", +%d without a fix yet", g.unfixed)
	}
	if g.kernel {
		s += "  [reboot]"
	}
	return s
}

func (t *textDoc) textAllFindings(fs []finding.Finding) {
	t.section(fmt.Sprintf("ALL FINDINGS (%d)", len(fs)))
	if len(fs) == 0 {
		t.para("", "No findings.")
		t.blank()
		return
	}
	bySev := map[finding.Severity][]finding.Finding{}
	for _, f := range fs {
		s := f.Severity
		if s.Rank() == 0 {
			s = finding.SeverityUnknown
		}
		bySev[s] = append(bySev[s], f)
	}
	n := 0
	for _, sev := range severityOrder {
		list := bySev[sev]
		if len(list) == 0 {
			continue
		}
		sortFindings(list)
		head := fmt.Sprintf("%s (%d)", strings.ToUpper(string(sev)), len(list))
		t.line(head)
		t.line(strings.Repeat("-", len(head)))
		for _, f := range list {
			n++
			num := fmt.Sprintf("%3d. ", n)
			t.para(num, titleOf(f))
			ind := "     "
			t.kvIndent(ind, "ID", f.ID)
			if f.CVE != "" {
				c := f.CVE
				if f.CVSS > 0 {
					c += fmt.Sprintf("  CVSS %.1f", f.CVSS)
				}
				t.kvIndent(ind, "CVE", c)
			} else if f.CVSS > 0 {
				t.kvIndent(ind, "CVSS", fmt.Sprintf("%.1f", f.CVSS))
			}
			if f.Package != "" {
				p := f.Package
				if inst := shortVersion(f.Package, f.Installed); inst != "" {
					p += " " + inst
				}
				if f.FixedIn != "" {
					p += " -> " + f.FixedIn
				} else if f.Category == finding.CategoryCVE {
					p += " (no fix published yet)"
				}
				t.kvIndent(ind, "Package", p)
			}
			if f.Evidence != "" {
				t.kvIndent(ind, "Evidence", f.Evidence)
			}
			if f.Remediation != "" {
				t.kvIndent(ind, "Fix", f.Remediation)
			}
			for i, ref := range f.References {
				if i == 2 {
					t.kvIndent(ind, "", fmt.Sprintf("(+%d more references in the JSON report)", len(f.References)-2))
					break
				}
				label := ""
				if i == 0 {
					label = "Refs"
				}
				t.kvIndent(ind, label, ref)
			}
			t.blank()
		}
	}
}

func (t *textDoc) textInventory(inv *InventorySummary) {
	t.section("APPLICATION INVENTORY")
	ecos := make([]string, 0, len(inv.Counts))
	for e := range inv.Counts {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	var parts []string
	for _, e := range ecos {
		parts = append(parts, fmt.Sprintf("%s %d", e, inv.Counts[e]))
	}
	comp := fmt.Sprintf("%d outside the package manager", inv.Total)
	if len(parts) > 0 {
		comp += " (" + strings.Join(parts, ", ") + ")"
	}
	t.kv("Components", comp)
	switch inv.Status {
	case "ok":
		t.kv("OSV.dev", fmt.Sprintf("%d looked up, %d with known vulnerabilities (listed under ALL FINDINGS)", inv.Queried, inv.Vulnerable))
	case "failed":
		t.kv("OSV.dev", "lookup FAILED: "+inv.Error)
	default:
		if inv.Status != "" {
			t.kv("OSV.dev", inv.Status)
		}
	}
	walk := fmt.Sprintf("%d directory entries, %d files parsed in %s", inv.Stats.Entries, inv.Stats.FilesParsed, inv.Stats.Duration.Round(time.Millisecond))
	if inv.Stats.Truncated {
		walk += " (stopped early by a limit: results are partial)"
	}
	t.kv("Walk", walk)
	t.kv("Warnings", fmt.Sprintf("%d. The full component list is in the JSON report.", inv.Warnings))
	t.blank()
}

func (t *textDoc) textCoverage(cov []finding.PackCoverage) {
	t.section("CHECK COVERAGE")
	pw := 4
	for _, c := range cov {
		pw = max(pw, min(len(c.Pack), 24))
	}
	t.line(fmt.Sprintf("%-*s %7s %11s %7s %7s %8s %5s %9s", pw, "Pack", "Checks", "Applicable", "Passed", "Failed", "Skipped", "N/A", "Disabled"))
	var tot finding.PackCoverage
	var skips []finding.CheckSkip
	var idle []string
	for _, c := range cov {
		if c.Applicable > 0 {
			t.line(fmt.Sprintf("%-*s %7d %11d %7d %7d %8d %5d %9d", pw, c.Pack, c.Checks, c.Applicable, c.Passed, c.Failed, c.Skipped, c.NotApplicable, c.Disabled))
		} else {
			idle = append(idle, c.Pack)
		}
		tot.Checks += c.Checks
		tot.Applicable += c.Applicable
		tot.Passed += c.Passed
		tot.Failed += c.Failed
		tot.Skipped += c.Skipped
		tot.NotApplicable += c.NotApplicable
		tot.Disabled += c.Disabled
		skips = append(skips, c.Skips...)
	}
	t.line(fmt.Sprintf("%-*s %7d %11d %7d %7d %8d %5d %9d", pw, "TOTAL", tot.Checks, tot.Applicable, tot.Passed, tot.Failed, tot.Skipped, tot.NotApplicable, tot.Disabled))
	if len(idle) > 0 {
		t.blank()
		t.para("", fmt.Sprintf("%d packs did not apply to this host (software not present, or every check disabled; counted in TOTAL): %s",
			len(idle), strings.Join(idle, ", ")))
	}
	if len(skips) > 0 {
		t.blank()
		t.line("Skipped checks (could not decide on this host):")
		for i, s := range skips {
			if i == 10 {
				t.para("  ", fmt.Sprintf("... +%d more in the JSON report", len(skips)-10))
				break
			}
			t.para("  - ", s.Check+": "+s.Reason)
		}
	}
	t.blank()
}

// --- grouping and commands ---------------------------------------------------

// groupByPackage groups CVE findings by package. OS packages and
// application components (inventory findings) are returned separately,
// each sorted worst severity first, then by finding count.
func groupByPackage(cves []finding.Finding) (osGroups, appGroups, nodeGroups []*pkgGroup) {
	idx := map[string]*pkgGroup{}
	var order []*pkgGroup
	for _, f := range cves {
		node := isNodeFinding(f)
		app := node || isAppFinding(f)
		name := f.Package
		inst := shortVersion(f.Package, f.Installed)
		switch {
		case node:
			name, inst = nodeInstallPath(f), f.Installed
		case !app:
			name, _, _ = strings.Cut(name, ":")
		}
		if name == "" {
			name = "(unknown package)"
		}
		key := fmt.Sprintf("%t|%t|%s|%s", node, app, name, inst)
		g := idx[key]
		if g == nil {
			g = &pkgGroup{name: name, installed: inst, app: app, node: node, kernel: !app && isKernelPackage(name)}
			idx[key] = g
			order = append(order, g)
		}
		g.findings = append(g.findings, f)
		g.worst = max(g.worst, f.Severity.Rank())
		if f.FixedIn == "" {
			g.unfixed++
		} else if g.fixed == "" || matcher.CompareNEVR(f.FixedIn, g.fixed) > 0 {
			g.fixed = f.FixedIn
			if app {
				g.fix = f.Remediation
			}
		}
		if app && g.fix == "" {
			g.fix = f.Remediation
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.worst != b.worst {
			return a.worst > b.worst
		}
		if len(a.findings) != len(b.findings) {
			return len(a.findings) > len(b.findings)
		}
		return a.name < b.name
	})
	for _, g := range order {
		switch {
		case g.node:
			nodeGroups = append(nodeGroups, g)
		case g.app:
			appGroups = append(appGroups, g)
		default:
			osGroups = append(osGroups, g)
		}
	}
	return osGroups, appGroups, nodeGroups
}

// isNodeFinding: an upstream Node.js finding (internal/upstream: Source
// nodejs-release, nodejs-security-wg, nodejs-security-wg+nvd). These are
// fixed per binary (nvm, tarball, NodeSource...), not by the OS package
// update command.
func isNodeFinding(f finding.Finding) bool {
	return strings.HasPrefix(f.Source, "nodejs") && strings.HasPrefix(f.ID, "upstream:node-")
}

// nodeInstallPath is the binary path (or image:<ref>) an upstream Node
// finding is about: "upstream:node-cve:<CVE>:<path>" or
// "upstream:node-security-release:<path>".
func nodeInstallPath(f finding.Finding) string {
	if p, ok := strings.CutPrefix(f.ID, "upstream:node-security-release:"); ok {
		return p
	}
	if rest, ok := strings.CutPrefix(f.ID, "upstream:node-cve:"); ok {
		if _, p, ok := strings.Cut(rest, ":"); ok {
			return p
		}
	}
	return f.Package
}

// isAppFinding: an application-inventory finding (ID "<vuln>:<eco>/<name>@<path>")
// rather than an OS package matched by the distro feeds.
func isAppFinding(f finding.Finding) bool {
	return f.Package != "" && strings.Contains(f.ID, "/"+f.Package+"@")
}

func isKernelPackage(name string) bool {
	switch {
	case name == "kernel", strings.HasPrefix(name, "kernel-"),
		strings.HasPrefix(name, "linux-image"), name == "linux-lts", name == "linux-virt":
		return true
	}
	return false
}

// shortVersion strips the "<name>-" prefix and ".<arch>" suffix that RPM
// NEVRA strings carry, leaving "[epoch:]version-release". Debian
// multi-arch names ("libssl3:amd64") carry the arch in the name too.
func shortVersion(pkg, installed string) string {
	name, _, _ := strings.Cut(pkg, ":")
	v := installed
	if strings.HasPrefix(v, pkg+"-") {
		v = v[len(pkg)+1:]
	} else {
		v = strings.TrimPrefix(v, name+"-")
	}
	for _, arch := range []string{".x86_64", ".aarch64", ".noarch", ".i686", ".i386", ".ppc64le", ".s390x", ".amd64", ".arm64", ".all"} {
		if strings.HasSuffix(v, arch) {
			return strings.TrimSuffix(v, arch)
		}
	}
	return v
}

// osFamily maps os-release ID/ID_LIKE to a package-manager family.
func osFamily(o collector.OSInfo) string {
	ids := append([]string{o.ID}, o.IDLike...)
	for _, id := range ids {
		switch strings.ToLower(id) {
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "redhat":
			return "rpm"
		case "debian", "ubuntu":
			return "deb"
		case "alpine":
			return "apk"
		case "suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed":
			return "zypper"
		}
	}
	return ""
}

// updateCommand is one command that updates every package in pkgs on o's
// package manager, or "" when the family is unknown.
func updateCommand(o collector.OSInfo, pkgs []string) string {
	if len(pkgs) == 0 {
		return ""
	}
	list := strings.Join(pkgs, " ")
	switch osFamily(o) {
	case "rpm":
		major, _, _ := strings.Cut(o.VersionID, ".")
		if n, err := strconv.Atoi(major); err == nil && n < 8 && strings.ToLower(o.ID) != "fedora" {
			return "yum update " + list
		}
		return "dnf upgrade --refresh " + list
	case "deb":
		return "apt-get update && apt-get install --only-upgrade " + list
	case "apk":
		return "apk update && apk upgrade " + list
	case "zypper":
		return "zypper refresh && zypper update " + list
	}
	return ""
}

// --- ordering and labels -----------------------------------------------------

// sortFindings orders by severity, then CVE findings before the rest,
// then CVSS (highest first), then ID.
func sortFindings(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		ac, bc := a.Category == finding.CategoryCVE, b.Category == finding.CategoryCVE
		if ac != bc {
			return ac
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.ID < b.ID
	})
}

func titleOf(f finding.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	if f.CVE != "" {
		return f.CVE + " affects " + f.Package
	}
	return f.ID
}

func severityBreakdown(fs []finding.Finding) string {
	c := map[finding.Severity]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	var parts []string
	for _, s := range severityOrder {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], strings.ToLower(string(s))))
		}
	}
	return strings.Join(parts, ", ")
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func utc(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// --- text layout -------------------------------------------------------------

type textDoc struct{ b strings.Builder }

func (t *textDoc) String() string { return t.b.String() }

func (t *textDoc) line(s string) {
	t.b.WriteString(s)
	t.b.WriteByte('\n')
}

func (t *textDoc) blank() { t.line("") }

func (t *textDoc) rule(c byte) { t.line(strings.Repeat(string(c), textWidth)) }

func (t *textDoc) section(title string) {
	t.line(title)
	t.rule('-')
}

// para writes s wrapped to the page width; the first line starts with
// prefix and continuation lines are indented to match it.
func (t *textDoc) para(prefix, s string) {
	w := utf8.RuneCountInString(prefix)
	indent := strings.Repeat(" ", w)
	if strings.HasPrefix(prefix, "!!") {
		indent = prefix
	}
	for i, l := range wrapText(s, textWidth-w) {
		if i == 0 {
			t.line(strings.TrimRight(prefix+l, " "))
		} else {
			t.line(strings.TrimRight(indent+l, " "))
		}
	}
}

// kv writes a "Label       value" row with the value wrapped under itself.
func (t *textDoc) kv(label, value string) { t.kvIndent("", label, value) }

func (t *textDoc) kvIndent(indent, label, value string) {
	if value == "" {
		value = "-"
	}
	t.para(indent+padRight(label, labelW-2)+"  ", value)
}

// command writes a shell command, continuing long ones with " \" so the
// wrapped text still pastes as one command.
func (t *textDoc) command(indent, cmd string) {
	width := textWidth - utf8.RuneCountInString(indent) - 2
	words := strings.Fields(cmd)
	cur := ""
	var lines []string
	for _, w := range words {
		if cur != "" && utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) > width {
			lines = append(lines, cur)
			cur = "  " + w
			continue
		}
		if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	for i, l := range lines {
		if i < len(lines)-1 {
			l += " \\"
		}
		t.line(indent + l)
	}
}

func padRight(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

// wrapText word-wraps s to width columns. Existing newlines are kept,
// tabs become spaces, other control characters are dropped, and words
// longer than width (URLs, paths) are split hard.
func wrapText(s string, width int) []string {
	if width < 10 {
		width = 10
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur, curN := "", 0
		for _, w := range words {
			wn := utf8.RuneCountInString(w)
			for wn > width {
				if curN > 0 {
					out = append(out, cur)
					cur, curN = "", 0
				}
				head, tail := splitRunes(w, width)
				out = append(out, head)
				w, wn = tail, wn-width
			}
			switch {
			case curN == 0:
				cur, curN = w, wn
			case curN+1+wn <= width:
				cur += " " + w
				curN += 1 + wn
			default:
				out = append(out, cur)
				cur, curN = w, wn
			}
		}
		if curN > 0 {
			out = append(out, cur)
		}
	}
	return out
}

func splitRunes(s string, n int) (string, string) {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos], s[pos:]
		}
		i++
	}
	return s, ""
}
