package notify

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

// Message is one notification, rendered per channel.
type Message struct {
	Event        string // changes | baseline | digest | test
	Host         string
	OS           string
	Generated    time.Time
	MinSeverity  string
	ReportJSON   string
	ReportPDF    string
	Counts       map[finding.Severity]int
	Total        int
	New          []finding.Finding
	FixAvailable []finding.Finding
	Resolved     []finding.Finding
	Current      []finding.Finding // baseline / digest
	Sources      *feed.ScanSources
	Commands     []string // host-level remediation commands
	manager      string
}

func baseMessage(facts *collector.Facts, all []finding.Finding, src *feed.ScanSources, jsonPath, pdfPath, minSev string, now time.Time) *Message {
	m := &Message{Generated: now, MinSeverity: minSev, ReportJSON: jsonPath, ReportPDF: pdfPath, Sources: src,
		Counts: map[finding.Severity]int{}, Total: len(all)}
	if facts != nil {
		m.Host = facts.Hostname
		m.OS = facts.OS.PrettyName
		if len(facts.Packages) > 0 {
			m.manager = facts.Packages[0].Manager
		}
	}
	for _, f := range all {
		m.Counts[f.Severity]++
	}
	return m
}

func (m *Message) clone(event string) *Message {
	c := *m
	c.Event = event
	return &c
}

// remediationCommands builds package-manager commands for the CVE
// findings in fs (binary names, arch suffix stripped).
func remediationCommands(manager string, fs []finding.Finding) []string {
	seen := map[string]bool{}
	var pkgs []string
	for _, f := range fs {
		if f.Category != finding.CategoryCVE || f.Package == "" {
			continue
		}
		p, _, _ := strings.Cut(f.Package, ":")
		if !seen[p] {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		return nil
	}
	sort.Strings(pkgs)
	list := strings.Join(pkgs, " ")
	switch manager {
	case "rpm":
		return []string{"dnf upgrade --refresh " + list, "dnf upgrade --security   # all pending security errata"}
	case "dpkg":
		return []string{"apt-get update && apt-get install --only-upgrade " + list}
	case "apk":
		return []string{"apk update && apk upgrade " + list}
	}
	return nil
}

func (m *Message) actionable() []finding.Finding {
	switch m.Event {
	case "baseline", "digest":
		return m.Current
	}
	return append(append([]finding.Finding{}, m.New...), m.FixAvailable...)
}

// Subject is the one-line headline.
func (m *Message) Subject() string {
	host := m.Host
	if host == "" {
		host = "host"
	}
	switch m.Event {
	case "test":
		return fmt.Sprintf("[lync] test notification from %s", host)
	case "baseline":
		return fmt.Sprintf("[lync] %s: monitoring started, %d finding(s) at %s or above", host, len(m.Current), m.MinSeverity)
	case "digest":
		return fmt.Sprintf("[lync] %s: digest, %d open finding(s) at %s or above", host, len(m.Current), m.MinSeverity)
	}
	var parts []string
	if len(m.New) > 0 {
		parts = append(parts, fmt.Sprintf("%d new", len(m.New)))
	}
	if len(m.FixAvailable) > 0 {
		parts = append(parts, fmt.Sprintf("%d fix available", len(m.FixAvailable)))
	}
	if len(m.Resolved) > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", len(m.Resolved)))
	}
	worst := ""
	for _, f := range m.New {
		if worst == "" || f.Severity.Rank() > finding.Severity(worst).Rank() {
			worst = string(f.Severity)
		}
	}
	if worst != "" {
		worst = " (worst: " + worst + ")"
	}
	return fmt.Sprintf("[lync] %s: %s%s", host, strings.Join(parts, ", "), worst)
}

func itemLine(f finding.Finding) string {
	label := f.Title
	if f.CVE != "" {
		label = f.CVE + " in " + f.Package
	}
	if label == "" {
		label = f.ID
	}
	s := fmt.Sprintf("[%s] %s", f.Severity, label)
	if f.CVSS > 0 {
		s += fmt.Sprintf(" (CVSS %.1f)", f.CVSS)
	}
	if f.Installed != "" && f.FixedIn != "" {
		s += fmt.Sprintf(": installed %s, fixed in %s", f.Installed, f.FixedIn)
	} else if f.FixedIn != "" {
		s += ", fixed in " + f.FixedIn
	}
	return s
}

func incompleteNote(src *feed.ScanSources) string {
	if src == nil || src.Complete {
		return ""
	}
	return "WARNING: the CVE section of this scan is incomplete: " + strings.Join(src.IncompleteReasons, "; ")
}

const textLimit = 200

// Text renders the plain-text body.
func (m *Message) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nHost: %s (%s)\nScan: %s\n", m.Subject(), m.Host, m.OS, m.Generated.UTC().Format(time.RFC3339))
	if m.Event == "test" {
		b.WriteString("\nThis is a test notification from Lync. If you can read it, this channel works.\n")
		return b.String()
	}
	if n := incompleteNote(m.Sources); n != "" {
		b.WriteString("\n" + n + "\n")
	}
	section := func(title string, fs []finding.Finding, withFix bool) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", title, len(fs))
		for i, f := range fs {
			if i == textLimit {
				fmt.Fprintf(&b, "  ... and %d more (see the report)\n", len(fs)-textLimit)
				break
			}
			fmt.Fprintf(&b, "  - %s\n", itemLine(f))
			if withFix && f.Remediation != "" {
				fmt.Fprintf(&b, "      fix: %s\n", f.Remediation)
			}
		}
	}
	section("New findings", m.New, true)
	section("Fix now available", m.FixAvailable, true)
	section("Resolved", m.Resolved, false)
	section("Open findings", m.Current, true)
	if cmds := remediationCommands(m.manager, m.actionable()); len(cmds) > 0 {
		b.WriteString("\nTo update the affected packages:\n")
		for _, c := range cmds {
			b.WriteString("  " + c + "\n")
		}
	}
	fmt.Fprintf(&b, "\nTotals for this scan: %s\n", countsLine(m.Counts, m.Total))
	if m.ReportPDF != "" {
		fmt.Fprintf(&b, "Report on the host: %s\n", m.ReportPDF)
	}
	return b.String()
}

func countsLine(c map[finding.Severity]int, total int) string {
	return fmt.Sprintf("%d total: %d critical, %d high, %d medium, %d low, %d unknown",
		total, c[finding.SeverityCritical], c[finding.SeverityHigh], c[finding.SeverityMedium], c[finding.SeverityLow], c[finding.SeverityUnknown])
}

var sevHex = map[finding.Severity]string{
	finding.SeverityCritical: "#b00020", finding.SeverityHigh: "#d84315", finding.SeverityMedium: "#f57c00",
	finding.SeverityLow: "#9e9d24", finding.SeverityInfo: "#546e7a", finding.SeverityUnknown: "#9e9e9e",
}

// HTML renders the HTML body (inline styles only, for mail clients).
func (m *Message) HTML() string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body style="font-family:Helvetica,Arial,sans-serif;color:#1c1c23;font-size:14px">`)
	fmt.Fprintf(&b, `<h2 style="margin:0 0 4px">%s</h2><p style="color:#666;margin:0 0 12px">%s &middot; %s &middot; %s</p>`,
		e(m.Subject()), e(m.Host), e(m.OS), e(m.Generated.UTC().Format(time.RFC3339)))
	if m.Event == "test" {
		b.WriteString(`<p>This is a test notification from Lync. If you can read it, this channel works.</p></body></html>`)
		return b.String()
	}
	if n := incompleteNote(m.Sources); n != "" {
		fmt.Fprintf(&b, `<p style="background:#fdecea;border-left:4px solid #b00020;padding:8px;color:#b00020"><b>%s</b></p>`, e(n))
	}
	section := func(title string, fs []finding.Finding, withFix bool) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, `<h3 style="margin:16px 0 6px">%s (%d)</h3><table style="border-collapse:collapse;width:100%%">`, e(title), len(fs))
		for i, f := range fs {
			if i == textLimit {
				fmt.Fprintf(&b, `<tr><td colspan="2">... and %d more (see the report)</td></tr>`, len(fs)-textLimit)
				break
			}
			fix := ""
			if withFix && f.Remediation != "" {
				fix = `<br><code style="color:#444">` + e(f.Remediation) + `</code>`
			}
			fmt.Fprintf(&b, `<tr><td style="padding:4px 8px;vertical-align:top;white-space:nowrap;color:%s;font-weight:bold">%s</td><td style="padding:4px 8px;border-bottom:1px solid #eee">%s%s</td></tr>`,
				sevHex[f.Severity], e(string(f.Severity)), e(strings.TrimPrefix(itemLine(f), "["+string(f.Severity)+"] ")), fix)
		}
		b.WriteString(`</table>`)
	}
	section("New findings", m.New, true)
	section("Fix now available", m.FixAvailable, true)
	section("Resolved", m.Resolved, false)
	section("Open findings", m.Current, true)
	if cmds := remediationCommands(m.manager, m.actionable()); len(cmds) > 0 {
		b.WriteString(`<h3 style="margin:16px 0 6px">To update the affected packages</h3><pre style="background:#f4f4f6;padding:8px">`)
		for _, c := range cmds {
			b.WriteString(e(c) + "\n")
		}
		b.WriteString(`</pre>`)
	}
	fmt.Fprintf(&b, `<p style="color:#666">Totals for this scan: %s`, e(countsLine(m.Counts, m.Total)))
	if m.ReportPDF != "" {
		fmt.Fprintf(&b, `<br>Report on the host: <code>%s</code>`, e(m.ReportPDF))
	}
	b.WriteString(`</p></body></html>`)
	return b.String()
}

// --- generic JSON payload ----------------------------------------------------

// Payload is the documented generic webhook body (schema lync.notification/v1).
type Payload struct {
	Schema       string            `json:"schema"`
	Event        string            `json:"event"`
	Host         string            `json:"host"`
	OS           string            `json:"os"`
	Generated    time.Time         `json:"generated"`
	Summary      string            `json:"summary"`
	MinSeverity  string            `json:"min_severity"`
	Counts       map[string]int    `json:"counts"`
	New          []PayloadItem     `json:"new"`
	FixAvailable []PayloadItem     `json:"fix_available"`
	Resolved     []PayloadItem     `json:"resolved"`
	Current      []PayloadItem     `json:"current,omitempty"`
	Commands     []string          `json:"remediation_commands,omitempty"`
	Report       map[string]string `json:"report,omitempty"`
	DataSources  *feed.ScanSources `json:"data_sources,omitempty"`
}

// PayloadItem is one finding in a generic payload.
type PayloadItem struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category,omitempty"`
	Title       string  `json:"title,omitempty"`
	CVE         string  `json:"cve,omitempty"`
	Package     string  `json:"package,omitempty"`
	Installed   string  `json:"installed,omitempty"`
	FixedIn     string  `json:"fixed_in,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Source      string  `json:"source,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
}

func items(fs []finding.Finding) []PayloadItem {
	out := make([]PayloadItem, 0, len(fs))
	for _, f := range fs {
		out = append(out, PayloadItem{ID: f.ID, Severity: string(f.Severity), Category: string(f.Category), Title: f.Title,
			CVE: f.CVE, Package: f.Package, Installed: f.Installed, FixedIn: f.FixedIn, CVSS: f.CVSS, Source: f.Source, Remediation: f.Remediation})
	}
	return out
}

// Payload builds the generic JSON body.
func (m *Message) Payload() Payload {
	p := Payload{
		Schema: "lync.notification/v1", Event: m.Event, Host: m.Host, OS: m.OS, Generated: m.Generated.UTC(),
		Summary: m.Subject(), MinSeverity: m.MinSeverity, Counts: map[string]int{"total": m.Total},
		New: items(m.New), FixAvailable: items(m.FixAvailable), Resolved: items(m.Resolved),
		Commands: remediationCommands(m.manager, m.actionable()), DataSources: m.Sources,
	}
	if m.Current != nil {
		p.Current = items(m.Current)
	}
	for sev, n := range m.Counts {
		p.Counts[strings.ToLower(string(sev))] = n
	}
	if m.ReportJSON != "" || m.ReportPDF != "" {
		p.Report = map[string]string{"json": m.ReportJSON, "pdf": m.ReportPDF}
	}
	return p
}
