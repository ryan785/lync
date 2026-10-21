package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

var severityColors = map[finding.Severity][3]int{
	finding.SeverityCritical: {176, 0, 32},
	finding.SeverityHigh:     {216, 67, 21},
	finding.SeverityMedium:   {245, 124, 0},
	finding.SeverityLow:      {158, 157, 36},
	finding.SeverityInfo:     {84, 110, 122},
	finding.SeverityUnknown:  {158, 158, 158},
}

const (
	pageW       = 210.0
	contentL    = 15.0
	contentR    = 195.0
	contentW    = contentR - contentL
	headerH     = 14.0
	footerH     = 12.0
	bottomLimit = 285.0 // y where new cards force a page break
)

type pdfWriter struct {
	pdf  *fpdf.Fpdf
	host string
	when time.Time
}

// WritePDFFromJSON reads the canonical JSON report and renders it as PDF.
// Used by the daemon (write-once-render-once) and the `lync render` command
// (re-render arbitrary past reports without rerunning a scan).
func WritePDFFromJSON(jsonPath, pdfPath string) error {
	r, err := ReadJSON(jsonPath)
	if err != nil {
		return err
	}
	return WritePDF(pdfPath, r)
}

// WritePDF renders a Report to the given path. Takes the canonical struct
// directly; the BuildReport / ReadJSON helpers produce one.
func WritePDF(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	when := r.Generated
	if when.IsZero() {
		when = time.Now()
	}
	w := &pdfWriter{
		pdf:  fpdf.New("P", "mm", "A4", ""),
		host: r.Host,
		when: when,
	}
	w.pdf.SetMargins(contentL, headerH+6, contentL)
	w.pdf.SetAutoPageBreak(true, footerH+3)
	w.pdf.AliasNbPages("")
	w.pdf.SetHeaderFunc(w.drawHeader)
	w.pdf.SetFooterFunc(w.drawFooter)
	w.pdf.AddPage()

	w.drawTitle()
	w.drawHostBlock(r)
	w.drawDataSources(r.DataSources)
	w.divider()
	w.drawExecSummary(r.Impact, r.DataSources)
	w.divider()
	w.drawSeverityChart(r.Impact)
	w.divider()
	if r.Inventory != nil {
		w.drawInventory(r.Inventory)
		w.divider()
	}
	w.drawFindings(r.Findings)
	return w.pdf.OutputFileAndClose(path)
}

func (w *pdfWriter) drawHeader() {
	pdf := w.pdf
	pdf.SetFillColor(28, 28, 35)
	pdf.Rect(0, 0, pageW, headerH, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetXY(contentL, 4)
	pdf.Cell(40, 6, "LYNC")
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(contentL, 4)
	right := fmt.Sprintf("%s  |  %s", w.host, w.when.Format("2006-01-02 15:04 MST"))
	pdf.CellFormat(contentW, 6, right, "", 0, "R", false, 0, "")
	// accent stripe
	pdf.SetFillColor(216, 67, 21)
	pdf.Rect(0, headerH, pageW, 0.6, "F")
	pdf.SetTextColor(0, 0, 0)
	// Place cursor below header so subsequent drawing on continuation pages
	// doesn't overlap the header band.
	pdf.SetXY(contentL, headerH+6)
}

func (w *pdfWriter) drawFooter() {
	pdf := w.pdf
	pdf.SetY(-footerH)
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetTextColor(140, 140, 140)
	left := fmt.Sprintf("lync %s", w.when.Format(time.RFC3339))
	pdf.CellFormat(contentW/2, 4, left, "", 0, "L", false, 0, "")
	pdf.CellFormat(contentW/2, 4, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

func (w *pdfWriter) drawTitle() {
	pdf := w.pdf
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(28, 28, 35)
	pdf.Cell(0, 10, "Vulnerability Report")
	pdf.Ln(11)
}

func (w *pdfWriter) drawHostBlock(r *Report) {
	pdf := w.pdf
	rows := [][2]string{
		{"Host", r.Host},
		{"OS", r.OS.PrettyName},
		{"Kernel", r.Kernel.Release},
		{"Packages", strconv.Itoa(r.PkgCount)},
		{"Services", strconv.Itoa(r.Impact.RunningServicesCount) + " running"},
		{"Scanned", w.when.Format(time.RFC3339)},
	}
	for _, r := range rows {
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(120, 120, 120)
		pdf.Cell(25, 5, r[0])
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(20, 20, 20)
		pdf.Cell(0, 5, r[1])
		pdf.Ln(5)
	}
	pdf.SetTextColor(0, 0, 0)
}

func (w *pdfWriter) divider() {
	pdf := w.pdf
	y := pdf.GetY() + 3
	pdf.SetDrawColor(225, 225, 230)
	pdf.SetLineWidth(0.3)
	pdf.Line(contentL, y, contentR, y)
	pdf.SetXY(contentL, y+4)
}

func (w *pdfWriter) sectionTitle(t string) {
	pdf := w.pdf
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(28, 28, 35)
	pdf.Cell(0, 6, t)
	pdf.Ln(7)
}

func (w *pdfWriter) drawExecSummary(s ImpactSummary, ds *feed.ScanSources) {
	pdf := w.pdf
	w.sectionTitle("Executive summary")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(20, 20, 20)

	if s.TotalFindings == 0 {
		msg := "No vulnerabilities detected on this host."
		if incompleteText(ds) != "" {
			msg = "No findings from the checks that completed. The CVE section is INCOMPLETE (see Data sources above), so this does not mean the host is free of known vulnerabilities."
		}
		pdf.MultiCell(contentW, 5, msg, "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		return
	}

	lead := fmt.Sprintf("Detected %d vulnerabilities affecting %d packages across this host.",
		s.TotalFindings, s.UniquePackageCount)
	pdf.MultiCell(contentW, 5, lead, "", "L", false)
	pdf.Ln(2)

	if s.HighestCVSSCVE != "" {
		w.summaryBullet(176, 0, 32,
			fmt.Sprintf("Highest CVSS: %.1f", s.HighestCVSS),
			fmt.Sprintf("(%s, %s)", s.HighestCVSSCVE, s.HighestCVSSPackage))
	}
	if s.NeedsReboot {
		var head string
		switch {
		case s.KernelFindings == 1 && len(s.KernelCVEs) == 1:
			head = fmt.Sprintf("Kernel: %s affects the running kernel", s.KernelCVEs[0])
		case len(s.KernelCVEs) <= 3:
			head = fmt.Sprintf("Kernel: %d CVEs affect the running kernel (%s)",
				s.KernelFindings, strings.Join(s.KernelCVEs, ", "))
		default:
			head = fmt.Sprintf("Kernel: %d CVEs affect the running kernel (%s, +%d more)",
				s.KernelFindings,
				strings.Join(s.KernelCVEs[:3], ", "),
				len(s.KernelCVEs)-3)
		}
		w.summaryBullet(216, 67, 21, head, "- reboot required after updating the kernel package.")
	}
	if len(s.ActiveServicesAffected) > 0 {
		list := s.ActiveServicesAffected
		var trailer string
		if len(list) > 8 {
			trailer = fmt.Sprintf(" + %d more", len(list)-8)
			list = list[:8]
		}
		pdf.SetX(contentL)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(216, 67, 21)
		pdf.Cell(0, 5, "Active services affected:")
		pdf.Ln(5)
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(20, 20, 20)
		pdf.SetX(contentL + 4)
		pdf.MultiCell(contentW-4, 5, strings.Join(list, ", ")+trailer, "", "L", false)
	}
	pdf.SetTextColor(0, 0, 0)
}

// summaryBullet renders a two-tone line: a colored heading followed by a
// neutral tail. Uses measured string widths so a long heading doesn't
// truncate the tail.
func (w *pdfWriter) summaryBullet(r, g, b int, head, tail string) {
	pdf := w.pdf
	pdf.SetX(contentL)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(r, g, b)
	headW := pdf.GetStringWidth(head) + 1
	pdf.Cell(headW, 5, head)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	pdf.Cell(0, 5, tail)
	pdf.Ln(6)
}

func (w *pdfWriter) drawSeverityChart(s ImpactSummary) {
	pdf := w.pdf
	w.sectionTitle("Severity distribution")
	pdf.SetFont("Helvetica", "", 9)

	max := 1
	for _, c := range s.CountsList {
		if c.Count > max {
			max = c.Count
		}
	}

	const barMax = 130.0
	const rowH = 6.0
	for _, c := range s.CountsList {
		y := pdf.GetY()
		pdf.SetTextColor(60, 60, 60)
		pdf.SetXY(contentL, y+0.7)
		pdf.CellFormat(22, rowH-1, string(c.Severity), "", 0, "L", false, 0, "")

		col := severityColors[c.Severity]
		// background track
		pdf.SetFillColor(238, 238, 240)
		pdf.Rect(contentL+22, y+1.2, barMax, rowH-2.4, "F")
		// filled portion
		if c.Count > 0 {
			pdf.SetFillColor(col[0], col[1], col[2])
			barLen := barMax * float64(c.Count) / float64(max)
			if barLen < 1.5 {
				barLen = 1.5
			}
			pdf.Rect(contentL+22, y+1.2, barLen, rowH-2.4, "F")
		}
		pdf.SetTextColor(20, 20, 20)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetXY(contentL+22+barMax+3, y+0.7)
		pdf.Cell(0, rowH-1, strconv.Itoa(c.Count))
		pdf.SetFont("Helvetica", "", 9)
		pdf.Ln(rowH)
	}
	pdf.SetTextColor(0, 0, 0)
}

func (w *pdfWriter) drawFindings(findings []finding.Finding) {
	pdf := w.pdf

	cveFindings, otherFindings := splitFindings(findings)

	// CVE section — sorted by CVSS descending (operators care about
	// "what scored worst", not "which CVE id is newest"). Severity rank
	// breaks CVSS ties; CVE id is the last tiebreak so output is stable.
	sort.Slice(cveFindings, func(i, j int) bool {
		if cveFindings[i].CVSS != cveFindings[j].CVSS {
			return cveFindings[i].CVSS > cveFindings[j].CVSS
		}
		if cveFindings[i].Severity.Rank() != cveFindings[j].Severity.Rank() {
			return cveFindings[i].Severity.Rank() > cveFindings[j].Severity.Rank()
		}
		return cveFindings[i].CVE > cveFindings[j].CVE
	})
	// Non-CVE section — severity desc, then ID asc for stability.
	sort.Slice(otherFindings, func(i, j int) bool {
		if otherFindings[i].Severity.Rank() != otherFindings[j].Severity.Rank() {
			return otherFindings[i].Severity.Rank() > otherFindings[j].Severity.Rank()
		}
		return otherFindings[i].ID < otherFindings[j].ID
	})

	if len(cveFindings) > 0 {
		w.sectionTitle(fmt.Sprintf("Vulnerabilities  (%d CVE findings, highest CVSS first)", len(cveFindings)))
		for i, f := range cveFindings {
			w.drawFindingCard(f, i%2 == 1)
		}
	}

	if len(otherFindings) > 0 {
		// Fresh page for the non-CVE section so configuration and runtime
		// findings don't get visually mashed against CVE cards — unless
		// the CVE section's last card already pushed us onto a new page,
		// in which case AddPage would insert an empty one. headerH is the
		// dark banner; +20mm lets us tell "near the top of a new page"
		// from "middle of a page that already has content".
		if pdf.GetY() > headerH+20 {
			pdf.AddPage()
		}
		w.sectionTitle(fmt.Sprintf("Configuration & Runtime  (%d findings)", len(otherFindings)))
		for i, f := range otherFindings {
			w.drawFindingCard(f, i%2 == 1)
		}
	}

	if len(findings) == 0 {
		w.sectionTitle("Findings")
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(120, 120, 120)
		pdf.Cell(0, 5, "No findings.")
		pdf.SetTextColor(0, 0, 0)
	}
}

// splitFindings partitions findings into "CVE matches" and "everything else
// (rules, monitor, EOL, etc.)". CVE findings are identified by the cve
// category — they're the ones the matcher emits.
func splitFindings(findings []finding.Finding) (cve, other []finding.Finding) {
	for _, f := range findings {
		if f.Category == finding.CategoryCVE {
			cve = append(cve, f)
		} else {
			other = append(other, f)
		}
	}
	return
}

func (w *pdfWriter) drawFindingCard(f finding.Finding, shaded bool) {
	pdf := w.pdf
	sev := severityColors[f.Severity]

	const barW = 2.8
	const labelW = 22.0
	const lineH = 4.2
	const titleH = 5.5
	const padBottom = 1.5
	contentX := contentL + barW + 3.5
	innerW := contentW - barW - 4
	valueW := innerW - labelW

	// Build body rows. CVE findings use the structured per-field set; rule
	// findings additionally show their Evidence row because that's the
	// concrete observation the title summarizes.
	type bodyRow struct{ label, value string }
	var rows []bodyRow
	if f.CVE == "" && f.Evidence != "" {
		rows = append(rows, bodyRow{"Detail", f.Evidence})
	}
	if f.FixedIn != "" {
		rows = append(rows, bodyRow{"Fixed in", f.FixedIn})
	}
	if f.CVSS > 0 {
		rows = append(rows, bodyRow{"CVSS", fmt.Sprintf("%.1f", f.CVSS)})
	}
	if f.Installed != "" && f.CVE != "" {
		rows = append(rows, bodyRow{"Installed", f.Installed})
	}
	if f.Source != "" {
		rows = append(rows, bodyRow{"Source", f.Source})
	}
	if f.Remediation != "" {
		rows = append(rows, bodyRow{"Fix", f.Remediation})
	}

	// Pre-measure: wrap each value at valueW and count lines so cardH
	// matches what we'll actually render. Without this the colored
	// severity bar would be the wrong height when text wraps.
	pdf.SetFont("Helvetica", "", 8.5)
	bodyH := 0.0
	rowLineCounts := make([]int, len(rows))
	for i, r := range rows {
		ls := pdf.SplitLines([]byte(r.value), valueW)
		n := len(ls)
		if n < 1 {
			n = 1
		}
		rowLineCounts[i] = n
		bodyH += float64(n) * lineH
	}
	cardH := titleH + bodyH + padBottom

	if pdf.GetY()+cardH > bottomLimit {
		pdf.AddPage()
	}
	y := pdf.GetY()

	if shaded {
		pdf.SetFillColor(247, 247, 250)
		pdf.Rect(contentL, y, contentW, cardH, "F")
	}
	pdf.SetFillColor(sev[0], sev[1], sev[2])
	pdf.Rect(contentL, y, barW, cardH, "F")

	// Title row — CVE findings show "CVE-ID   package", rule findings
	// show the rule's Title verbatim. Severity badge right-aligned.
	pdf.SetXY(contentX, y+1.5)
	pdf.SetFont("Helvetica", "B", 10.5)
	pdf.SetTextColor(20, 20, 25)
	var titleText string
	if f.CVE != "" {
		titleText = fmt.Sprintf("%s   %s", f.CVE, f.Package)
	} else {
		titleText = f.Title
	}
	pdf.Cell(innerW-30, 5, titleText)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetTextColor(sev[0], sev[1], sev[2])
	pdf.CellFormat(30, 5, strings.ToUpper(string(f.Severity)), "", 0, "R", false, 0, "")
	pdf.Ln(titleH - 0.5)

	// Body — MultiCell so long values (Fix/Remediation in particular)
	// wrap inside the card instead of running off the right edge.
	for i, r := range rows {
		rowY := pdf.GetY()
		pdf.SetXY(contentX, rowY)
		pdf.SetTextColor(125, 125, 130)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.Cell(labelW, lineH, r.label)
		pdf.SetTextColor(40, 40, 45)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(valueW, lineH, r.value, "", "L", false)
		// MultiCell returns X to left margin; explicit Y in case the row
		// height got out of sync with our pre-computation (e.g. a long
		// CJK glyph wraps differently than SplitLines guessed).
		_ = rowY
		_ = rowLineCounts[i]
	}

	pdf.SetTextColor(0, 0, 0)
	// Snap to predicted end-of-card so the next card starts cleanly even
	// if MultiCell's line count diverged from our pre-measure by a hair.
	pdf.SetY(y + cardH)
}

// drawDataSources lists where the CVE data came from (mode, sources,
// request counts, timestamp) and, when a source failed, a red banner
// saying the CVE section is incomplete.
func (w *pdfWriter) drawDataSources(ds *feed.ScanSources) {
	if ds == nil {
		return
	}
	pdf := w.pdf
	pdf.Ln(2)
	mode := feedModeText(ds)
	label := func(k string) {
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(120, 120, 120)
		pdf.Cell(25, 5, k)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(20, 20, 20)
	}
	label("CVE data")
	pdf.MultiCell(contentW-25, 5, mode, "", "L", false)
	checked := ds.CheckedAt.Format(time.RFC3339)
	if ds.PackagesChecked > 0 {
		checked += fmt.Sprintf("  -  %d packages checked", ds.PackagesChecked)
	}
	if ds.Ecosystem != "" {
		checked += "  -  ecosystem " + ds.Ecosystem
	}
	label("Checked")
	pdf.MultiCell(contentW-25, 5, checked, "", "L", false)
	for _, s := range ds.Sources {
		line := sourceLine(s)
		label("Source")
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(contentW-25, 4.5, line, "", "L", false)
	}
	if ds.UnfixedCVEs > 0 {
		label("No fix yet")
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(contentW-25, 4.5, unfixedText(ds.UnfixedCVEs), "", "L", false)
	}
	if text := incompleteText(ds); text != "" {
		pdf.Ln(1)
		pdf.SetFont("Helvetica", "B", 9)
		lines := pdf.SplitLines([]byte(text), contentW-6)
		h := float64(len(lines))*4.5 + 4
		y := pdf.GetY()
		pdf.SetFillColor(253, 236, 234)
		pdf.Rect(contentL, y, contentW, h, "F")
		pdf.SetFillColor(176, 0, 32)
		pdf.Rect(contentL, y, 1.5, h, "F")
		pdf.SetTextColor(176, 0, 32)
		pdf.SetXY(contentL+4, y+2)
		pdf.MultiCell(contentW-6, 4.5, text, "", "L", false)
		pdf.SetY(y + h)
	}
	pdf.SetTextColor(0, 0, 0)
}

// drawInventory is a short summary of the application inventory: counts
// per ecosystem and how many components OSV.dev flagged. The component
// list itself is in the JSON report.
func (w *pdfWriter) drawInventory(inv *InventorySummary) {
	pdf := w.pdf
	w.sectionTitle("Application inventory")
	pdf.SetFont("Helvetica", "", 9.5)
	pdf.SetTextColor(20, 20, 20)
	ecos := make([]string, 0, len(inv.Counts))
	for e := range inv.Counts {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	var parts []string
	for _, e := range ecos {
		parts = append(parts, fmt.Sprintf("%s %d", e, inv.Counts[e]))
	}
	line := fmt.Sprintf("%d components outside the package manager", inv.Total)
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	line += "."
	switch inv.Status {
	case "ok":
		line += fmt.Sprintf(" %d looked up on OSV.dev, %d with known vulnerabilities (listed under Vulnerabilities).", inv.Queried, inv.Vulnerable)
	case "failed":
		line += " The OSV.dev lookup FAILED: " + inv.Error
	}
	line += fmt.Sprintf(" Walk: %d directory entries, %d files parsed in %s", inv.Stats.Entries, inv.Stats.FilesParsed, inv.Stats.Duration.Round(time.Millisecond))
	if inv.Stats.Truncated {
		line += " (stopped early by a limit: results are partial)"
	}
	line += fmt.Sprintf("; %d warnings. Full component list in the JSON report.", inv.Warnings)
	pdf.MultiCell(contentW, 5, line, "", "L", false)
	pdf.SetTextColor(0, 0, 0)
}
