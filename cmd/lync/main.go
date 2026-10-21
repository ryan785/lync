package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ryan785/lync/internal/ipc"
	"github.com/ryan785/lync/internal/reporter"
)

const version = "0.1.0"

const usage = `lync - Linux vulnerability scanner CLI

Usage:
  lync [global flags] <command> [command flags]

Commands:
  status              Show daemon state, last scan, running jobs
  scan [flags]        Trigger a scan (full host by default)
  sync                Refresh vulnerability feeds now
  reports             List previously generated reports
  cve CVE-ID          Is this host affected by CVE-ID? Collects fresh facts and
                      checks every cached feed. Exit code: 0 not affected,
                      10 affected, 11 possibly affected (no fix published yet),
                      12 unknown to the cached feeds (run 'lync sync' first)
  checks [-config F]  List every rules check, its severity and whether it is
                      enabled under the config (no daemon needed)
  render JSON [PDF]   Re-render a PDF from a JSON report. PDF path defaults
                      to the JSON path with .pdf extension.
  version             Print the CLI version
  help                Show this message

Global flags:
  -socket PATH        IPC socket path (default /run/lync.sock)
  -json               Print raw JSON instead of formatted text
  -color WHEN         Color output: auto (default) | always | never
  -no-color           Shorthand for -color=never

Scan flags (default scans the whole host):
  -package NAME       Scan only the named package
  -service NAME       Scan the package providing the named systemd service
                      (".service" suffix optional)
  -kernel             Scan only the kernel

Examples:
  lync status
  lync scan
  lync scan -package openssh
  lync scan -service sshd
  lync scan -kernel
  lync reports
  lync cve CVE-2026-109618
  lync -json cve CVE-2026-109618
  lync -json status
`

type globalFlags struct {
	socket  string
	json    bool
	color   string
	noColor bool
}

func main() {
	g, args := parseGlobal(os.Args[1:])
	setupColor(g.color == "always", g.noColor || g.color == "never")

	if len(args) == 0 {
		fmt.Fprint(os.Stderr, formatUsage())
		os.Exit(1)
	}
	cmd, rest := args[0], args[1:]
	c := ipc.Client{Socket: g.socket}

	switch cmd {
	case "status":
		runStatus(c, g)
	case "scan":
		runScan(c, g, rest)
	case "sync":
		runSync(c, g)
	case "reports", "list":
		runReports(c, g)
	case "cve", "check":
		runCVE(c, g, rest)
	case "checks":
		runChecks(g, rest)
	case "render":
		runRender(rest)
	case "version", "-v", "--version":
		fmt.Println("lync", version)
	case "help", "-h", "--help":
		fmt.Print(formatUsage())
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n%s",
			red("lync"), cmd, formatUsage())
		os.Exit(1)
	}
}

// parseGlobal consumes flags that may appear before the subcommand.
// Anything after the first positional (the subcommand name) is returned as-is.
func parseGlobal(argv []string) (globalFlags, []string) {
	g := globalFlags{socket: "/run/lync.sock", color: "auto"}
	rest := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-socket" || a == "--socket":
			if i+1 < len(argv) {
				g.socket = argv[i+1]
				i++
			}
		case strings.HasPrefix(a, "-socket="):
			g.socket = strings.TrimPrefix(a, "-socket=")
		case strings.HasPrefix(a, "--socket="):
			g.socket = strings.TrimPrefix(a, "--socket=")
		case a == "-color" || a == "--color":
			if i+1 < len(argv) {
				g.color = argv[i+1]
				i++
			}
		case strings.HasPrefix(a, "-color="):
			g.color = strings.TrimPrefix(a, "-color=")
		case strings.HasPrefix(a, "--color="):
			g.color = strings.TrimPrefix(a, "--color=")
		case a == "-no-color" || a == "--no-color":
			g.noColor = true
		case a == "-json" || a == "--json":
			g.json = true
		default:
			rest = append(rest, argv[i:]...)
			return g, rest
		}
	}
	return g, rest
}

func send(c ipc.Client, req ipc.Request) *ipc.Response {
	resp, err := c.Send(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	if !resp.OK {
		fmt.Fprintln(os.Stderr, red("lync:"), resp.Error)
		os.Exit(3)
	}
	return resp
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// formatUsage colorizes section headers and command names in the help text.
func formatUsage() string {
	if !colorEnabled {
		return usage
	}
	out := usage
	for _, h := range []string{"Usage:", "Commands:", "Global flags:", "Scan flags (default scans the whole host):", "Examples:"} {
		out = strings.Replace(out, h, bold(h), 1)
	}
	for _, cmd := range []string{"status", "scan [flags]", "sync", "reports", "cve CVE-ID", "checks [-config F]", "version", "help"} {
		out = strings.Replace(out,
			"  "+cmd+"  ",
			"  "+cyan(cmd)+"  ",
			1)
	}
	return out
}

// --- commands ---------------------------------------------------------------

func runStatus(c ipc.Client, g globalFlags) {
	resp := send(c, ipc.Request{Cmd: ipc.CmdStatus})
	if g.json {
		printJSON(resp)
		return
	}
	formatStatus(resp)
}

func runScan(c ipc.Client, g globalFlags, args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	pkg := fs.String("package", "", "scan only the named package")
	svc := fs.String("service", "", "scan only the package providing the named service")
	kernelOnly := fs.Bool("kernel", false, "scan only the kernel")
	fs.Parse(args)

	reqArgs := map[string]any{}
	if *pkg != "" {
		reqArgs["package"] = *pkg
	}
	if *svc != "" {
		reqArgs["service"] = *svc
	}
	if *kernelOnly {
		reqArgs["kernel"] = true
	}

	resp := send(c, ipc.Request{Cmd: ipc.CmdScan, Args: reqArgs})
	if g.json {
		printJSON(resp)
		return
	}
	scope := scopeLabel(reqArgs)
	fmt.Printf("%s  (scope: %s)\n", green("Scan queued"), magenta(scope))
	fmt.Printf("%s  %s\n", dim("Watch progress:"), cyan("lync status"))
}

func runSync(c ipc.Client, g globalFlags) {
	resp := send(c, ipc.Request{Cmd: ipc.CmdSync})
	if g.json {
		printJSON(resp)
		return
	}
	fmt.Printf("%s\n", green("Feed sync queued."))
	fmt.Printf("%s  %s\n", dim("Watch progress:"), cyan("lync status"))
}

// Exit codes for `lync cve`, so fleet scripts can branch without parsing.
const (
	exitCVEAffected = 10
	exitCVEPossibly = 11
	exitCVEUnknown  = 12
)

func runCVE(c ipc.Client, g globalFlags, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: lync cve CVE-YYYY-NNNN")
		os.Exit(1)
	}
	resp := send(c, ipc.Request{Cmd: ipc.CmdCVE, Args: map[string]any{"id": args[0]}})
	d, _ := resp.Data.(map[string]any)
	verdict := fmt.Sprint(d["verdict"])
	if g.json {
		printJSON(d)
	} else {
		formatCVE(d)
	}
	switch verdict {
	case "affected":
		os.Exit(exitCVEAffected)
	case "possibly_affected":
		os.Exit(exitCVEPossibly)
	case "unknown":
		os.Exit(exitCVEUnknown)
	}
}

func formatCVE(d map[string]any) {
	verdict := fmt.Sprint(d["verdict"])
	var v string
	switch verdict {
	case "affected":
		v = boldHue(cRed, "AFFECTED")
	case "possibly_affected":
		v = yellow("POSSIBLY AFFECTED")
	case "not_affected":
		v = green("not affected")
	default:
		v = yellow("UNKNOWN")
	}
	fmt.Printf("%s  %s  %s\n", bold(fmt.Sprint(d["cve"])), v, dim(fmt.Sprint(d["host"])))
	fmt.Printf("%s %s\n", dim("Reason:"), d["reason"])
	if known, ok := d["known_by"].(map[string]any); ok && len(known) > 0 {
		names := make([]string, 0, len(known))
		for k := range known {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Printf("%s %s\n", dim("Known by:"), strings.Join(names, ", "))
	}
	if inst, ok := d["installed"].([]any); ok && len(inst) > 0 {
		fmt.Println(dim("Installed packages named by feeds:"))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, e := range inst {
			m, _ := e.(map[string]any)
			fix := fmt.Sprint(m["fixed_in"])
			if fix == "" || fix == "<nil>" {
				fix = fmt.Sprint(m["range"])
			}
			if fix == "" || fix == "<nil>" {
				fix = dim("(no fix published)")
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\n", cyan(fmt.Sprint(m["installed"])), dim(fmt.Sprint(m["source"])), fix)
		}
		w.Flush()
	}
	if fs, ok := d["findings"].([]any); ok {
		for _, e := range fs {
			m, _ := e.(map[string]any)
			fmt.Printf("  %s %s\n", red("*"), m["title"])
			if r, ok := m["remediation"].(string); ok && r != "" {
				fmt.Printf("    %s %s\n", dim("fix:"), r)
			}
		}
	}
}

func runRender(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: lync render <json> [pdf]")
		os.Exit(1)
	}
	jsonPath := args[0]
	pdfPath := strings.TrimSuffix(jsonPath, ".json") + ".pdf"
	if len(args) > 1 {
		pdfPath = args[1]
	}
	if err := reporter.WritePDFFromJSON(jsonPath, pdfPath); err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	fmt.Printf("%s  %s\n", green("Rendered:"), cyan(pdfPath))
}

func runReports(c ipc.Client, g globalFlags) {
	resp := send(c, ipc.Request{Cmd: ipc.CmdReports})
	if g.json {
		printJSON(resp)
		return
	}
	entries, _ := resp.Data.([]any)
	if len(entries) == 0 {
		fmt.Println(dim("No reports yet."), "Run", cyan("lync scan"), "to generate one.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, bold("WHEN")+"\t"+bold("SIZE")+"\t"+bold("NAME"))
	for _, e := range entries {
		m := e.(map[string]any)
		t, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(m["mtime"]))
		size := int64(0)
		if v, ok := m["size"].(float64); ok {
			size = int64(v)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			dim(t.Format("2006-01-02 15:04")),
			humanSize(size),
			cyan(fmt.Sprint(m["name"])))
	}
	w.Flush()
}

// --- formatting -------------------------------------------------------------

func formatStatus(resp *ipc.Response) {
	d, _ := resp.Data.(map[string]any)

	fmt.Printf("%s\n", boldHue(cCyan, "lync "+fmt.Sprint(d["version"])))
	fmt.Println(dim(strings.Repeat("-", 60)))

	if up, ok := timeField(d, "started_at"); ok {
		fmt.Printf("%-12s%s  %s\n",
			"Daemon:", green("running"),
			dim("(up "+humanDuration(time.Since(up))+")"))
	}

	if sources, ok := d["sources"].([]any); ok && len(sources) > 0 {
		ss := make([]string, len(sources))
		for i, s := range sources {
			ss[i] = cyan(fmt.Sprint(s))
		}
		fmt.Printf("%-12s%s\n", "Sources:", strings.Join(ss, ", "))
	}

	if t, ok := timeField(d, "last_scan"); ok {
		findings := intField(d, "findings")
		findingsStr := fmt.Sprintf("%d findings", findings)
		if findings == 0 {
			findingsStr = green(findingsStr)
		} else {
			findingsStr = bold(findingsStr)
		}
		fmt.Printf("%-12s%s  %s\n",
			"Last scan:",
			cyan(t.Format("2006-01-02 15:04:05")),
			dim(fmt.Sprintf("(%s ago, ", humanDuration(time.Since(t))))+findingsStr+dim(")"))
	} else {
		fmt.Printf("%-12s%s\n", "Last scan:", dim("never"))
	}

	if t, ok := timeField(d, "last_sync"); ok {
		fmt.Printf("%-12s%s  %s\n",
			"Last sync:",
			cyan(t.Format("2006-01-02 15:04:05")),
			dim("("+humanDuration(time.Since(t))+" ago)"))
	} else {
		fmt.Printf("%-12s%s\n", "Last sync:", dim("never"))
	}

	if pdf, ok := d["last_pdf"].(string); ok && pdf != "" {
		fmt.Printf("%-12s%s\n", "Last PDF:", cyan(pdf))
	}

	fmt.Println()
	fmt.Println(bold("Active jobs:"))
	jobs, _ := d["running"].([]any)
	if len(jobs) == 0 {
		fmt.Println("  " + dim("(idle)"))
		return
	}
	sort.Slice(jobs, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(jobs[i].(map[string]any)["started_at"]))
		tj, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(jobs[j].(map[string]any)["started_at"]))
		return ti.Before(tj)
	})
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  "+dim("KIND")+"\t"+dim("STARTED")+"\t"+dim("ELAPSED")+"\t"+dim("SCOPE"))
	for _, j := range jobs {
		m := j.(map[string]any)
		started, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(m["started_at"]))
		scopeStr := "all"
		if s, ok := m["scope"].(string); ok && s != "" {
			scopeStr = s
		}
		kind := fmt.Sprint(m["kind"])
		var kindColored string
		switch kind {
		case "scan":
			kindColored = cyan(kind)
		case "sync":
			kindColored = yellow(kind)
		default:
			kindColored = kind
		}
		scopeColored := scopeStr
		if scopeStr != "all" {
			scopeColored = magenta(scopeStr)
		} else {
			scopeColored = dim(scopeStr)
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			kindColored,
			cyan(started.Format("15:04:05")),
			humanDuration(time.Since(started)),
			scopeColored)
	}
	w.Flush()
}

func scopeLabel(args map[string]any) string {
	if len(args) == 0 {
		return "full host"
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func timeField(m map[string]any, key string) (time.Time, bool) {
	v, ok := m[key].(string)
	if !ok || v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || t.IsZero() || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, true
}

func intField(m map[string]any, key string) int {
	v, ok := m[key].(float64)
	if !ok {
		return 0
	}
	return int(v)
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%dB", b)
}
