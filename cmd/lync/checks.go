package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/rules"
)

// runChecks lists every rules check with its enabled state under the local
// config. It reads lync.yaml directly; no daemon needed.
func runChecks(g globalFlags, args []string) {
	fs := flag.NewFlagSet("checks", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/lync/lync.yaml", "config file to evaluate rules.enable/disable against")
	pack := fs.String("pack", "", "only checks in this pack (e.g. ssh, nginx, hardening)")
	tag := fs.String("tag", "", "only checks with this tag (e.g. cis)")
	sev := fs.String("severity", "", "only checks at or above this severity (critical|high|medium|low)")
	explain := fs.String("explain", "", "show probe, expectation, remediation and references for one check ID")
	fs.Parse(args)

	for _, err := range rules.LoadCheckDirs(rules.DefaultCheckDirs) {
		fmt.Fprintln(os.Stderr, yellow("lync:"), err)
	}
	if *explain != "" {
		s, ok := rules.Explain(*explain)
		if !ok {
			fmt.Fprintln(os.Stderr, red("lync:"), "unknown check", *explain)
			os.Exit(2)
		}
		fmt.Print(s)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	tg := rules.Toggles{Disable: cfg.Rules.Disable, Enable: cfg.Rules.Enable}
	level := rules.ParseLevel(cfg.Rules.Level)
	type row struct {
		rules.CheckInfo
		Enabled bool `json:"enabled"`
	}
	var rows []row
	for _, c := range rules.FilterCatalog(rules.CatalogFilter{Pack: *pack, Tag: *tag, Severity: *sev}) {
		on := cfg.Rules.Enabled && tg.RuleEnabled(c.Rule) && tg.CheckEnabled(c.ID) &&
			(c.Level == "" || rules.ParseLevel(c.Level) <= level)
		rows = append(rows, row{c, on})
	}
	if g.json {
		printJSON(rows)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, bold("ID")+"\t"+bold("PACK")+"\t"+bold("SEVERITY")+"\t"+bold("STATE")+"\t"+bold("APPLIES IF")+"\t"+bold("TITLE"))
	on := 0
	for _, r := range rows {
		state := green("on")
		switch {
		case r.Enabled:
			on++
		case r.DefaultOff:
			state = yellow("off (opt-in)")
		case r.Level != "" && rules.ParseLevel(r.Level) > level:
			state = dim("off (level " + r.Level + ")")
		default:
			state = dim("off")
		}
		applies := r.Applies
		if applies == "" {
			applies = "-"
		}
		if len(applies) > 48 {
			applies = applies[:45] + "..."
		}
		title := r.Title
		if title == "" {
			title = r.Description
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", cyan(r.ID), r.PackName(), severityLabel(r.Severity), state, applies, title)
	}
	w.Flush()
	fmt.Printf("\n%d checks, %d enabled (config: %s, level %s). Toggle with rules.disable / rules.enable (IDs, prefixes, pack:<name>, tag:<tag>); details: lync checks --explain ID.\n",
		len(rows), on, *cfgPath, level)
}

func severityLabel(s finding.Severity) string {
	return strings.ToLower(string(s))
}
