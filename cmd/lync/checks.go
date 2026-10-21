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
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	tg := rules.Toggles{Disable: cfg.Rules.Disable, Enable: cfg.Rules.Enable}
	type row struct {
		rules.CheckInfo
		Enabled bool `json:"enabled"`
	}
	var rows []row
	for _, c := range rules.Catalog() {
		on := cfg.Rules.Enabled && tg.RuleEnabled(c.Rule) && tg.CheckEnabled(c.ID)
		rows = append(rows, row{c, on})
	}
	if g.json {
		printJSON(rows)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, bold("ID")+"\t"+bold("RULE")+"\t"+bold("SEVERITY")+"\t"+bold("STATE")+"\t"+bold("DESCRIPTION"))
	on := 0
	for _, r := range rows {
		state := green("on")
		if r.Enabled {
			on++
		} else if r.DefaultOff && !r.Enabled {
			state = yellow("off (opt-in)")
		} else {
			state = dim("off")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", cyan(r.ID), r.Rule, severityLabel(r.Severity), state, r.Description)
	}
	w.Flush()
	fmt.Printf("\n%d checks, %d enabled (config: %s). Toggle with rules.disable / rules.enable in lync.yaml.\n",
		len(rows), on, *cfgPath)
}

func severityLabel(s finding.Severity) string {
	return strings.ToLower(string(s))
}
