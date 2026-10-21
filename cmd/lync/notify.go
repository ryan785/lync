package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/notify"
)

// runNotify implements `lync notify test`: it reads lync.yaml directly
// (no daemon needed) and sends a test message to each channel.
func runNotify(g globalFlags, args []string) {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: lync notify test [-config /etc/lync/lync.yaml]")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("notify test", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/lync/lync.yaml", "config file with the notify: block")
	fs.Parse(args[1:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	nc := cfg.Notify
	if !nc.Enabled {
		fmt.Fprintf(os.Stderr, "%s notify.enabled is false in %s; testing the configured channels anyway\n", yellow("note:"), *cfgPath)
		nc.Enabled = true
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	n, err := notify.New(nc, version, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("lync:"), err)
		os.Exit(2)
	}
	hostname, _ := os.Hostname()
	facts := &collector.Facts{Hostname: hostname, OS: collector.ReadOSRelease()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	results := n.Test(ctx, facts)
	failed := 0
	type row struct {
		Channel string `json:"channel"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}
	var rows []row
	for _, r := range results {
		rw := row{Channel: r.Channel, OK: r.Err == nil}
		if r.Err != nil {
			failed++
			rw.Error = r.Err.Error()
		}
		rows = append(rows, rw)
	}
	if g.json {
		printJSON(rows)
	} else {
		for _, r := range rows {
			if r.OK {
				fmt.Printf("%-40s %s\n", r.Channel, green("sent"))
			} else {
				fmt.Printf("%-40s %s %s\n", r.Channel, red("FAILED"), r.Error)
			}
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}
