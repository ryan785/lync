// Command gendoc regenerates docs/CHECKS.md from the check catalog.
//
//	go run ./internal/checks/gendoc            (from the repository root)
//	go generate ./internal/checks
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ryan785/lync/internal/rules"
)

func main() {
	out := flag.String("out", "docs/CHECKS.md", "output file")
	flag.Parse()
	for _, err := range rules.PackErrors() {
		fmt.Fprintln(os.Stderr, "gendoc:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(rules.ChecksMarkdown()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gendoc:", err)
		os.Exit(1)
	}
}
