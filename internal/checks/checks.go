// Package checks holds Lync's declarative check packs: YAML files that
// describe what to inspect on a host, what the safe state is, and how to
// fix it. They are embedded into the binary and evaluated by the rules
// engine (internal/rules, decl_*.go). See docs/EXTENDING.md for the format.
package checks

import "embed"

//go:generate go run ./gendoc -out ../../docs/CHECKS.md

// Packs is every built-in pack (packs/*.yaml).
//
//go:embed packs/*.yaml
var Packs embed.FS
