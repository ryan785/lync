package rules

import "strings"

// Level controls how aggressive the rules engine is. Each individual check
// declares the minimum Level at which it fires; operators pick a Level via
// lync.yaml and only get checks at or below their threshold.
//
//	Basic   only the highest-impact, almost-no-false-positive checks
//	Medium  the default — broad hardening that fits most servers
//	Strict  comprehensive CIS-Benchmark-style coverage including
//	        items that may produce findings on a perfectly normal
//	        server (e.g. fs.suid_dumpable, kernel.modules_disabled)
type Level int

const (
	LevelBasic  Level = 1
	LevelMedium Level = 2
	LevelStrict Level = 3
)

func (l Level) String() string {
	switch l {
	case LevelBasic:
		return "basic"
	case LevelStrict:
		return "strict"
	}
	return "medium"
}

// ParseLevel maps the YAML string into a Level. Unknown values fall back to
// Medium rather than erroring — config typos shouldn't take the daemon down.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "basic":
		return LevelBasic
	case "strict", "nist", "cis", "paranoid":
		return LevelStrict
	}
	return LevelMedium
}

// Options is threaded through Rule.Run so each rule can honor the user's
// configured level. New fields can be added without breaking existing rule
// implementations.
type Options struct {
	Level Level
	// Host is the filesystem/command view checks read. nil = real host.
	Host *Host
	// Toggles comes from rules.disable / rules.enable.
	Toggles Toggles
	// ImageMaxAgeDays flags container images older than this (0 = 365).
	ImageMaxAgeDays int
	// WireGuardStaleDays flags peers without a handshake for this long (0 = 90).
	WireGuardStaleDays int
	// SecretScanDirs are extra roots searched for compose/.env files.
	SecretScanDirs []string
	// CacheDir is where rules may cache network lookups (EOL data). ""
	// keeps the historical /var/lib/lync/feeds/eol.
	CacheDir string
	// CheckDirs are searched for local check packs (*.yaml). nil uses
	// DefaultCheckDirs; an empty non-nil slice loads none.
	CheckDirs []string
}
