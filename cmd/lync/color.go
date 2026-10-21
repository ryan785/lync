package main

import (
	"os"
	"strings"
)

// Color handling. Default: auto-detect a TTY on stdout and honor the standard
// NO_COLOR env var. Override with -no-color, or NO_COLOR=1. Output to a pipe
// (e.g. `lync status | less`) drops to plain text automatically.

var colorEnabled bool

const (
	cReset   = "\x1b[0m"
	cBold    = "\x1b[1m"
	cDim     = "\x1b[2m"
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cBlue    = "\x1b[34m"
	cMagenta = "\x1b[35m"
	cCyan    = "\x1b[36m"
)

func setupColor(force, disable bool) {
	switch {
	case disable, os.Getenv("NO_COLOR") != "":
		colorEnabled = false
	case force:
		colorEnabled = true
	default:
		fi, err := os.Stdout.Stat()
		if err != nil {
			colorEnabled = false
			return
		}
		colorEnabled = (fi.Mode() & os.ModeCharDevice) != 0
	}
}

func paint(code, s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return code + s + cReset
}

// Named helpers by hue rather than semantic intent — keeps call sites
// readable and avoids shadowing the universal `ok` boolean from type
// assertions.

func green(s string) string   { return paint(cGreen, s) }
func yellow(s string) string  { return paint(cYellow, s) }
func red(s string) string     { return paint(cRed, s) }
func cyan(s string) string    { return paint(cCyan, s) }
func magenta(s string) string { return paint(cMagenta, s) }
func dim(s string) string     { return paint(cDim, s) }
func bold(s string) string    { return paint(cBold, s) }

func boldHue(code, s string) string {
	if !colorEnabled {
		return s
	}
	return cBold + code + s + cReset
}

func severityColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return paint(cRed+cBold, severity)
	case "HIGH":
		return paint(cRed, severity)
	case "MEDIUM":
		return paint(cYellow, severity)
	case "LOW":
		return paint(cBlue, severity)
	}
	return dim(severity)
}
