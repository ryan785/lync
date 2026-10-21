package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a logger writing to stdout (journald under systemd).
func New(level, format string) *slog.Logger {
	return NewTo(os.Stdout, level, format)
}

// NewTo returns a logger writing to w. One-shot mode logs to stderr so
// stdout carries only the JSON result.
func NewTo(w io.Writer, level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "error":
		lvl = slog.LevelError
	case "warn":
		lvl = slog.LevelWarn
	case "info":
		lvl = slog.LevelInfo
	case "debug", "trace":
		lvl = slog.LevelDebug
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}
