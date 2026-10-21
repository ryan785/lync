// Package audit writes the run log: one line per action Lync takes on the
// host (commands executed with exit code and duration, network fetches
// with status/bytes/retries, files created and removed, checks run). It is
// what makes the one-shot runner's "the log is the only thing left
// behind" promise checkable. When no writer is set every call is a cheap
// no-op, so the daemon pays nothing.
//
// Line format (tab-free, one event per line):
//
//	2026-10-21T09:15:02.123Z CMD     rpm -qa --qf '...' exit=0 dur=1.204s out=1.9MB
//	2026-10-21T09:15:09.880Z FETCH   GET https://services.nvd.nist.gov/... status=200 bytes=3.4MB dur=4.1s attempts=2 proto=HTTP/1.1
//	2026-10-21T09:15:10.002Z FILE+   /dev/shm/lync.Xa1/cache/nvd/vulns.json 3.1MB
package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	mu sync.Mutex
	w  io.Writer
)

// Enable sends audit lines to out (nil disables).
func Enable(out io.Writer) {
	mu.Lock()
	w = out
	mu.Unlock()
}

// Enabled reports whether audit logging is on.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return w != nil
}

// OpenFile appends to path (created 0600) and enables logging to it.
func OpenFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	Enable(f)
	return f, nil
}

// Log writes one event line. kind is a short upper-case tag.
func Log(kind, format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if w == nil {
		return
	}
	msg := Redact(fmt.Sprintf(format, args...))
	msg = strings.ReplaceAll(msg, "\n", `\n`)
	fmt.Fprintf(w, "%s %-7s %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), kind, msg)
}

var redactRE = regexp.MustCompile(`(?i)((?:api[_-]?key|token|password|passwd|secret|authorization)["']?\s*[=:]\s*(?:bearer\s+|token\s+)?)[^\s&"',;]+`)
var ghTokenRE = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)

// Redact masks credential-looking values (key=value, Authorization
// headers, GitHub tokens).
func Redact(s string) string {
	s = redactRE.ReplaceAllString(s, "${1}[REDACTED]")
	return ghTokenRE.ReplaceAllString(s, "[REDACTED]")
}

// Size renders a byte count for log lines.
func Size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// DefaultCommandTimeout bounds every external command run through Output.
const DefaultCommandTimeout = 2 * time.Minute

// Output runs a command with a timeout (0 = DefaultCommandTimeout) and
// returns stdout, logging the exact command line, exit code, duration and
// output size. A missing binary is reported as exit=127.
func Output(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	start := time.Now()
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case errors.Is(err, exec.ErrNotFound):
		code = 127
	default:
		code = -1
	}
	extra := ""
	if ctx.Err() == context.DeadlineExceeded {
		extra = " TIMEOUT(" + timeout.String() + ")"
	}
	Log("CMD", "%s exit=%d dur=%s out=%s%s", Quote(name, args), code, time.Since(start).Round(time.Millisecond), Size(int64(stdout.Len())), extra)
	return stdout.Bytes(), err
}

// Quote renders a command line the way a shell user would type it.
func Quote(name string, args []string) string {
	parts := []string{name}
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t'\"$`\\|&;<>(){}*?[]#~%") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// FileWritten records a file Lync created or replaced.
func FileWritten(path string, n int64) { Log("FILE+", "%s %s", path, Size(n)) }

// FileRemoved records a file Lync deleted.
func FileRemoved(path string) { Log("FILE-", "%s", path) }
