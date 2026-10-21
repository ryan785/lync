package rules

import (
	"bufio"
	"context"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// NetworkRule enumerates listening TCP sockets via `ss -tlnp` and flags
// services bound to all interfaces (0.0.0.0 or ::). UDP could be added the
// same way; left out for now since UDP listeners are usually narrowly
// scoped (DNS, NTP, mDNS) and produce more noise than signal.
type NetworkRule struct{}

func NewNetworkRule() *NetworkRule { return &NetworkRule{} }

func (r *NetworkRule) Name() string { return "network" }

// publiclyExposedAllowList — listeners we expect to be on all interfaces.
// Loopback and link-local addresses are filtered upstream so this is only
// consulted for 0.0.0.0 / :: binds.
var publiclyExposedAllowList = map[int]bool{
	22:  true, // sshd
	80:  true, // http
	443: true, // https
}

func (r *NetworkRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	out, err := audit.Output(ctx, CommandTimeout, "ss", "-tlnp")
	if err != nil {
		log.Debug("ss unavailable; skipping network rule", "err", err)
		return nil
	}
	var findings []finding.Finding
	now := time.Now()
	s := bufio.NewScanner(strings.NewReader(string(out)))
	// skip header
	if s.Scan() {
		_ = s.Text()
	}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := fields[3]
		addr, portStr, ok := splitHostPort(local)
		if !ok {
			continue
		}
		var port int
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		if addr != "0.0.0.0" && addr != "*" && addr != "::" {
			continue
		}
		if publiclyExposedAllowList[port] {
			continue
		}
		// Reported by dedicated, higher-severity checks in exposure.go.
		if _, ds := datastorePorts[port]; ds || port == 111 || port == 6556 {
			continue
		}
		// ss -tlnp columns:
		//   State Recv-Q Send-Q Local Peer Process
		// Process info (users:((...))) lives at fields[5]; it may contain
		// commas but never spaces, so Join from 5 onward is safe and
		// tolerates future column additions.
		proc := ""
		if len(fields) >= 6 {
			proc = strings.Join(fields[5:], " ")
		}
		procName := extractProcessName(proc)
		title := fmt.Sprintf("Port %d listening on all interfaces", port)
		if procName != "" {
			title = fmt.Sprintf("%s (port %d) listening on all interfaces", procName, port)
		}
		findings = append(findings, finding.Finding{
			ID:          fmt.Sprintf("net:exposed:%d", port),
			Category:    finding.CategoryNetwork,
			Severity:    finding.SeverityMedium,
			Title:       title,
			Evidence:    fmt.Sprintf("bind=%s process=%s", local, proc),
			Remediation: "If this service should only be reachable locally, bind it to 127.0.0.1 (or ::1) in its config. If externally needed, add a firewall rule allowing only known clients.",
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}
	log.Debug("network rule scanned", "findings", len(findings))
	return findings
}

// extractProcessName parses the program field from `ss -tlnp`:
//
//	users:(("sshd",pid=1234,fd=3))
//	users:(("nginx",pid=999,fd=6),("nginx",pid=1000,fd=6))
//
// Returns just the first program name, or "" if the field doesn't parse.
func extractProcessName(s string) string {
	const marker = `(("`
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// splitHostPort handles ss's bracketed IPv6 form ([::]:443) and dotted IPv4.
func splitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return "", "", false
		}
		return s[1:end], s[end+2:], true
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
