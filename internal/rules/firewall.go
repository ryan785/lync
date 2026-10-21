package rules

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// FirewallRule reports the host's firewall state. It checks the four common
// flavors in order (firewalld, ufw, nftables, iptables) and emits Critical
// if NONE of them appear to be filtering. This is one of the highest-leverage
// findings on a server exposed to the internet.
type FirewallRule struct{}

func NewFirewallRule() *FirewallRule { return &FirewallRule{} }

func (r *FirewallRule) Name() string { return "firewall" }

func (r *FirewallRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	state := detectFirewall(ctx)
	now := time.Now()
	if state.Active {
		log.Debug("firewall active", "kind", state.Kind, "rules", state.RuleCount)
		return nil
	}
	return []finding.Finding{{
		ID:          "firewall:none-active",
		Category:    finding.CategoryNetwork,
		Severity:    finding.SeverityCritical,
		Title:       "No active host firewall detected",
		Evidence:    state.Evidence,
		Remediation: "Enable firewalld (`systemctl enable --now firewalld`) or nftables, then add rules for required inbound ports. A host facing the network with no firewall is one accidental service-bind away from public exposure.",
		DetectedAt:  now,
		Source:      "lync-rules",
	}}
}

type firewallState struct {
	Kind      string // firewalld | ufw | nftables | iptables | none
	Active    bool
	RuleCount int
	Evidence  string
}

func detectFirewall(ctx context.Context) firewallState {
	// firewalld
	if firewallActive(ctx, "firewall-cmd", "--state") {
		return firewallState{Kind: "firewalld", Active: true, Evidence: "firewall-cmd --state returned active"}
	}
	// ufw
	if out, err := runCmd(ctx, "ufw", "status"); err == nil && strings.Contains(strings.ToLower(out), "active") {
		return firewallState{Kind: "ufw", Active: true, Evidence: "ufw status: active"}
	}
	// nftables — non-empty ruleset
	if out, err := runCmd(ctx, "nft", "list", "ruleset"); err == nil {
		nonEmpty := false
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				nonEmpty = true
				break
			}
		}
		if nonEmpty {
			return firewallState{Kind: "nftables", Active: true, Evidence: "nft list ruleset: non-empty"}
		}
	}
	// iptables — at least one rule beyond the policy lines
	if out, err := runCmd(ctx, "iptables", "-S"); err == nil {
		rules := 0
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") {
				rules++
			}
		}
		if rules > 0 {
			return firewallState{Kind: "iptables", Active: true, RuleCount: rules,
				Evidence: "iptables -S: " + itoa(rules) + " -A rules"}
		}
	}
	return firewallState{
		Kind:     "none",
		Active:   false,
		Evidence: "firewalld inactive, no ufw, no nftables ruleset, no iptables -A rules",
	}
}

func firewallActive(ctx context.Context, name string, args ...string) bool {
	out, err := runCmd(ctx, name, args...)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), "running") ||
		strings.TrimSpace(out) == "running"
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := audit.Output(ctx, CommandTimeout, name, args...)
	return string(out), err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}
