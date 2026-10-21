package rules

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "wireguard:stale-peer", Rule: "vpn", Severity: finding.SeverityLow,
			Description: "WireGuard peer that never completed a handshake or not for rules.wireguard_stale_days (default 90)"},
		CheckInfo{ID: "wireguard:module-missing", Rule: "vpn", Severity: finding.SeverityMedium,
			Description: "wireguard module loaded but not installed for the running kernel (VPN breaks on next module reload/reboot)"},
	)
}

// VPNRule audits WireGuard peers and module availability.
type VPNRule struct{}

func NewVPNRule() *VPNRule { return &VPNRule{} }

func (r *VPNRule) Name() string { return "vpn" }

func (r *VPNRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	dump, err := h.Run(ctx, "wg", "show", "all", "dump")
	if err != nil && dump == "" {
		return nil
	}
	var out []finding.Finding
	if opts.on("wireguard:stale-peer") {
		days := opts.WireGuardStaleDays
		if days <= 0 {
			days = 90
		}
		now := h.now()
		for _, line := range strings.Split(dump, "\n") {
			f := strings.Split(strings.TrimSpace(line), "\t")
			// peer line: iface pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive
			if len(f) != 9 {
				continue
			}
			iface, pub, endpoint, allowed := f[0], f[1], f[3], f[4]
			hs, err := strconv.ParseInt(f[5], 10, 64)
			if err != nil {
				continue
			}
			short := pub
			if len(short) > 10 {
				short = short[:10] + "..."
			}
			var why string
			switch {
			case hs == 0:
				why = "has never completed a handshake"
			case now.Sub(time.Unix(hs, 0)) > time.Duration(days)*24*time.Hour:
				why = fmt.Sprintf("last handshake %d days ago (%s)", ageDays(now.Sub(time.Unix(hs, 0))), time.Unix(hs, 0).UTC().Format("2006-01-02"))
			default:
				continue
			}
			out = append(out, mkFinding(h, "wireguard:stale-peer", iface+":"+pub, finding.CategoryNetwork, finding.SeverityLow,
				fmt.Sprintf("WireGuard peer %s on %s %s", short, iface, why),
				fmt.Sprintf("peer %s allowed-ips %s endpoint %s %s. Unused peers keep a valid key that still grants VPN access.", pub, allowed, endpoint, why),
				fmt.Sprintf("If the device is retired: wg set %s peer %s remove, and delete its [Peer] block from /etc/wireguard/%s.conf", iface, pub, iface)))
		}
	}
	if opts.on("wireguard:module-missing") && h.Exists("/sys/module/wireguard") {
		rel := runningKernel(h, facts)
		if rel != "" && !wireguardModuleOnDisk(h, rel) {
			out = append(out, mkFinding(h, "wireguard:module-missing", rel, finding.CategoryRuntime, finding.SeverityMedium,
				"wireguard module is loaded but not installed for kernel "+rel,
				"/sys/module/wireguard exists, but /lib/modules/"+rel+" has no wireguard.ko* and modules.builtin doesn't list it (installed for another kernel, or a kmod/DKMS package was removed). The tunnel won't come back after a reboot or module reload.",
				"Install the module for this kernel (Rocky/RHEL 8: dnf install kmod-wireguard; DKMS: dkms autoinstall), then verify: modinfo wireguard"))
		}
	}
	return out
}

func wireguardModuleOnDisk(h *Host, rel string) bool {
	base := "/lib/modules/" + rel
	if b, err := h.ReadFile(base + "/modules.builtin"); err == nil && strings.Contains(string(b), "wireguard.ko") {
		return true
	}
	found := false
	h.Walk(base, 8, 200000, func(p string, d fs.DirEntry) error {
		if !d.IsDir() && strings.HasPrefix(d.Name(), "wireguard.ko") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
