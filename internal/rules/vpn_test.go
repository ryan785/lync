package rules

import (
	"fmt"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func wgDump() string {
	recent := fixedNow.Add(-2 * 60 * 1e9).Unix()
	old := fixedNow.AddDate(0, 0, -200).Unix()
	return "wg0\tPRIVKEY\tPUBKEY\t51820\toff\n" +
		fmt.Sprintf("wg0\tAlicePeerKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t1.2.3.4:5555\t10.0.0.2/32\t%d\t100\t200\t25\n", recent) +
		"wg0\tNeverPeerKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff\n" +
		fmt.Sprintf("wg0\tOldPeerKeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\t(none)\t5.6.7.8:4444\t10.0.0.4/32\t%d\t1\t2\toff\n", old)
}

func TestVPNRule(t *testing.T) {
	cases := []struct {
		name       string
		modOnDisk  bool
		builtin    bool
		wantModule bool
	}{
		{"module missing for running kernel", false, false, true},
		{"module on disk", true, false, false},
		{"module builtin", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newFixture(t)
			rel := "6.10.3-1.el9.elrepo.x86_64"
			fx.cmd("wg show all dump", wgDump()).
				file("/proc/sys/kernel/osrelease", rel).
				dir("/sys/module/wireguard").
				dir("/lib/modules/" + rel + "/kernel/drivers/net")
			if c.modOnDisk {
				fx.file("/lib/modules/"+rel+"/extra/wireguard/wireguard.ko.xz", "x")
			}
			if c.builtin {
				fx.file("/lib/modules/"+rel+"/modules.builtin", "kernel/drivers/net/wireguard/wireguard.ko\n")
			}
			got := runRule(NewVPNRule(), &collector.Facts{}, fx.opts())
			requireShape(t, got)
			if hasID(got, "wireguard:stale-peer:wg0:NeverPeerKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=") == nil ||
				hasID(got, "wireguard:stale-peer:wg0:OldPeerKeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=") == nil {
				t.Errorf("stale peers missing: %v", ids(got))
			}
			if hasPrefix(got, "wireguard:stale-peer:wg0:AlicePeer") != 0 {
				t.Error("recent peer flagged")
			}
			f := hasID(got, "wireguard:module-missing:"+rel)
			if (f != nil) != c.wantModule {
				t.Errorf("module-missing = %v, want %v", f != nil, c.wantModule)
			}
			if f != nil && f.Severity != finding.SeverityMedium {
				t.Errorf("severity %s", f.Severity)
			}
		})
	}
}

func TestVPNRuleNoWireGuard(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewVPNRule(), &collector.Facts{}, fx.opts()); len(got) != 0 {
		t.Errorf("no wg: got %v", ids(got))
	}
}
