package rules

import (
	"testing"

	"github.com/ryan785/lync/internal/finding"
)

const ssFixture = `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=6))
tcp LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("docker-proxy",pid=3,fd=4))
tcp LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=4,fd=20))
tcp LISTEN 0 511 10.0.0.5:6379 0.0.0.0:* users:(("redis-server",pid=5,fd=6))
tcp LISTEN 0 64 0.0.0.0:111 0.0.0.0:* users:(("rpcbind",pid=6,fd=4))
tcp LISTEN 0 64 [::]:6556 [::]:* users:(("systemd",pid=1,fd=50))
tcp LISTEN 0 64 [::]:9090 [::]:* users:(("systemd",pid=1,fd=51))
udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
`

func exposureFixture(t *testing.T) *fixtureHost {
	fx := newFixture(t)
	fx.cmd("ss -H -tulnp", ssFixture).
		cmd("docker ps --format {{.Names}}\t{{.Ports}}", "db\t0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp\nweb\t127.0.0.1:8080->80/tcp\nminio\t0.0.0.0:9000-9001->9000-9001/tcp\n").
		cmd("iptables -S DOCKER-USER", "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n").
		cmd("firewall-cmd --get-active-zones", "public\n  interfaces: eth0\n").
		cmd("firewall-cmd --zone=public --list-services", "cockpit dhcpv6-client http https ssh\n").
		cmd("firewall-cmd --zone=public --list-ports", "3306/tcp 21115-21119/tcp 51820/udp 8443/tcp\n").
		cmd("systemctl is-enabled cockpit.socket", "enabled\n").
		file("/usr/lib/firewalld/services/http.xml", `<service><port protocol="tcp" port="80"/></service>`).
		file("/usr/lib/firewalld/services/https.xml", `<service><port protocol="tcp" port="443"/></service>`).
		file("/usr/lib/firewalld/services/ssh.xml", `<service><port protocol="tcp" port="22"/></service>`).
		file("/usr/lib/firewalld/services/cockpit.xml", `<service><port protocol="tcp" port="9090"/></service>`).
		file("/etc/redis/redis.conf", "bind 10.0.0.5\nprotected-mode yes\n# requirepass foo\n")
	return fx
}

func TestExposureRule(t *testing.T) {
	fx := exposureFixture(t)
	got := runRule(NewExposureRule(), nil, fx.opts())
	requireShape(t, got)
	want := map[string]finding.Severity{
		"docker:published-bypass:db:5432/tcp":      finding.SeverityCritical,
		"docker:published-bypass:minio:9000/tcp":   finding.SeverityHigh,
		"firewall:stale-open:public:service-http":  finding.SeverityLow,
		"firewall:stale-open:public:port-3306/tcp": finding.SeverityLow,
		"firewall:stale-open:public:port-8443/tcp": finding.SeverityLow,
		"net:datastore-exposed:5432":               finding.SeverityHigh,
		"net:datastore-exposed:6379":               finding.SeverityHigh,
		"redis:no-auth:/etc/redis/redis.conf":      finding.SeverityCritical,
		"net:rpcbind-exposed":                      finding.SeverityMedium,
		"checkmk:unrestricted":                     finding.SeverityMedium,
		"cockpit:enabled":                          finding.SeverityMedium,
	}
	for id, sev := range want {
		f := hasID(got, id)
		if f == nil {
			t.Errorf("missing %s; got %v", id, ids(got))
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s severity %s, want %s", id, f.Severity, sev)
		}
	}
	for _, id := range []string{
		"docker:published-bypass:web:8080/tcp",       // loopback publish
		"net:datastore-exposed:3306",                 // loopback
		"firewall:stale-open:public:service-https",   // 443 listening
		"firewall:stale-open:public:service-cockpit", // 9090 listening
		"firewall:stale-open:public:port-51820/udp",  // udp listening
		"firewall:stale-open:public:port-21115-21119/tcp",
		"firewall:stale-open:public:service-dhcpv6-client",
	} {
		if hasID(got, id) != nil {
			t.Errorf("unexpected %s", id)
		}
	}
}

func TestExposureDockerUserFiltered(t *testing.T) {
	fx := exposureFixture(t)
	fx.cmd("iptables -S DOCKER-USER", "-N DOCKER-USER\n-A DOCKER-USER -i eth0 -j DROP\n-A DOCKER-USER -j RETURN\n")
	if n := hasPrefix(runRule(NewExposureRule(), nil, fx.opts()), "docker:published-bypass"); n != 0 {
		t.Errorf("DOCKER-USER has rules: want no bypass findings, got %d", n)
	}
}

func TestExposureNoTools(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewExposureRule(), nil, fx.opts()); len(got) != 0 {
		t.Errorf("no tools: got %v", ids(got))
	}
}

func TestRedisAuthAndCheckmkRestricted(t *testing.T) {
	fx := exposureFixture(t)
	fx.file("/etc/redis/redis.conf", "bind 127.0.0.1\nrequirepass s3cret\n").
		file("/etc/xinetd.d/check-mk-agent", "service check_mk\n{\n  only_from = 10.0.0.2\n}\n")
	got := runRule(NewExposureRule(), nil, fx.opts())
	if hasPrefix(got, "redis:no-auth") != 0 || hasID(got, "checkmk:unrestricted") != nil {
		t.Errorf("got %v", ids(got))
	}
}

func TestParseSS(t *testing.T) {
	ls := parseSS(ssFixture + "tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n")
	if len(ls) != 10 {
		t.Fatalf("parsed %d listeners", len(ls))
	}
	if !ls[9].Loopback() || ls[6].Proc != "systemd" || !ls[6].Wildcard() || ls[8].Proto != "udp" {
		t.Errorf("listeners = %+v", ls)
	}
}
