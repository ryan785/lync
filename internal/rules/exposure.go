package rules

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "docker:published-bypass", Rule: "exposure", Severity: finding.SeverityHigh,
			Description: "Docker-published port on 0.0.0.0/:: while DOCKER-USER is empty: reachable regardless of firewalld"},
		CheckInfo{ID: "firewall:stale-open", Rule: "exposure", Severity: finding.SeverityLow,
			Description: "firewalld zone opens a port/service that nothing listens on"},
		CheckInfo{ID: "net:datastore-exposed", Rule: "exposure", Severity: finding.SeverityHigh,
			Description: "Database/cache port (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached...) listening on a non-loopback address"},
		CheckInfo{ID: "redis:no-auth", Rule: "exposure", Severity: finding.SeverityHigh,
			Description: "Redis config without requirepass/ACL users"},
		CheckInfo{ID: "net:rpcbind-exposed", Rule: "exposure", Severity: finding.SeverityMedium,
			Description: "rpcbind (111) listening on a non-loopback address"},
		CheckInfo{ID: "checkmk:unrestricted", Rule: "exposure", Severity: finding.SeverityMedium,
			Description: "Checkmk agent (6556) answers anyone: no only_from restriction and no TLS agent controller"},
		CheckInfo{ID: "cockpit:enabled", Rule: "exposure", Severity: finding.SeverityLow,
			Description: "Cockpit web console socket is enabled"},
	)
}

// datastorePorts are services that should never face the network directly.
var datastorePorts = map[int]string{
	3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch/OpenSearch",
	9300: "Elasticsearch transport", 11211: "Memcached", 5984: "CouchDB", 8086: "InfluxDB", 9042: "Cassandra", 2379: "etcd",
}

// ExposureRule covers network exposure that the plain "listening on all
// interfaces" check misses or under-rates.
type ExposureRule struct{}

func NewExposureRule() *ExposureRule { return &ExposureRule{} }

func (r *ExposureRule) Name() string { return "exposure" }

func (r *ExposureRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	var out []finding.Finding
	ls, lsOK := h.Listeners(ctx)
	if opts.on("docker:published-bypass") {
		out = append(out, dockerPublished(ctx, h)...)
	}
	if opts.on("firewall:stale-open") && lsOK {
		out = append(out, staleFirewall(ctx, h, ls)...)
	}
	if lsOK {
		seen := map[string]bool{}
		for _, l := range ls {
			if l.Loopback() || l.Proto != "tcp" {
				continue
			}
			if svc, ok := datastorePorts[l.Port]; ok && opts.on("net:datastore-exposed") {
				k := strconv.Itoa(l.Port)
				if !seen[k] {
					seen[k] = true
					out = append(out, mkFinding(h, "net:datastore-exposed", k, finding.CategoryNetwork, finding.SeverityHigh,
						fmt.Sprintf("%s port %d listening on %s", svc, l.Port, l.Addr),
						fmt.Sprintf("bind=%s:%d process=%s", l.Addr, l.Port, orNone(l.Proc)),
						fmt.Sprintf("Bind %s to 127.0.0.1 (or a private interface) in its config, or for Docker publish as 127.0.0.1:%d:%d; then confirm with ss -tlnp | grep :%d", svc, l.Port, l.Port, l.Port)))
				}
			}
			if l.Port == 111 && opts.on("net:rpcbind-exposed") && !seen["111"] {
				seen["111"] = true
				out = append(out, mkFinding(h, "net:rpcbind-exposed", "", finding.CategoryNetwork, finding.SeverityMedium,
					"rpcbind listening on "+l.Addr+":111",
					"rpcbind enables NFS/RPC service enumeration and has been used for DDoS amplification",
					"If NFS isn't used: systemctl disable --now rpcbind.service rpcbind.socket; otherwise firewall port 111 to NFS clients"))
			}
			if l.Port == 6556 && opts.on("checkmk:unrestricted") && !seen["6556"] {
				seen["6556"] = true
				if f, ok := checkmkUnrestricted(h, l); ok {
					out = append(out, f)
				}
			}
		}
	}
	if opts.on("redis:no-auth") {
		out = append(out, redisNoAuth(h, ls)...)
	}
	if opts.on("cockpit:enabled") {
		if st := h.SystemctlIsEnabled(ctx, "cockpit.socket"); st == "enabled" {
			sev := finding.SeverityLow
			ev := "cockpit.socket is enabled"
			if lsOK {
				for _, l := range ls {
					if l.Port == 9090 && !l.Loopback() {
						sev = finding.SeverityMedium
						ev += "; listening on " + l.Addr + ":9090"
					}
				}
			}
			out = append(out, mkFinding(h, "cockpit:enabled", "", finding.CategoryNetwork, sev,
				"Cockpit web console enabled", ev+" (root-capable web login surface)",
				"If unused: systemctl disable --now cockpit.socket && firewall-cmd --permanent --remove-service=cockpit && firewall-cmd --reload"))
		}
	}
	return out
}

var dockerPortRE = regexp.MustCompile(`(0\.0\.0\.0|\[::\]|::):(\d+)(?:-\d+)?->(\d+)(?:-\d+)?/(tcp|udp)`)

func dockerPublished(ctx context.Context, h *Host) []finding.Finding {
	out, err := h.Run(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
	if err != nil && out == "" {
		return nil
	}
	type pub struct{ name, port, proto string }
	var pubs []pub
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name, ports, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		for _, m := range dockerPortRE.FindAllStringSubmatch(ports, -1) {
			k := name + "/" + m[2] + "/" + m[4]
			if !seen[k] {
				seen[k] = true
				pubs = append(pubs, pub{name, m[2], m[4]})
			}
		}
	}
	if len(pubs) == 0 {
		return nil
	}
	chain, cerr := h.Run(ctx, "iptables", "-S", "DOCKER-USER")
	userRules := 0
	for _, l := range strings.Split(chain, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A DOCKER-USER") && l != "-A DOCKER-USER -j RETURN" {
			userRules++
		}
	}
	if userRules > 0 {
		return nil
	}
	chainState := "DOCKER-USER chain has no filtering rules"
	if cerr != nil && chain == "" {
		chainState = "DOCKER-USER chain not readable/absent (iptables -S DOCKER-USER failed)"
	}
	var res []finding.Finding
	for _, p := range pubs {
		sev := finding.SeverityHigh
		if p.port == "80" || p.port == "443" {
			sev = finding.SeverityMedium
		}
		if n, err := strconv.Atoi(p.port); err == nil {
			if _, ds := datastorePorts[n]; ds {
				sev = finding.SeverityCritical
			}
		}
		res = append(res, mkFinding(h, "docker:published-bypass", p.name+":"+p.port+"/"+p.proto, finding.CategoryNetwork, sev,
			fmt.Sprintf("Container %s publishes %s/%s on all interfaces, bypassing firewalld", p.name, p.port, p.proto),
			fmt.Sprintf("docker ps: %s -> 0.0.0.0:%s; %s. Docker's DNAT happens before firewalld's INPUT zones, so firewall-cmd rules do not protect this port.", p.name, p.port, chainState),
			fmt.Sprintf("Publish on loopback (ports: \"127.0.0.1:%s:<container-port>\") and front it with nginx, or add DOCKER-USER rules: iptables -I DOCKER-USER -i <wan-if> -p %s --dport <container-port> -j DROP (persist via firewalld direct rules)", p.port, p.proto),
			"https://docs.docker.com/engine/network/packet-filtering-firewalls/"))
	}
	return res
}

var fwPortRE = regexp.MustCompile(`<port\s+[^>]*?protocol="(\w+)"\s+port="([\d-]+)"|<port\s+[^>]*?port="([\d-]+)"\s+protocol="(\w+)"`)

// firewalldServicePorts resolves a firewalld service name to proto/port pairs.
func firewalldServicePorts(h *Host, svc string) [][2]string {
	for _, dir := range []string{"/etc/firewalld/services/", "/usr/lib/firewalld/services/"} {
		b, err := h.ReadFile(dir + svc + ".xml")
		if err != nil {
			continue
		}
		var out [][2]string
		for _, m := range fwPortRE.FindAllStringSubmatch(string(b), -1) {
			if m[1] != "" {
				out = append(out, [2]string{m[1], m[2]})
			} else {
				out = append(out, [2]string{m[4], m[3]})
			}
		}
		return out
	}
	return nil
}

// firewalld services that are client-side or not tied to a local listener.
var fwClientServices = map[string]bool{"dhcpv6-client": true, "dhcp": true, "mdns": true, "samba-client": true}

func staleFirewall(ctx context.Context, h *Host, ls []Listener) []finding.Finding {
	zonesOut, err := h.Run(ctx, "firewall-cmd", "--get-active-zones")
	if err != nil && zonesOut == "" {
		return nil
	}
	var zones []string
	for _, line := range strings.Split(zonesOut, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			zones = append(zones, strings.Fields(line)[0])
		}
	}
	var out []finding.Finding
	for _, z := range zones {
		type item struct{ label, proto, port string }
		var items []item
		svcs, _ := h.Run(ctx, "firewall-cmd", "--zone="+z, "--list-services")
		for _, s := range strings.Fields(svcs) {
			if fwClientServices[s] {
				continue
			}
			for _, pp := range firewalldServicePorts(h, s) {
				items = append(items, item{"service " + s, pp[0], pp[1]})
			}
		}
		ports, _ := h.Run(ctx, "firewall-cmd", "--zone="+z, "--list-ports")
		for _, p := range strings.Fields(ports) {
			port, proto, ok := strings.Cut(p, "/")
			if ok {
				items = append(items, item{"port " + p, proto, port})
			}
		}
		reported := map[string]bool{}
		for _, it := range items {
			if strings.Contains(it.port, "-") { // ranges: can't judge
				continue
			}
			n, err := strconv.Atoi(it.port)
			// Only non-loopback listeners count: a firewall opening for a
			// service bound to 127.0.0.1 exposes nothing today but will
			// the moment someone rebinds it.
			if err != nil || listeningOn(publicOnly(ls), it.proto, n) || reported[it.label] {
				continue
			}
			reported[it.label] = true
			removal := "--remove-port=" + it.port + "/" + it.proto
			if strings.HasPrefix(it.label, "service ") {
				removal = "--remove-service=" + strings.TrimPrefix(it.label, "service ")
			}
			out = append(out, mkFinding(h, "firewall:stale-open", z+":"+strings.ReplaceAll(it.label, " ", "-"), finding.CategoryNetwork, finding.SeverityLow,
				fmt.Sprintf("firewalld zone %s opens %s but nothing listens on %s/%s", z, it.label, it.port, it.proto),
				fmt.Sprintf("zone %s allows %s (%s/%s); no local listener. A service started later on that port is exposed without review.", z, it.label, it.port, it.proto),
				fmt.Sprintf("firewall-cmd --permanent --zone=%s %s && firewall-cmd --reload", z, removal)))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func redisNoAuth(h *Host, ls []Listener) []finding.Finding {
	var out []finding.Finding
	for _, f := range append(h.Glob("/etc/redis.conf"), h.Glob("/etc/redis/redis*.conf")...) {
		b, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		auth, protectedNo, publicBind := false, false, false
		bind := ""
		for _, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(strings.TrimSpace(line))
			if len(fs) == 0 || strings.HasPrefix(fs[0], "#") {
				continue
			}
			switch strings.ToLower(fs[0]) {
			case "requirepass", "aclfile":
				if len(fs) > 1 {
					auth = true
				}
			case "user":
				if len(fs) > 1 && fs[1] == "default" && strings.Contains(line, ">") {
					auth = true
				}
			case "protected-mode":
				protectedNo = len(fs) > 1 && fs[1] == "no"
			case "bind":
				bind = strings.Join(fs[1:], " ")
				for _, a := range fs[1:] {
					a = strings.TrimPrefix(a, "-")
					if !strings.HasPrefix(a, "127.") && a != "::1" && a != "localhost" {
						publicBind = true
					}
				}
			}
		}
		if bind == "" { // no bind line: Redis listens on all interfaces
			publicBind = listeningOn(publicOnly(ls), "tcp", 6379)
		}
		if auth {
			continue
		}
		sev := finding.SeverityLow
		why := "no requirepass / ACL; reachable only via loopback"
		if publicBind || protectedNo {
			sev = finding.SeverityCritical
			why = fmt.Sprintf("no requirepass / ACL and bind=%q protected-mode-no=%v: unauthenticated Redis = remote code execution (CONFIG SET dir / MODULE LOAD)", bind, protectedNo)
		}
		out = append(out, mkFinding(h, "redis:no-auth", f, finding.CategoryConfig, sev,
			"Redis without authentication: "+f, why,
			"Set `requirepass <long random>` (or ACL users) and `bind 127.0.0.1 -::1` in "+f+", then systemctl restart redis",
			"https://redis.io/docs/latest/operate/oss_and_stack/management/security/"))
	}
	return out
}

func publicOnly(ls []Listener) []Listener {
	var out []Listener
	for _, l := range ls {
		if !l.Loopback() {
			out = append(out, l)
		}
	}
	return out
}

func checkmkUnrestricted(h *Host, l Listener) (finding.Finding, bool) {
	if strings.Contains(l.Proc, "cmk-agent-ctl") {
		// Agent controller: TLS + registration; plaintext only after
		// registration is skipped. Treat as restricted.
		return finding.Finding{}, false
	}
	for _, f := range append(h.Glob("/etc/xinetd.d/check*mk*"), h.Glob("/etc/xinetd.d/check-mk*")...) {
		b, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && strings.TrimSpace(k) == "only_from" && strings.TrimSpace(v) != "" && !strings.HasPrefix(strings.TrimSpace(k), "#") {
				return finding.Finding{}, false
			}
		}
	}
	for _, f := range h.Glob("/etc/systemd/system/check-mk-agent.socket.d/*.conf") {
		if b, err := h.ReadFile(f); err == nil && strings.Contains(string(b), "IPAddressAllow") {
			return finding.Finding{}, false
		}
	}
	return mkFinding(h, "checkmk:unrestricted", "", finding.CategoryNetwork, finding.SeverityMedium,
		"Checkmk agent on "+l.Addr+":6556 answers any client",
		"plaintext agent output (processes, packages, mounts, users) with no only_from / IPAddressAllow restriction and no cmk-agent-ctl TLS",
		"Register the agent for TLS (cmk-agent-ctl register ...) or restrict: systemctl edit check-mk-agent.socket -> [Socket] IPAddressDeny=any / IPAddressAllow=<monitoring server IP>; xinetd: only_from = <server IP>"), true
}
