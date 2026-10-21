package rules

// Config-file probes: parse common formats into effective key/value
// documents. Parsing is deliberately forgiving (the daemon's own -t/-T is
// the real validator); include directives are followed with depth and
// size limits.

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var configFormats = []string{"kv", "env", "ini", "sshd", "nginx", "apache", "php", "phpfpm", "mycnf", "postgresql", "redis", "yaml", "json"}

func validFormat(f string) bool {
	for _, x := range configFormats {
		if x == f {
			return true
		}
	}
	return false
}

func formatNeedsPath(f string) bool {
	switch f {
	case "sshd", "nginx", "apache", "php", "phpfpm", "mycnf":
		return false
	}
	return true
}

type cfgEntry struct {
	val, file, ctx string
	line           int
}

func (e cfgEntry) loc() string {
	if e.line > 0 {
		return fmt.Sprintf("%s:%d", e.file, e.line)
	}
	return e.file
}

// cfgDoc is one effective configuration (a file set, an instance, a pool).
type cfgDoc struct {
	label     string // finding-ID key when there are several docs
	loc       string
	entries   map[string][]cfgEntry
	firstWins bool
	each      bool // report every occurrence (nginx/apache directives)
}

func newDoc(label string) cfgDoc {
	return cfgDoc{label: label, loc: label, entries: map[string][]cfgEntry{}}
}

func (d cfgDoc) add(k string, e cfgEntry) { d.entries[k] = append(d.entries[k], e) }

func (d cfgDoc) get(k string, _ bool) (cfgEntry, bool) {
	es := d.entries[k]
	if len(es) == 0 {
		return cfgEntry{}, false
	}
	if d.firstWins {
		return es[0], true
	}
	return es[len(es)-1], true
}

// ---- probe ------------------------------------------------------------------

func (env *evalEnv) probeConfig(ctx context.Context, p *Probe) probeOut {
	docs, skip := env.loadConfig(ctx, p)
	if skip != "" {
		return probeOut{skip: skip}
	}
	keys := []string(p.Keys)
	if p.Key != "" {
		keys = append([]string{p.Key}, keys...)
	}
	norm := func(k string) string {
		switch p.Format {
		case "yaml", "json":
			return k
		case "mycnf":
			return strings.ToLower(strings.ReplaceAll(k, "-", "_"))
		}
		return strings.ToLower(k)
	}
	lookup := func(k string) string {
		k = norm(k)
		if p.Section != "" {
			return strings.ToLower(p.Section) + "." + k
		}
		return k
	}
	def, hasDef := env.configDefault(p)
	multi := len(docs) > 1 || p.PerFile
	var out []obs
	for _, d := range docs {
		base := obs{fLoc: d.loc}
		if multi {
			base[fKey] = d.label
		}
		primary := lookup(keys[0])
		if d.each && len(keys) == 1 {
			es := d.entries[primary]
			if len(es) == 0 {
				o := cloneObs(base)
				env.setDefault(o, keys[0], def, hasDef, d.loc)
				out = append(out, env.splitObs(p, o)...)
				continue
			}
			for _, e := range es {
				o := cloneObs(base)
				o["value"], o[norm(keys[0])], o["file"], o["context"], o["set"] = e.val, e.val, e.loc(), e.ctx, "true"
				o[fLoc] = e.loc()
				out = append(out, env.splitObs(p, o)...)
			}
			continue
		}
		o := cloneObs(base)
		for i, k := range keys {
			e, ok := d.get(lookup(k), false)
			if !ok {
				if i == 0 {
					env.setDefault(o, k, def, hasDef, d.loc)
				} else {
					o[norm(k)] = "" // unset secondary key: known and empty
				}
				continue
			}
			o[norm(k)] = e.val
			if i == 0 {
				o["value"], o["file"], o["set"] = e.val, e.loc(), "true"
				o[fLoc] = e.loc()
			}
		}
		out = append(out, env.splitObs(p, o)...)
	}
	return probeOut{obs: out}
}

func cloneObs(o obs) obs {
	c := obs{}
	for k, v := range o {
		c[k] = v
	}
	return c
}

func (env *evalEnv) setDefault(o obs, k, def string, hasDef bool, loc string) {
	o["set"] = "false"
	if hasDef {
		o["value"], o[strings.ToLower(k)], o["file"] = def, def, "(default)"
		o[fLoc] = loc + " (" + k + " not set; default " + def + ")"
		return
	}
	o["value"], o["file"] = "", "(unset)"
	o[fLoc] = loc + " (" + k + " not set)"
}

// splitObs fans a list value ("a,b,c") into one observation per element.
func (env *evalEnv) splitObs(p *Probe, o obs) []obs {
	if p.Split == "" {
		return []obs{o}
	}
	var out []obs
	for _, el := range strings.Split(o["value"], p.Split) {
		el = strings.TrimSpace(el)
		if el == "" {
			continue
		}
		c := cloneObs(o)
		c["list"] = o["value"]
		c["value"] = el
		if c[fKey] != "" {
			c[fKey] += ":" + el
		} else {
			c[fKey] = el
		}
		out = append(out, c)
	}
	return out
}

func (env *evalEnv) configDefault(p *Probe) (string, bool) {
	for _, d := range p.Defaults {
		if env.osMatchAny(d.OS) && (d.VersionGE == "" || env.osVersionCmp(d.VersionGE) >= 0) && (d.VersionLT == "" || env.osVersionCmp(d.VersionLT) < 0) {
			return d.Value, true
		}
	}
	if p.Default != nil {
		return *p.Default, true
	}
	return "", false
}

func (env *evalEnv) loadConfig(ctx context.Context, p *Probe) ([]cfgDoc, string) {
	switch p.Format {
	case "sshd":
		d, ok := env.sshdDoc(ctx)
		if !ok {
			return nil, ""
		}
		return []cfgDoc{d}, ""
	case "nginx":
		c := env.h.loadNginx(ctx)
		if c == nil {
			return nil, ""
		}
		d := newDoc("nginx")
		d.loc = "nginx config"
		d.entries = nginxEntries(c)
		d.each = true
		return []cfgDoc{d}, ""
	case "apache":
		ents := env.apacheEntries()
		if ents == nil {
			return nil, ""
		}
		d := newDoc("apache")
		d.loc = "apache config"
		d.entries = ents
		d.each = true
		return []cfgDoc{d}, ""
	case "php":
		return env.phpDocs(), ""
	case "phpfpm":
		return env.fpmDocs(), ""
	case "mycnf":
		paths := []string(p.Paths)
		if len(paths) == 0 {
			paths = []string{"/etc/my.cnf", "/etc/mysql/my.cnf"}
		}
		return env.kvDocs(paths, "mycnf", p.PerFile), ""
	case "postgresql", "redis":
		return env.kvDocs(p.Paths, p.Format, true), ""
	}
	return env.kvDocs(p.Paths, p.Format, p.PerFile), ""
}

// kvDocs parses files of a line format; perFile=false merges them in order.
func (env *evalEnv) kvDocs(paths []string, format string, perFile bool) []cfgDoc {
	key := fmt.Sprintf("decl:cfg:%s:%v:%s", format, perFile, strings.Join(paths, "|"))
	return env.h.once(key, func() any {
		files := env.expand(paths)
		var docs []cfgDoc
		if len(files) == 0 {
			return docs
		}
		if !perFile {
			d := newDoc("")
			d.loc = strings.Join(files, ", ")
			for _, f := range files {
				env.parseInto(d, f, format, 0, "")
			}
			return []cfgDoc{d}
		}
		for _, f := range files {
			d := newDoc(f)
			env.parseInto(d, f, format, 0, "")
			docs = append(docs, d)
		}
		return docs
	}).([]cfgDoc)
}

var (
	inlineHashRE  = regexp.MustCompile(`\s+#.*$`)
	mysqlServerRE = regexp.MustCompile(`^(mysqld|mariadb|mariadbd|server|galera|mysqld-[0-9.]+|mariadb-[0-9.]+)$`)
)

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func (env *evalEnv) parseInto(d cfgDoc, f, format string, depth int, section string) {
	if depth > 5 {
		return
	}
	switch format {
	case "yaml", "json":
		env.parseStructured(d, f, format)
		return
	}
	src, ok := readCapped(env.h, f, 2<<20)
	if !ok {
		return
	}
	dir := path.Dir(f)
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		e := cfgEntry{file: f, line: i + 1}
		switch format {
		case "ini", "mycnf", "phpini":
			if format == "phpini" && line[0] == '[' {
				continue // php.ini [Section] headers are cosmetic
			}
			if strings.HasPrefix(line, "!include") {
				fs := strings.Fields(line)
				if len(fs) == 2 && format == "mycnf" {
					if fs[0] == "!includedir" {
						for _, g := range env.h.Glob(fs[1] + "/*.cnf") {
							env.parseInto(d, g, format, depth+1, section)
						}
					} else {
						env.parseInto(d, fs[1], format, depth+1, section)
					}
				}
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
				if format == "mycnf" && mysqlServerRE.MatchString(section) {
					section = "mysqld"
				}
				continue
			}
			k, v, hasEq := strings.Cut(line, "=")
			k = strings.ToLower(strings.TrimSpace(k))
			if format == "mycnf" {
				k = strings.ReplaceAll(k, "-", "_")
				if !hasEq {
					v = "ON"
				}
			} else if !hasEq {
				// pam-style flags in pwquality/faillock.conf: "enforce_for_root"
				v = "true"
			}
			if i := strings.Index(v, " #"); i >= 0 {
				v = v[:i]
			}
			if i := strings.Index(v, " ;"); i >= 0 {
				v = v[:i]
			}
			e.val = unquote(v)
			if section != "" {
				d.add(section+"."+k, e)
			} else {
				d.add(k, e)
			}
		case "env":
			line = strings.TrimPrefix(line, "export ")
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if len(v) > 0 && v[0] != '"' && v[0] != '\'' {
				v = inlineHashRE.ReplaceAllString(v, "")
			}
			e.val = unquote(v)
			d.add(strings.ToLower(strings.TrimSpace(k)), e)
		default: // kv, postgresql, redis
			k, v := splitKV(line)
			if k == "" {
				continue
			}
			k = strings.ToLower(k)
			v = strings.TrimSpace(v)
			if len(v) > 0 && v[0] != '"' && v[0] != '\'' {
				v = inlineHashRE.ReplaceAllString(v, "")
			}
			v = unquote(v)
			switch {
			case format == "redis" && k == "include":
				env.parseInto(d, v, format, depth+1, "")
				continue
			case format == "postgresql" && (k == "include" || k == "include_if_exists"):
				if !strings.HasPrefix(v, "/") {
					v = path.Join(dir, v)
				}
				env.parseInto(d, v, format, depth+1, "")
				continue
			case format == "postgresql" && k == "include_dir":
				if !strings.HasPrefix(v, "/") {
					v = path.Join(dir, v)
				}
				for _, g := range env.h.Glob(v + "/*.conf") {
					env.parseInto(d, g, format, depth+1, "")
				}
				continue
			}
			e.val = v
			d.add(k, e)
		}
	}
	if format == "postgresql" && depth == 0 {
		// ALTER SYSTEM settings override postgresql.conf.
		if auto := dir + "/postgresql.auto.conf"; env.h.Exists(auto) {
			env.parseInto(d, auto, format, depth+1, "")
		}
	}
}

// splitKV splits "key value", "key=value" and "key = value".
func splitKV(line string) (string, string) {
	ws := strings.IndexAny(line, " \t")
	eq := strings.IndexByte(line, '=')
	if eq > 0 && (ws < 0 || eq < ws || strings.TrimSpace(line[ws:eq]) == "") {
		return strings.TrimSpace(line[:eq]), line[eq+1:]
	}
	if ws < 0 {
		return line, ""
	}
	return line[:ws], line[ws+1:]
}

func (env *evalEnv) parseStructured(d cfgDoc, f, format string) {
	src, ok := readCapped(env.h, f, 2<<20)
	if !ok {
		return
	}
	var v any
	var err error
	if format == "json" {
		err = json.Unmarshal([]byte(src), &v)
	} else {
		err = yaml.Unmarshal([]byte(src), &v)
	}
	if err != nil {
		return
	}
	var walk func(prefix string, x any)
	walk = func(prefix string, x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, c := range t {
				walk(joinKey(prefix, k), c)
			}
			if prefix != "" {
				d.add(prefix, cfgEntry{val: "{...}", file: f})
			}
		case map[any]any:
			for k, c := range t {
				walk(joinKey(prefix, fmt.Sprint(k)), c)
			}
		case []any:
			var parts []string
			for i, c := range t {
				walk(joinKey(prefix, fmt.Sprint(i)), c)
				switch c.(type) {
				case map[string]any, []any, map[any]any:
				default:
					parts = append(parts, fmt.Sprint(c))
				}
			}
			d.add(prefix, cfgEntry{val: strings.Join(parts, ","), file: f})
		case nil:
			d.add(prefix, cfgEntry{val: "", file: f})
		default:
			d.add(prefix, cfgEntry{val: fmt.Sprint(t), file: f})
		}
	}
	walk("", v)
}

func joinKey(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

// ---- nginx / apache ---------------------------------------------------------

func nginxEntries(c *nginxConf) map[string][]cfgEntry {
	out := map[string][]cfgEntry{}
	var walk func(ds []nginxDirective, ctx string)
	walk = func(ds []nginxDirective, ctx string) {
		for _, d := range ds {
			if d.Block != nil {
				walk(d.Block, strings.TrimSpace(ctx+" "+d.Name))
				continue
			}
			out[d.Name] = append(out[d.Name], cfgEntry{val: strings.Join(d.Args, " "), file: d.File, ctx: ctx})
		}
	}
	walk(c.Top, "")
	return out
}

func (env *evalEnv) apacheEntries() map[string][]cfgEntry {
	return env.h.once("decl:apache", func() any {
		var main, root string
		for _, c := range [][2]string{{"/etc/httpd/conf/httpd.conf", "/etc/httpd"}, {"/etc/apache2/apache2.conf", "/etc/apache2"}} {
			if env.h.Exists(c[0]) {
				main, root = c[0], c[1]
				break
			}
		}
		if main == "" {
			return map[string][]cfgEntry(nil)
		}
		out := map[string][]cfgEntry{}
		seen := map[string]bool{}
		var ctx []string
		var load func(f string, depth int)
		load = func(f string, depth int) {
			if depth > 6 || seen[f] {
				return
			}
			seen[f] = true
			src, ok := readCapped(env.h, f, 2<<20)
			if !ok {
				return
			}
			lines := strings.Split(src, "\n")
			for i := 0; i < len(lines); i++ {
				ln := i + 1
				line := strings.TrimSpace(lines[i])
				for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
					i++
					line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[i])
				}
				if line == "" || line[0] == '#' {
					continue
				}
				if strings.HasPrefix(line, "</") {
					if len(ctx) > 0 {
						ctx = ctx[:len(ctx)-1]
					}
					continue
				}
				if strings.HasPrefix(line, "<") {
					ctx = append(ctx, strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">"))
					continue
				}
				name, args, _ := strings.Cut(line, " ")
				name = strings.ToLower(name)
				args = strings.TrimSpace(args)
				if name == "serverroot" {
					root = unquote(args)
				}
				if name == "include" || name == "includeoptional" {
					pat := unquote(args)
					if !strings.HasPrefix(pat, "/") {
						pat = root + "/" + pat
					}
					var ms []string
					if env.h.IsDir(pat) {
						ms = env.h.Glob(pat + "/*")
					} else {
						ms = env.h.Glob(pat)
					}
					sort.Strings(ms)
					for _, m := range ms {
						if !env.h.IsDir(m) {
							load(m, depth+1)
						}
					}
					continue
				}
				out[name] = append(out[name], cfgEntry{val: args, file: f, line: ln, ctx: strings.Join(ctx, " > ")})
			}
		}
		load(main, 0)
		return out
	}).(map[string][]cfgEntry)
}

// ---- sshd -------------------------------------------------------------------

// sshdDefaults are OpenSSH (8.x/9.x) compiled-in defaults, used only when
// `sshd -T` cannot run and sshd_config leaves a key unset.
var sshdDefaults = map[string]string{
	"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "permitemptypasswords": "no",
	"pubkeyauthentication": "yes", "hostbasedauthentication": "no", "ignorerhosts": "yes",
	"kbdinteractiveauthentication": "yes", "challengeresponseauthentication": "yes",
	"x11forwarding": "no", "allowagentforwarding": "yes", "allowtcpforwarding": "yes", "allowstreamlocalforwarding": "yes",
	"gatewayports": "no", "permittunnel": "no", "permituserenvironment": "no", "strictmodes": "yes",
	"maxauthtries": "6", "maxsessions": "10", "maxstartups": "10:30:100", "logingracetime": "120",
	"clientaliveinterval": "0", "clientalivecountmax": "3", "loglevel": "INFO", "usedns": "no",
	"tcpkeepalive": "yes", "compression": "yes", "banner": "none", "printlastlog": "yes",
	"gssapiauthentication": "no", "kerberosauthentication": "no", "usepam": "no", "syslogfacility": "AUTH",
	"disableforwarding": "no", "permitopen": "any", "port": "22", "addressfamily": "any", "listenaddress": "0.0.0.0",
	"ciphers":       "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
	"macs":          "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
	"kexalgorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
}

func sshTimeSeconds(v string) string {
	if n := parseTimeSeconds(v); n > 0 || v == "0" {
		return fmt.Sprint(n)
	}
	return v
}

// sshdDoc is the effective sshd configuration: `sshd -T` when it runs,
// otherwise sshd_config (+Include, first value wins, Match blocks ignored)
// over compiled-in defaults.
func (env *evalEnv) sshdDoc(ctx context.Context) (cfgDoc, bool) {
	type res struct {
		d  cfgDoc
		ok bool
	}
	r := env.h.once("decl:sshd", func() any {
		d := newDoc("sshd")
		d.firstWins = true
		if out, err := env.h.Run(ctx, "sshd", "-T"); err == nil && strings.Contains(out, "permitrootlogin") {
			d.loc = "sshd -T"
			for _, line := range strings.Split(out, "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
				if !ok {
					continue
				}
				d.add(strings.ToLower(k), cfgEntry{val: v, file: "sshd -T"})
			}
			if es, ok := d.entries["kbdinteractiveauthentication"]; ok && len(d.entries["challengeresponseauthentication"]) == 0 {
				d.entries["challengeresponseauthentication"] = es
			}
			return res{d, true}
		}
		if !env.h.Exists("/etc/ssh/sshd_config") {
			return res{}
		}
		d.loc = "/etc/ssh/sshd_config"
		stopped := false
		var load func(f string, depth int)
		load = func(f string, depth int) {
			if depth > 5 || stopped {
				return
			}
			src, ok := readCapped(env.h, f, 1<<20)
			if !ok {
				return
			}
			for i, raw := range strings.Split(src, "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || line[0] == '#' {
					continue
				}
				fs := strings.Fields(line)
				k := strings.ToLower(fs[0])
				if k == "match" {
					stopped = true
					return
				}
				if len(fs) < 2 {
					continue
				}
				if k == "include" {
					for _, pat := range fs[1:] {
						if !strings.HasPrefix(pat, "/") {
							pat = "/etc/ssh/" + pat
						}
						for _, m := range env.h.Glob(pat) {
							load(m, depth+1)
							if stopped {
								return
							}
						}
					}
					continue
				}
				v := strings.Join(fs[1:], " ")
				switch k {
				case "logingracetime", "clientaliveinterval":
					v = sshTimeSeconds(v)
				case "challengeresponseauthentication":
					d.add("kbdinteractiveauthentication", cfgEntry{val: strings.ToLower(v), file: f, line: i + 1})
				case "kbdinteractiveauthentication":
					d.add("challengeresponseauthentication", cfgEntry{val: strings.ToLower(v), file: f, line: i + 1})
				}
				if len(fs) == 2 && k != "banner" && k != "authorizedkeysfile" {
					v = strings.ToLower(v)
				}
				d.add(k, cfgEntry{val: v, file: f, line: i + 1})
			}
		}
		load("/etc/ssh/sshd_config", 0)
		for k, v := range sshdDefaults {
			d.add(k, cfgEntry{val: v, file: "(OpenSSH default)"})
		}
		return res{d, true}
	}).(res)
	return r.d, r.ok
}

// ---- php --------------------------------------------------------------------

type phpSAPI struct{ label, ini, dir string }

func (env *evalEnv) phpSAPIs() []phpSAPI {
	var out []phpSAPI
	if env.h.Exists("/etc/php.ini") {
		out = append(out, phpSAPI{"system", "/etc/php.ini", "/etc/php.d"})
	}
	for _, d := range env.h.Glob("/etc/opt/remi/php*") {
		if env.h.Exists(d + "/php.ini") {
			out = append(out, phpSAPI{"remi-" + path.Base(d), d + "/php.ini", d + "/php.d"})
		}
	}
	for _, sapi := range []string{"fpm", "apache2", "cgi"} {
		for _, d := range env.h.Glob("/etc/php/*/" + sapi) {
			if env.h.Exists(d + "/php.ini") {
				out = append(out, phpSAPI{"php" + path.Base(path.Dir(d)) + "-" + sapi, d + "/php.ini", d + "/conf.d"})
			}
		}
	}
	for _, d := range env.h.Glob("/etc/php*/php.ini") { // Alpine: /etc/php82/php.ini
		dir := path.Dir(d)
		if path.Base(dir) != "php" && strings.HasPrefix(path.Base(dir), "php") {
			out = append(out, phpSAPI{path.Base(dir), d, dir + "/conf.d"})
		}
	}
	return out
}

func (env *evalEnv) phpDocs() []cfgDoc {
	return env.h.once("decl:php", func() any {
		var docs []cfgDoc
		for _, s := range env.phpSAPIs() {
			d := newDoc(s.label)
			d.loc = s.ini
			// php.ini first, then conf.d/*.ini alphabetically: PHP's own order.
			env.parseInto(d, s.ini, "phpini", 0, "")
			for _, f := range env.h.Glob(s.dir + "/*.ini") {
				env.parseInto(d, f, "phpini", 0, "")
			}
			docs = append(docs, d)
		}
		return docs
	}).([]cfgDoc)
}

func (env *evalEnv) fpmDocs() []cfgDoc {
	return env.h.once("decl:fpm", func() any {
		var globs []string
		globs = append(globs, "/etc/php-fpm.d/*.conf", "/etc/opt/remi/php*/php-fpm.d/*.conf", "/etc/php/*/fpm/pool.d/*.conf", "/etc/php*/php-fpm.d/*.conf")
		var docs []cfgDoc
		for _, f := range env.expand(globs) {
			src, ok := readCapped(env.h, f, 1<<20)
			if !ok {
				continue
			}
			var cur *cfgDoc
			for i, raw := range strings.Split(src, "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || line[0] == ';' || line[0] == '#' {
					continue
				}
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					name := strings.Trim(line, "[]")
					if name == "global" {
						cur = nil
						continue
					}
					d := newDoc(f + ":" + name)
					d.loc = f + " [" + name + "]"
					docs = append(docs, d)
					cur = &docs[len(docs)-1]
					continue
				}
				if cur == nil {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				cur.add(strings.ToLower(strings.TrimSpace(k)), cfgEntry{val: unquote(v), file: f, line: i + 1})
			}
		}
		return docs
	}).([]cfgDoc)
}
