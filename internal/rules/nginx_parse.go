package rules

import (
	"context"
	"path"
	"strings"
)

// nginxDirective is one parsed directive; Block is set for `name args { ... }`.
type nginxDirective struct {
	Name  string
	Args  []string
	Block []nginxDirective
	File  string
}

// nginxConf is the parsed configuration plus the comments seen (used for
// intent markers such as "cloudflare").
type nginxConf struct {
	Top      []nginxDirective
	Comments []string
	Files    []string
}

// tokenizeNginx splits nginx config text into tokens, with comments
// returned separately. Quotes are honoured; ; { } are their own tokens.
func tokenizeNginx(src string) (toks []string, comments []string) {
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '#':
			flush()
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				j = len(src) - i
			}
			comments = append(comments, strings.TrimSpace(src[i+1:i+j]))
			i += j
		case c == '"' || c == '\'':
			flush()
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j > len(src) {
				j = len(src)
			}
			toks = append(toks, src[i+1:min(j, len(src))])
			i = j
		case c == ';' || c == '{' || c == '}':
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks, comments
}

// parseNginxTokens builds the directive tree. Unbalanced input is
// tolerated (best effort; nginx -t is the real validator).
func parseNginxTokens(toks []string, pos *int, file string) []nginxDirective {
	var out []nginxDirective
	var cur []string
	for *pos < len(toks) {
		t := toks[*pos]
		*pos++
		switch t {
		case ";":
			if len(cur) > 0 {
				out = append(out, nginxDirective{Name: cur[0], Args: cur[1:], File: file})
			}
			cur = nil
		case "{":
			d := nginxDirective{File: file}
			if len(cur) > 0 {
				d.Name, d.Args = cur[0], cur[1:]
			}
			d.Block = parseNginxTokens(toks, pos, file)
			out = append(out, d)
			cur = nil
		case "}":
			return out
		default:
			cur = append(cur, t)
		}
	}
	return out
}

// loadNginx parses the nginx config (memoized per scan). It reads
// /etc/nginx/nginx.conf and follows include globs; if that file is missing
// it falls back to `nginx -T`, which dumps every file with a
// "# configuration file X:" header.
func (h *Host) loadNginx(ctx context.Context) *nginxConf {
	return h.once("nginx", func() any {
		files := map[string]string{}
		mainPath := "/etc/nginx/nginx.conf"
		read := func(p string) (string, bool) {
			if s, ok := files[p]; ok {
				return s, true
			}
			b, err := h.ReadFile(p)
			if err != nil {
				return "", false
			}
			return string(b), true
		}
		if !h.Exists(mainPath) {
			out, err := h.Run(ctx, "nginx", "-T")
			if err != nil && out == "" {
				return (*nginxConf)(nil)
			}
			first := ""
			for name, body := range splitNginxDump(out) {
				files[name] = body
				if strings.HasSuffix(name, "/nginx.conf") && (first == "" || len(name) < len(first)) {
					first = name
				}
			}
			if first == "" {
				return (*nginxConf)(nil)
			}
			mainPath = first
			read = func(p string) (string, bool) { s, ok := files[p]; return s, ok }
		}
		conf := &nginxConf{}
		seen := map[string]bool{}
		var load func(p string, depth int) []nginxDirective
		load = func(p string, depth int) []nginxDirective {
			if depth > 8 || seen[p] {
				return nil
			}
			seen[p] = true
			src, ok := read(p)
			if !ok {
				return nil
			}
			conf.Files = append(conf.Files, p)
			toks, comments := tokenizeNginx(src)
			conf.Comments = append(conf.Comments, comments...)
			pos := 0
			return expandIncludes(parseNginxTokens(toks, &pos, p), func(pattern string) []nginxDirective {
				if !strings.HasPrefix(pattern, "/") {
					pattern = path.Join(path.Dir(mainPath), pattern)
				}
				var ds []nginxDirective
				matches := h.Glob(pattern)
				if len(files) > 0 {
					matches = globMap(files, pattern)
				}
				for _, m := range matches {
					ds = append(ds, load(m, depth+1)...)
				}
				return ds
			})
		}
		conf.Top = load(mainPath, 0)
		if len(conf.Files) == 0 {
			return (*nginxConf)(nil)
		}
		return conf
	}).(*nginxConf)
}

func expandIncludes(ds []nginxDirective, inc func(string) []nginxDirective) []nginxDirective {
	var out []nginxDirective
	for _, d := range ds {
		if d.Name == "include" && len(d.Args) == 1 && d.Block == nil {
			out = append(out, inc(d.Args[0])...)
			continue
		}
		if d.Block != nil {
			d.Block = expandIncludes(d.Block, inc)
		}
		out = append(out, d)
	}
	return out
}

func splitNginxDump(out string) map[string]string {
	files := map[string]string{}
	cur := ""
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# configuration file ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			if cur != "" {
				files[cur] = b.String()
			}
			cur = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "# configuration file "), ":")
			b.Reset()
			continue
		}
		if cur != "" {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if cur != "" {
		files[cur] = b.String()
	}
	return files
}

func globMap(files map[string]string, pattern string) []string {
	var out []string
	for name := range files {
		if ok, _ := path.Match(pattern, name); ok {
			out = append(out, name)
		}
	}
	return out
}

// ---- semantic model --------------------------------------------------------

type nginxLocation struct {
	Match    string // "~ \.php$", "/uploads/", ...
	Root     string // effective root (inherited)
	Alias    string
	FastCGI  string
	TryFiles []string
	DenyAll  bool
	Allows   []string
}

// PHP reports whether the location hands requests to PHP.
func (l nginxLocation) PHP() bool {
	return l.FastCGI != "" || strings.Contains(l.Match, ".php")
}

type nginxServer struct {
	Names      []string
	Listens    []string
	Root       string
	Locations  []nginxLocation
	ErrorPages [][]string
	Certs      []string
	DenyAll    bool
	Allows     []string
	RealIP     []string // set_real_ip_from + real_ip_header values
	File       string
}

func (s nginxServer) Label() string {
	if len(s.Names) > 0 && s.Names[0] != "_" && s.Names[0] != "" {
		return s.Names[0]
	}
	if len(s.Listens) > 0 {
		return "listen " + s.Listens[0]
	}
	return s.File
}

type nginxModel struct {
	Servers   []nginxServer
	Upstreams map[string][]string // name -> server addresses
	Comments  []string
}

func firstArg(d nginxDirective) string {
	if len(d.Args) > 0 {
		return d.Args[0]
	}
	return ""
}

// nginxModelOf flattens the directive tree into servers and locations,
// applying root inheritance (http -> server -> location).
func nginxModelOf(c *nginxConf) *nginxModel {
	m := &nginxModel{Upstreams: map[string][]string{}, Comments: c.Comments}
	var walkHTTP func(ds []nginxDirective, root string, deny bool, allows, realIP []string)
	walkHTTP = func(ds []nginxDirective, root string, deny bool, allows, realIP []string) {
		for _, d := range ds {
			switch d.Name {
			case "root":
				root = firstArg(d)
			case "deny":
				if firstArg(d) == "all" {
					deny = true
				}
			case "allow":
				allows = append(allows, firstArg(d))
			case "set_real_ip_from", "real_ip_header":
				realIP = append(realIP, firstArg(d))
			}
		}
		for _, d := range ds {
			switch d.Name {
			case "http", "":
				walkHTTP(d.Block, root, deny, allows, realIP)
			case "upstream":
				for _, u := range d.Block {
					if u.Name == "server" {
						m.Upstreams[firstArg(d)] = append(m.Upstreams[firstArg(d)], firstArg(u))
					}
				}
			case "server":
				if d.Block != nil {
					m.Servers = append(m.Servers, buildServer(d, root, deny, allows, realIP))
				}
			}
		}
	}
	walkHTTP(c.Top, "", false, nil, nil)
	return m
}

func buildServer(d nginxDirective, root string, deny bool, allows, realIP []string) nginxServer {
	s := nginxServer{Root: root, DenyAll: deny, File: d.File,
		Allows: append([]string(nil), allows...), RealIP: append([]string(nil), realIP...)}
	for _, x := range d.Block {
		switch x.Name {
		case "server_name":
			s.Names = append(s.Names, x.Args...)
		case "listen":
			s.Listens = append(s.Listens, strings.Join(x.Args, " "))
		case "root":
			s.Root = firstArg(x)
		case "error_page":
			s.ErrorPages = append(s.ErrorPages, x.Args)
		case "ssl_certificate":
			s.Certs = append(s.Certs, firstArg(x))
		case "deny":
			if firstArg(x) == "all" {
				s.DenyAll = true
			}
		case "allow":
			s.Allows = append(s.Allows, firstArg(x))
		case "set_real_ip_from", "real_ip_header":
			s.RealIP = append(s.RealIP, firstArg(x))
		}
	}
	var addLocs func(ds []nginxDirective, root string)
	addLocs = func(ds []nginxDirective, root string) {
		for _, x := range ds {
			if x.Name != "location" || x.Block == nil {
				continue
			}
			l := nginxLocation{Match: strings.Join(x.Args, " "), Root: root}
			for _, y := range x.Block {
				switch y.Name {
				case "root":
					l.Root = firstArg(y)
				case "alias":
					l.Alias = firstArg(y)
				case "fastcgi_pass":
					l.FastCGI = firstArg(y)
				case "try_files":
					l.TryFiles = y.Args
				case "deny":
					if firstArg(y) == "all" {
						l.DenyAll = true
					}
				case "allow":
					l.Allows = append(l.Allows, firstArg(y))
				case "return":
					if firstArg(y) == "403" || firstArg(y) == "404" {
						l.DenyAll = true
					}
				}
			}
			s.Locations = append(s.Locations, l)
			addLocs(x.Block, l.Root)
		}
	}
	addLocs(d.Block, s.Root)
	return s
}

// webRoots returns every document root / alias directory nginx and Apache
// serve (host paths, deduplicated, no variables).
func (h *Host) webRoots(ctx context.Context) []string {
	return h.once("webroots", func() any {
		seen := map[string]bool{}
		var out []string
		add := func(p string) {
			p = strings.TrimRight(p, "/")
			if p == "" || strings.Contains(p, "$") || seen[p] || !strings.HasPrefix(p, "/") {
				return
			}
			if !h.IsDir(p) {
				return
			}
			seen[p] = true
			out = append(out, p)
		}
		if c := h.loadNginx(ctx); c != nil {
			for _, s := range nginxModelOf(c).Servers {
				add(s.Root)
				for _, l := range s.Locations {
					add(l.Root)
					add(l.Alias)
				}
			}
		}
		for _, p := range apacheDocRoots(h) {
			add(p)
		}
		return out
	}).([]string)
}

// apacheDocRoots greps DocumentRoot/Alias from httpd/apache2 configs.
func apacheDocRoots(h *Host) []string {
	var files []string
	for _, g := range []string{"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
		"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*", "/etc/apache2/conf-enabled/*"} {
		files = append(files, h.Glob(g)...)
	}
	var out []string
	for _, f := range files {
		b, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(strings.TrimSpace(line))
			if len(fs) >= 2 && strings.EqualFold(fs[0], "DocumentRoot") {
				out = append(out, strings.Trim(fs[1], `"`))
			}
			if len(fs) >= 3 && strings.EqualFold(fs[0], "Alias") {
				out = append(out, strings.Trim(fs[2], `"`))
			}
		}
	}
	return out
}
