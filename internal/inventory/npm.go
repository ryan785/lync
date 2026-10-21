package inventory

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- package-lock.json / npm-shrinkwrap.json (v1, v2, v3) ----------------

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev"`
	Bundled      bool                    `json:"bundled"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
}

type npmLock struct {
	LockfileVersion int                     `json:"lockfileVersion"`
	Packages        map[string]npmLockPkg   `json:"packages"`
	Dependencies    map[string]npmLockV1Dep `json:"dependencies"`
}

func (c *collector) npmLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	comps, err := parseNPMLock(data)
	if err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	c.addAll(comps, hp, SourceLockfile)
}

func parseNPMLock(data []byte) ([]Component, error) {
	var l npmLock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	var out []Component
	if len(l.Packages) > 0 { // v2 / v3
		for key, p := range l.Packages {
			if key == "" || p.Link || p.Version == "" {
				continue
			}
			name := p.Name
			if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
				name = key[i+len("node_modules/"):]
			}
			if name == "" || strings.HasPrefix(p.Version, "file:") || strings.HasPrefix(p.Version, "link:") {
				continue
			}
			out = append(out, Component{Ecosystem: EcoNPM, Name: name, Version: p.Version, Dev: p.Dev})
		}
		return out, nil
	}
	var walk func(deps map[string]npmLockV1Dep, depth int)
	walk = func(deps map[string]npmLockV1Dep, depth int) {
		if depth > 64 {
			return
		}
		for name, d := range deps {
			if d.Version != "" && !strings.Contains(d.Version, ":") {
				out = append(out, Component{Ecosystem: EcoNPM, Name: name, Version: d.Version, Dev: d.Dev})
			}
			walk(d.Dependencies, depth+1)
		}
	}
	walk(l.Dependencies, 0)
	return out, nil
}

// ---- yarn.lock (classic v1 and berry) -------------------------------------

func (c *collector) yarnLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	c.addAll(parseYarnLock(data), hp, SourceLockfile)
}

// parseYarnLock handles both formats: classic blocks
//
//	"lodash@^4.17.0", lodash@^4.17.15:
//	  version "4.17.15"
//
// and berry (YAML) blocks
//
//	"lodash@npm:^4.17.0":
//	  version: 4.17.15
//	  resolution: "lodash@npm:4.17.15"
func parseYarnLock(data []byte) []Component {
	var out []Component
	var header string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			header = strings.TrimSuffix(line, ":")
			continue
		}
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "version") || header == "" || strings.HasPrefix(header, "__metadata") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(t, "version"))
		v = strings.Trim(strings.TrimPrefix(v, ":"), ` "`)
		first := strings.TrimSpace(strings.Split(header, ",")[0])
		first = strings.Trim(first, `"`)
		if strings.Contains(first, "@workspace:") || strings.Contains(first, "@link:") ||
			strings.Contains(first, "@portal:") || strings.Contains(first, "@file:") {
			header = ""
			continue
		}
		name := npmDescriptorName(first)
		if name != "" && v != "" && !strings.Contains(v, "-use.local") {
			out = append(out, Component{Ecosystem: EcoNPM, Name: name, Version: v})
		}
		header = ""
	}
	return out
}

// npmDescriptorName returns the package name of "name@range" or
// "@scope/name@npm:range".
func npmDescriptorName(d string) string {
	at := strings.LastIndex(d, "@")
	if at <= 0 {
		return d
	}
	name := d[:at]
	// "pkg@npm:other@^1" aliases: keep the left-hand name.
	if i := strings.Index(name[1:], "@"); i >= 0 {
		name = name[:i+1]
	}
	return name
}

// ---- pnpm-lock.yaml (v5, v6, v9) ------------------------------------------

type pnpmLock struct {
	LockfileVersion any                       `yaml:"lockfileVersion"`
	Packages        map[string]map[string]any `yaml:"packages"`
	Snapshots       map[string]any            `yaml:"snapshots"`
}

func (c *collector) pnpmLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	comps, err := parsePNPMLock(data)
	if err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	c.addAll(comps, hp, SourceLockfile)
}

func parsePNPMLock(data []byte) ([]Component, error) {
	var l pnpmLock
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	var out []Component
	for key, attrs := range l.Packages {
		name, ver := pnpmKey(key)
		if name == "" || ver == "" {
			continue
		}
		if v, ok := attrs["version"].(string); ok && v != "" && !strings.Contains(v, ":") {
			ver = v
		}
		if n, ok := attrs["name"].(string); ok && n != "" {
			name = n
		}
		dev, _ := attrs["dev"].(bool)
		out = append(out, Component{Ecosystem: EcoNPM, Name: name, Version: ver, Dev: dev})
	}
	return out, nil
}

// pnpmKey splits "/lodash/4.17.15" (v5), "/lodash@4.17.15" (v6),
// "lodash@4.17.15" (v9) and their "(peer@x)" / "_peer@x" suffixes.
func pnpmKey(key string) (name, ver string) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	if strings.Contains(k, ":") { // tarball / git / file references
		return "", ""
	}
	parts := strings.SplitN(k, "/", 4)
	nameParts := 1
	if strings.HasPrefix(k, "@") {
		nameParts = 2
	}
	if len(parts) == nameParts+1 && parts[nameParts] != "" && parts[nameParts][0] >= '0' && parts[nameParts][0] <= '9' {
		// v5: /name/1.2.3 or /@scope/name/1.2.3_peer@x
		name, ver = strings.Join(parts[:nameParts], "/"), parts[nameParts]
	} else if at := strings.LastIndex(k, "@"); at > 0 {
		name, ver = k[:at], k[at+1:]
	} else {
		return "", ""
	}
	if i := strings.Index(ver, "_"); i > 0 {
		ver = ver[:i]
	}
	if ver == "" || ver[0] < '0' || ver[0] > '9' {
		return "", ""
	}
	return name, ver
}

// ---- node_modules ---------------------------------------------------------

// nodeModulesDir handles a node_modules directory. Project lockfiles next to
// it already describe it; otherwise use npm's hidden lockfile, otherwise
// read installed package.json files (global installs, lockfile-less apps).
func (c *collector) nodeModulesDir(hp, local string) {
	parent := filepath.Dir(local)
	for _, lf := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if fileExists(filepath.Join(parent, lf)) {
			return
		}
	}
	hidden := filepath.Join(local, ".package-lock.json")
	if fileExists(hidden) {
		c.stats.FilesParsed++
		c.npmLock(hp+"/.package-lock.json", hidden)
		return
	}
	c.readNodeModules(hp, local, 0)
}

const maxNodeModulesPkgs = 5000

func (c *collector) readNodeModules(hp, local string, depth int) {
	if depth > 4 || !c.budgetLeft() {
		return
	}
	ents, err := os.ReadDir(local)
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		var pkgs []string
		if strings.HasPrefix(e.Name(), "@") {
			sub, _ := os.ReadDir(filepath.Join(local, e.Name()))
			for _, s := range sub {
				if s.IsDir() {
					pkgs = append(pkgs, e.Name()+"/"+s.Name())
				}
			}
		} else {
			pkgs = []string{e.Name()}
		}
		for _, p := range pkgs {
			n++
			if n > maxNodeModulesPkgs {
				c.warn("limit", hp, "more than %d packages; rest skipped", maxNodeModulesPkgs)
				return
			}
			c.stats.Entries++
			pl := filepath.Join(local, filepath.FromSlash(p))
			pj := filepath.Join(pl, "package.json")
			var meta struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if b := readHead(pj, 1<<20); b != nil && json.Unmarshal(b, &meta) == nil && meta.Version != "" {
				name := meta.Name
				if name == "" {
					name = p
				}
				c.stats.FilesParsed++
				c.add(Component{Ecosystem: EcoNPM, Name: name, Version: meta.Version,
					Paths: []string{path.Join(hp, p, "package.json")}, Source: SourceMetadata})
			}
			if nm := filepath.Join(pl, "node_modules"); dirExists(nm) {
				c.readNodeModules(path.Join(hp, p, "node_modules"), nm, depth+1)
			}
		}
	}
}

func dirExists(local string) bool {
	fi, err := os.Stat(local)
	return err == nil && fi.IsDir()
}

// addAll records parsed components found in one file.
func (c *collector) addAll(comps []Component, hp, source string) {
	for _, comp := range comps {
		comp.Paths = []string{hp}
		if comp.Source == "" {
			comp.Source = source
		}
		c.add(comp)
	}
}
