package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// composerVersion strips the "v" composer keeps from git tags and drops
// branch versions (dev-main, 1.x-dev) that OSV cannot range-match.
func composerVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev") {
		return ""
	}
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

// ---- composer.lock ----------------------------------------------------------

func (c *collector) composerLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	comps, err := parseComposerLock(data)
	if err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	c.addAll(comps, hp, SourceLockfile)
}

func parseComposerLock(data []byte) ([]Component, error) {
	var l struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	var out []Component
	for i, list := range [][]composerPkg{l.Packages, l.PackagesDev} {
		for _, p := range list {
			if v := composerVersion(p.Version); p.Name != "" && v != "" {
				out = append(out, Component{Ecosystem: EcoPackagist, Name: strings.ToLower(p.Name), Version: v, Dev: i == 1})
			}
		}
	}
	return out, nil
}

// ---- vendor/composer/installed.json (composer 1 and 2) -------------------------

func (c *collector) composerInstalled(hp, local string) {
	// composer.lock beside vendor/ is the same data; prefer it.
	if fileExists(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(local))), "composer.lock")) {
		return
	}
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	comps, err := parseComposerInstalled(data)
	if err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	c.stats.FilesParsed++
	c.addAll(comps, hp, SourceMetadata)
}

func parseComposerInstalled(data []byte) ([]Component, error) {
	var pkgs []composerPkg
	dev := map[string]bool{}
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(data, &pkgs); err != nil {
			return nil, err
		}
	} else {
		var v2 struct {
			Packages         []composerPkg `json:"packages"`
			DevPackageNames  []string      `json:"dev-package-names"`
			DevMode          bool          `json:"dev"`
			DevPackageNames2 []string      `json:"devPackageNames"`
		}
		if err := json.Unmarshal(data, &v2); err != nil {
			return nil, err
		}
		pkgs = v2.Packages
		for _, n := range append(v2.DevPackageNames, v2.DevPackageNames2...) {
			dev[strings.ToLower(n)] = true
		}
	}
	var out []Component
	for _, p := range pkgs {
		name := strings.ToLower(p.Name)
		if v := composerVersion(p.Version); name != "" && v != "" {
			out = append(out, Component{Ecosystem: EcoPackagist, Name: name, Version: v, Dev: dev[name]})
		}
	}
	return out, nil
}

// ---- composer.json: applications identified by their root package -----------

// composerJSON identifies root applications whose own version OSV tracks
// (the root package never appears in its own composer.lock).
func (c *collector) composerJSON(hp, local string) {
	b := readHead(local, 256<<10)
	var root struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &root) != nil {
		return
	}
	switch strings.ToLower(root.Name) {
	case "pterodactyl/panel":
		dir := filepath.Dir(local)
		v := phpConfigVersion(filepath.Join(dir, "config", "app.php"))
		if v == "" || v == "canary" {
			return
		}
		c.add(Component{Ecosystem: EcoPackagist, Name: "pterodactyl/panel", Version: composerVersion(v),
			Paths: []string{path.Join(path.Dir(hp), "config/app.php")}, Source: SourceMetadata, Scope: ScopeApp,
			Meta: map[string]string{"app": "Pterodactyl Panel"}})
	}
}

var phpVersionKey = regexp.MustCompile(`['"]version['"]\s*=>\s*(?:env\(\s*['"][A-Z_]+['"]\s*,\s*)?['"]([^'"]+)['"]`)

// phpConfigVersion reads only the 'version' => '...' entry of a Laravel
// config file (no other values are read or kept).
func phpConfigVersion(local string) string {
	m := phpVersionKey.FindSubmatch(readHead(local, 64<<10))
	if m == nil {
		return ""
	}
	return string(m[1])
}

// ---- WordPress --------------------------------------------------------------

var wpVersionRE = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

// wordpress records core (wp-includes/version.php) and each plugin and
// theme version of the site rooted at hp. wp-config.php is never read.
func (c *collector) wordpress(hp, local string) {
	vp := filepath.Join(local, "wp-includes", "version.php")
	m := wpVersionRE.FindSubmatch(readHead(vp, 64<<10))
	c.stats.FilesParsed++
	if m != nil {
		c.add(Component{Ecosystem: EcoWordPress, Name: "wordpress", Version: string(m[1]),
			Paths: []string{hp + "/wp-includes/version.php"}, Source: SourceMetadata, Scope: ScopeApp})
	}
	content := filepath.Join(local, "wp-content")
	for _, kind := range []string{"plugins", "themes"} {
		ents, err := os.ReadDir(filepath.Join(content, kind))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dir := filepath.Join(content, kind, e.Name())
			hdir := hp + "/wp-content/" + kind + "/" + e.Name()
			var ver, file string
			if kind == "themes" {
				ver = wpHeader(filepath.Join(dir, "style.css"), "Theme Name", "Version")
				file = "style.css"
			} else {
				ver, file = wpPluginVersion(dir)
			}
			if ver == "" {
				continue
			}
			eco := EcoWordPressPlugin
			if kind == "themes" {
				eco = EcoWordPressTheme
			}
			c.add(Component{Ecosystem: eco, Name: e.Name(), Version: ver,
				Paths: []string{hdir + "/" + file}, Source: SourceMetadata, Scope: ScopeApp})
		}
	}
}

// wpPluginVersion finds the main plugin file (the top-level .php with a
// "Plugin Name:" header) and returns its Version; readme.txt "Stable tag"
// is the fallback.
func wpPluginVersion(dir string) (version, file string) {
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".php") {
			continue
		}
		if n++; n > 50 {
			break
		}
		if v := wpHeader(filepath.Join(dir, e.Name()), "Plugin Name", "Version"); v != "" {
			return v, e.Name()
		}
	}
	if v := wpHeader(filepath.Join(dir, "readme.txt"), "", "Stable tag"); v != "" && v != "trunk" {
		return v, "readme.txt"
	}
	return "", ""
}

// wpHeader reads the WordPress file header (first 8 KiB, as WordPress
// itself does). When marker is set the file must contain it.
func wpHeader(local, marker, key string) string {
	data := readHead(local, 8<<10)
	if data == nil || (marker != "" && !bytes.Contains(data, []byte(marker+":"))) {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " \t/*#@")
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), key) {
			v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "*/"))
			if v != "" && v[0] >= '0' && v[0] <= '9' {
				return v
			}
			return ""
		}
	}
	return ""
}
