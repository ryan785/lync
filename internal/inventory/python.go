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

// normalizePyPI applies PEP 503 name normalisation.
func normalizePyPI(name string) string {
	return strings.ToLower(pyNameSep.ReplaceAllString(strings.TrimSpace(name), "-"))
}

var pyNameSep = regexp.MustCompile(`[-_.]+`)

// ---- site-packages / dist-packages ----------------------------------------

// osInstallers are INSTALLER values written by distro package builds.
var osInstallers = map[string]bool{"rpm": true, "dpkg": true, "debian": true, "apk": true, "conda": false}

// sitePackages reads *.dist-info/METADATA and *.egg-info of one
// site-packages directory without descending into the modules themselves.
func (c *collector) sitePackages(hp, local string) {
	ents, err := os.ReadDir(local)
	if err != nil {
		return
	}
	skippedOS := 0
	for _, e := range ents {
		name := e.Name()
		var meta string
		switch {
		case strings.HasSuffix(name, ".dist-info") && e.IsDir():
			meta = filepath.Join(local, name, "METADATA")
		case strings.HasSuffix(name, ".egg-info") && e.IsDir():
			meta = filepath.Join(local, name, "PKG-INFO")
		case strings.HasSuffix(name, ".egg-info"):
			meta = filepath.Join(local, name)
		default:
			continue
		}
		c.stats.Entries++
		pkg, ver := readPyMetadata(meta)
		if pkg == "" || ver == "" {
			continue
		}
		installer := ""
		if e.IsDir() {
			installer = strings.ToLower(strings.TrimSpace(string(readHead(filepath.Join(local, name, "INSTALLER"), 64))))
		}
		if !c.opts.IncludeOSManaged && pyOSManaged(hp, installer) {
			skippedOS++
			continue
		}
		c.stats.FilesParsed++
		c.add(Component{Ecosystem: EcoPyPI, Name: normalizePyPI(pkg), Version: ver,
			Paths: []string{path.Join(hp, name)}, Source: SourceMetadata})
	}
	if skippedOS > 0 {
		c.warn("skip", hp, "%d distro-managed python packages (covered by the OS package scan)", skippedOS)
	}
}

// pyOSManaged: distro packages either say so in INSTALLER, or live under
// /usr/lib* with no INSTALLER (Debian dist-packages, RPM egg-info).
func pyOSManaged(hp, installer string) bool {
	if osInstallers[installer] {
		return true
	}
	if installer != "" {
		return false
	}
	return strings.HasPrefix(hp, "/usr/lib/") || strings.HasPrefix(hp, "/usr/lib64/") || strings.HasPrefix(hp, "/usr/share/")
}

// readPyMetadata reads Name and Version from the RFC 822 header block of
// METADATA / PKG-INFO.
func readPyMetadata(local string) (name, version string) {
	data := readHead(local, 64<<10)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "Name":
			name = strings.TrimSpace(v)
		case "Version":
			version = strings.TrimSpace(v)
		}
		if name != "" && version != "" {
			break
		}
	}
	return
}

// ---- requirements*.txt ------------------------------------------------------

func (c *collector) requirements(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	c.addAll(parseRequirements(data), hp, SourceManifest)
}

var reqPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$`)

// parseRequirements keeps exact pins only (name==1.2.3); ranges say nothing
// about what is installed.
func parseRequirements(data []byte) []Component {
	var out []Component
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, " --hash"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, `\`))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqPin.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Component{Ecosystem: EcoPyPI, Name: normalizePyPI(m[1]), Version: m[2]})
	}
	return out
}

// ---- poetry.lock --------------------------------------------------------------

func (c *collector) poetryLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	c.addAll(parsePoetryLock(data), hp, SourceLockfile)
}

// parsePoetryLock reads name/version/category/groups from [[package]]
// tables (enough TOML for lockfiles poetry writes).
func parsePoetryLock(data []byte) []Component {
	var out []Component
	for _, t := range tomlArrayTables(data, "package") {
		name, ver := t["name"], t["version"]
		if name == "" || ver == "" {
			continue
		}
		dev := t["category"] == "dev"
		if g := t["groups"]; g != "" && !strings.Contains(g, `"main"`) {
			dev = true
		}
		out = append(out, Component{Ecosystem: EcoPyPI, Name: normalizePyPI(name), Version: ver, Dev: dev})
	}
	return out
}

// tomlArrayTables returns the top-level string keys (raw for arrays) of each
// [[name]] table. Nested tables ([name.source], [name.dependencies]) end the
// key collection for that entry.
func tomlArrayTables(data []byte, name string) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	header := "[[" + name + "]]"
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			cur = nil
			if line == header {
				cur = map[string]string{}
				out = append(out, cur)
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			if s, err := unquoteTOML(v); err == nil {
				v = s
			}
		}
		cur[k] = v
	}
	return out
}

func unquoteTOML(v string) (string, error) {
	end := strings.Index(v[1:], `"`)
	if end < 0 {
		return v, nil
	}
	return v[1 : end+1], nil
}

// ---- Pipfile.lock ---------------------------------------------------------------

func (c *collector) pipfileLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	comps, err := parsePipfileLock(data)
	if err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	c.addAll(comps, hp, SourceLockfile)
}

func parsePipfileLock(data []byte) ([]Component, error) {
	var l map[string]json.RawMessage
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	var out []Component
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := l[section]; ok {
			_ = json.Unmarshal(raw, &deps)
		}
		for name, d := range deps {
			v := strings.TrimPrefix(d.Version, "==")
			if v == "" || v == d.Version {
				continue // not an exact pin (VCS/path dependency)
			}
			out = append(out, Component{Ecosystem: EcoPyPI, Name: normalizePyPI(name), Version: v, Dev: section == "develop"})
		}
	}
	return out, nil
}
