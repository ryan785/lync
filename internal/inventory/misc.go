package inventory

import (
	"encoding/json"
	"os"
	"path"
	"strings"
)

// ---- Cargo.lock -------------------------------------------------------------

func (c *collector) cargoLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	c.addAll(parseCargoLock(data), hp, SourceLockfile)
}

// parseCargoLock keeps registry crates; path and git dependencies are the
// project's own code.
func parseCargoLock(data []byte) []Component {
	var out []Component
	for _, t := range tomlArrayTables(data, "package") {
		if t["name"] == "" || t["version"] == "" || !strings.HasPrefix(t["source"], "registry+") {
			continue
		}
		out = append(out, Component{Ecosystem: EcoCrates, Name: t["name"], Version: t["version"]})
	}
	return out
}

// ---- Gemfile.lock -----------------------------------------------------------

func (c *collector) gemfileLock(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	c.addAll(parseGemfileLock(data), hp, SourceLockfile)
}

// parseGemfileLock reads the "specs:" of GEM sections; four-space entries
// are resolved gems ("    rack (2.2.3)"), deeper ones are their deps.
func parseGemfileLock(data []byte) []Component {
	var out []Component
	inGem, inSpecs := false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inGem = line == "GEM"
			inSpecs = false
			continue
		}
		if !inGem {
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(line), " (")
		if !ok {
			continue
		}
		ver := gemVersion(strings.TrimSuffix(rest, ")"))
		if name != "" && ver != "" {
			out = append(out, Component{Ecosystem: EcoRubyGems, Name: name, Version: ver})
		}
	}
	return out
}

// gemVersion strips a platform suffix: "1.15.4-x86_64-linux" -> "1.15.4".
func gemVersion(v string) string {
	if i := strings.Index(v, "-"); i > 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// gemSpecs reads installed gems from a specifications/ directory's file
// names (name-version.gemspec); the gemspec bodies are Ruby and not parsed.
func (c *collector) gemSpecs(hp, local string) {
	if !c.opts.IncludeOSManaged && strings.HasPrefix(hp, "/usr/share/") {
		return
	}
	ents, err := os.ReadDir(local)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), ".gemspec")
		if n == e.Name() {
			continue
		}
		c.stats.Entries++
		name, ver := splitNameVersion(n)
		if name == "" {
			continue
		}
		c.add(Component{Ecosystem: EcoRubyGems, Name: name, Version: gemVersion(ver),
			Paths: []string{path.Join(hp, e.Name())}, Source: SourceMetadata})
	}
}

// splitNameVersion splits "name-with-dashes-1.2.3" at the last dash that
// is followed by a digit.
func splitNameVersion(s string) (string, string) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			// keep going left while the remainder still looks like a
			// platform suffix ("nokogiri-1.15.4-x86_64-linux")
			name, ver := s[:i], s[i+1:]
			if j := strings.LastIndex(name, "-"); j > 0 && j+1 < len(name) && name[j+1] >= '0' && name[j+1] <= '9' {
				continue
			}
			return name, ver
		}
	}
	return "", ""
}

// ---- .NET *.deps.json -------------------------------------------------------

func (c *collector) depsJSON(hp, local string) {
	data, ok := c.read(hp, local)
	if !ok {
		return
	}
	var d struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		c.warn("error", hp, "parse: %v", err)
		return
	}
	for key, lib := range d.Libraries {
		if lib.Type != "package" {
			continue // "project" / "reference": the app's own assemblies
		}
		name, ver, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		c.add(Component{Ecosystem: EcoNuGet, Name: name, Version: ver, Paths: []string{hp}, Source: SourceLockfile})
	}
}
