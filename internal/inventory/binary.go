package inventory

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// minBinarySize skips small files: Go and Rust release binaries are
// megabytes, so this avoids opening scripts and data files.
const minBinarySize = 512 << 10

// osBinDirs hold distro-packaged executables (covered by the OS scan).
var osBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/lib", "/lib64"}

// maybeBinary reads Go build info or cargo-auditable data from an ELF
// executable found during the walk.
func (c *collector) maybeBinary(hp, local string, d fs.DirEntry) {
	if strings.Contains(d.Name(), ".") && !strings.HasSuffix(d.Name(), ".bin") {
		return // .so, .txt, .py...: binaries we care about have no extension
	}
	fi, err := d.Info()
	if err != nil || fi.Size() < minBinarySize {
		return
	}
	if fi.Mode().Perm()&0o111 == 0 && !isELF(local) {
		return
	}
	c.binary(hp, local)
}

func isELF(local string) bool {
	return bytes.Equal(readHead(local, 4), []byte("\x7fELF"))
}

// binary inventories one executable; it returns false when the file is not
// an ELF with Go or cargo-auditable metadata.
func (c *collector) binary(hp, local string) bool {
	if !isELF(local) {
		return false
	}
	c.stats.FilesParsed++
	if bi, err := buildinfo.ReadFile(local); err == nil {
		c.addGoBuildInfo(hp, bi)
		return true
	}
	if comps := cargoAuditable(local); len(comps) > 0 {
		for _, comp := range comps {
			comp.Paths = []string{hp}
			comp.Source = SourceBinary
			c.add(comp)
		}
		return true
	}
	return false
}

func (c *collector) addGoBuildInfo(hp string, bi *buildinfo.BuildInfo) {
	meta := map[string]string{"binary": hp}
	if v := strings.TrimPrefix(bi.GoVersion, "go"); v != "" && !strings.HasPrefix(bi.GoVersion, "devel") {
		// Strip experiment / toolchain suffixes: "1.22.1 X:boringcrypto".
		v = strings.Fields(v)[0]
		c.add(Component{Ecosystem: EcoGo, Name: "stdlib", Version: v, Paths: []string{hp}, Source: SourceBinary, Meta: meta})
	}
	if m := bi.Main; m.Path != "" && m.Version != "" && m.Version != "(devel)" {
		c.add(Component{Ecosystem: EcoGo, Name: m.Path, Version: goVersion(m.Version), Paths: []string{hp}, Source: SourceBinary, Meta: meta})
	}
	for _, dep := range bi.Deps {
		if dep.Replace != nil {
			dep = dep.Replace
		}
		if dep.Path == "" || dep.Version == "" || dep.Version == "(devel)" {
			continue
		}
		c.add(Component{Ecosystem: EcoGo, Name: dep.Path, Version: goVersion(dep.Version), Paths: []string{hp}, Source: SourceBinary, Meta: meta})
	}
}

// goVersion drops the leading "v" (OSV Go ranges are unprefixed).
func goVersion(v string) string { return strings.TrimPrefix(v, "v") }

// cargoAuditable reads the zlib-compressed JSON dependency list that
// cargo-auditable embeds in the ".dep-v0" section.
func cargoAuditable(local string) []Component {
	f, err := elf.Open(local)
	if err != nil {
		return nil
	}
	defer f.Close()
	sec := f.Section(".dep-v0")
	if sec == nil || sec.Size > 8<<20 {
		return nil
	}
	zr, err := zlib.NewReader(sec.Open())
	if err != nil {
		return nil
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, 32<<20))
	if err != nil {
		return nil
	}
	var deps struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Source  string `json:"source"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &deps) != nil {
		return nil
	}
	var out []Component
	for _, p := range deps.Packages {
		if p.Source == "crates.io" || p.Source == "registry" {
			out = append(out, Component{Ecosystem: EcoCrates, Name: p.Name, Version: p.Version})
		}
	}
	return out
}

// systemdUnitDirs hold service units whose ExecStart binaries are checked.
var systemdUnitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/usr/local/lib/systemd/system"}

// systemdBinaries checks every service ExecStart= executable outside the
// walked roots (inside them, the walk already saw it).
func (c *collector) systemdBinaries() {
	seen := map[string]bool{}
	for _, dir := range systemdUnitDirs {
		for _, unit := range c.h.Glob(dir + "/*.service") {
			if !c.budgetLeft() {
				return
			}
			for _, exe := range execStartPaths(readHead(c.local(unit), 256<<10)) {
				if seen[exe] {
					continue
				}
				seen[exe] = true
				if c.inRoots(exe) || (!c.opts.IncludeOSManaged && underAny(exe, osBinDirs)) || c.skipReason(path.Dir(exe)) != "" {
					continue
				}
				local := c.local(exe)
				fi, err := os.Stat(local)
				if err != nil || !fi.Mode().IsRegular() || fi.Size() < minBinarySize {
					continue
				}
				c.binary(exe, local)
			}
		}
	}
}

// execStartPaths returns the absolute executables named by ExecStart=
// lines (systemd prefixes "-@:+!" stripped).
func execStartPaths(unit []byte) []string {
	var out []string
	for _, line := range strings.Split(string(unit), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
		if len(f) == 0 {
			continue
		}
		exe := strings.TrimLeft(f[0], "-@:+!")
		if strings.HasPrefix(exe, "/") {
			out = append(out, path.Clean(exe))
		}
	}
	return out
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if hasPathPrefix(p, d) {
			return true
		}
	}
	return false
}

// inRoots reports whether the walk already covered p.
func (c *collector) inRoots(p string) bool {
	for _, r := range c.stats.Roots {
		if hasPathPrefix(p, r) {
			return true
		}
	}
	return false
}
