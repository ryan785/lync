package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/audit"
)

// apkInstalledDB is apk's package database. Its "o:" lines carry each
// package's origin (source package), which OSV keys Alpine advisories by.
var apkInstalledDB = "/lib/apk/db/installed"

// readApkPackages enumerates installed Alpine packages. `apk info -v` emits
// one "<name>-<version>-r<rel>" per line. Arch info is in apk's database; we
// don't fetch it per-package since Alpine is single-arch in practice.
func readApkPackages(ctx context.Context) ([]Package, error) {
	out, err := audit.Output(ctx, 2*time.Minute, "apk", "info", "-v")
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("apk info: %w", err)
	}
	pkgs, parseErr := parseApkInfoOutput(bytes.NewReader(out))
	if f, ferr := os.Open(apkInstalledDB); ferr == nil {
		origins := parseApkOrigins(f)
		f.Close()
		for i := range pkgs {
			if o := origins[pkgs[i].Name]; o != "" {
				pkgs[i].Source = o
			}
		}
	}
	if err != nil {
		return pkgs, fmt.Errorf("apk info: %w", err)
	}
	return pkgs, parseErr
}

// parseApkOrigins maps package name -> origin from apk's installed DB
// (stanzas of "P:<name>", "V:<version>", "o:<origin>", blank-line separated).
func parseApkOrigins(r io.Reader) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	name := ""
	for s.Scan() {
		line := s.Text()
		switch {
		case line == "":
			name = ""
		case strings.HasPrefix(line, "P:"):
			name = line[2:]
		case strings.HasPrefix(line, "o:") && name != "":
			out[name] = line[2:]
		}
	}
	return out
}

func parseApkInfoOutput(r interface{ Read(p []byte) (int, error) }) ([]Package, error) {
	var pkgs []Package
	var unparsed []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		name, version, ok := splitApkPackage(line)
		if !ok {
			unparsed = append(unparsed, line)
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    name,
			Version: version,
			Manager: "apk",
		})
	}
	// Surface parse failures so operators notice apk format drift rather
	// than silently lose packages from the matcher's view.
	if len(unparsed) > 0 {
		return pkgs, fmt.Errorf("apk: %d lines failed to parse (sample: %q)",
			len(unparsed), unparsed[0])
	}
	return pkgs, s.Err()
}

// splitApkPackage parses "openssl-3.1.4-r0" into ("openssl", "3.1.4-r0").
// Alpine versions always end with "-rN" so we find the second-to-last "-".
func splitApkPackage(s string) (name, version string, ok bool) {
	last := strings.LastIndex(s, "-r")
	if last <= 0 {
		return "", "", false
	}
	// Verify the part after -r is numeric (the rel digits).
	for _, c := range s[last+2:] {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	prev := strings.LastIndex(s[:last], "-")
	if prev <= 0 {
		return "", "", false
	}
	return s[:prev], s[prev+1:], true
}
