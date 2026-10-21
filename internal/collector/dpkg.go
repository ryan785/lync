package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"strings"
	"time"
)

// dpkg-query format: NAME|VERSION|ARCHITECTURE|SOURCE|STATUS
// Status filter "install ok installed" excludes half-installed/half-removed.
const dpkgQF = `${binary:Package}|${Version}|${Architecture}|${source:Package}|${db:Status-Status}\n`

// readDpkgPackages enumerates installed Debian packages via dpkg-query.
// dpkg versions are "[epoch:]upstream[-debian]" — we keep the whole thing in
// Version and leave Release/Epoch empty; the matcher's RPM-flavored NEVR
// comparator handles dpkg version strings adequately for "is installed
// version < fixed version" checks.
func readDpkgPackages(ctx context.Context) ([]Package, error) {
	out, err := audit.Output(ctx, 5*time.Minute, "dpkg-query", "-W", "-f", dpkgQF)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	pkgs, parseErr := parseDpkgQueryOutput(bytes.NewReader(out))
	if err != nil {
		return pkgs, fmt.Errorf("dpkg-query: %w", err)
	}
	return pkgs, parseErr
}

func parseDpkgQueryOutput(r interface{ Read(p []byte) (int, error) }) ([]Package, error) {
	var pkgs []Package
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		parts := strings.Split(s.Text(), "|")
		if len(parts) < 5 {
			continue
		}
		if parts[4] != "installed" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    parts[0],
			Version: parts[1],
			Arch:    parts[2],
			Source:  parts[3],
			Manager: "dpkg",
		})
	}
	return pkgs, s.Err()
}
