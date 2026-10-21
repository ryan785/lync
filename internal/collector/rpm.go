package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"strconv"
	"strings"
	"time"
)

const rpmQF = `%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SOURCERPM}\n`

func readRPMPackages(ctx context.Context) ([]Package, error) {
	out, runErr := audit.Output(ctx, 5*time.Minute, "rpm", "-qa", "--qf", rpmQF)
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("rpm -qa: %w", runErr)
	}

	var pkgs []Package
	s := bufio.NewScanner(bytes.NewReader(out))
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		parts := strings.Split(s.Text(), "|")
		if len(parts) < 6 {
			continue
		}
		epoch := 0
		if parts[1] != "" && parts[1] != "(none)" {
			if v, err := strconv.Atoi(parts[1]); err == nil {
				epoch = v
			}
		}
		pkgs = append(pkgs, Package{
			Name:    parts[0],
			Epoch:   epoch,
			Version: parts[2],
			Release: parts[3],
			Arch:    parts[4],
			Source:  parts[5],
			Manager: "rpm",
		})
	}
	if runErr != nil {
		return pkgs, fmt.Errorf("rpm -qa: %w", runErr)
	}
	return pkgs, s.Err()
}
