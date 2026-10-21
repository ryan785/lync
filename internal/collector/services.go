package collector

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"strings"
	"time"
)

// readServices enumerates running systemd services and resolves each unit
// file back to its owning RPM. Best-effort: a missing systemctl or rpm
// just degrades to an empty list rather than failing the scan.
func readServices(ctx context.Context) ([]Service, error) {
	names, err := runningServiceNames(ctx)
	if err != nil || len(names) == 0 {
		return nil, err
	}

	unitPaths := serviceUnitPaths(ctx, names)

	pkgByPath := map[string]string{}
	var paths []string
	for _, p := range unitPaths {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) > 0 {
		pkgByPath = rpmOwners(ctx, paths)
	}

	services := make([]Service, 0, len(names))
	for i, n := range names {
		s := Service{Name: n}
		if i < len(unitPaths) {
			s.Package = pkgByPath[unitPaths[i]]
		}
		services = append(services, s)
	}
	return services, nil
}

func runningServiceNames(ctx context.Context) ([]string, error) {
	out, err := audit.Output(ctx, time.Minute, "systemctl",
		"list-units", "--type=service", "--state=running",
		"--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		names = append(names, f[0])
	}
	return names, nil
}

// serviceUnitPaths returns FragmentPath for each name in the same order.
// Pairs by Names= rather than by block ordering, which gracefully handles
// unit aliases, slot units, and missing blocks without silently
// associating a path with the wrong service.
func serviceUnitPaths(ctx context.Context, names []string) []string {
	paths := make([]string, len(names))
	args := append([]string{"show", "--no-pager", "-p", "Names", "-p", "FragmentPath", "--"}, names...)
	out, err := audit.Output(ctx, time.Minute, "systemctl", args...)
	if err != nil {
		return paths
	}
	// Build a map of unit-name -> FragmentPath from the output. Each block
	// looks like:
	//   Names=sshd.service
	//   FragmentPath=/usr/lib/systemd/system/sshd.service
	pathByName := map[string]string{}
	var curNames []string
	var curPath string
	flush := func() {
		for _, n := range curNames {
			if curPath != "" {
				pathByName[n] = curPath
			}
		}
		curNames, curPath = nil, ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			flush()
			continue
		}
		if v, ok := strings.CutPrefix(line, "Names="); ok {
			curNames = strings.Fields(v)
		} else if v, ok := strings.CutPrefix(line, "FragmentPath="); ok {
			curPath = strings.TrimSpace(v)
		}
	}
	flush()
	for i, name := range names {
		paths[i] = pathByName[name]
	}
	return paths
}

// rpmOwners maps each unit path to its owning RPM name. Paths not owned by
// any package are omitted from the map. Queried one path at a time because
// rpm -qf splits its output across stdout/stderr for found/not-found cases,
// which breaks input-order pairing in batch mode.
func rpmOwners(ctx context.Context, paths []string) map[string]string {
	owners := map[string]string{}
	for _, p := range paths {
		out, err := audit.Output(ctx, 30*time.Second, "rpm", "-qf", "--qf", "%{NAME}", p)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(out))
		if name != "" && !strings.Contains(name, "not owned") {
			owners[p] = name
		}
	}
	return owners
}
