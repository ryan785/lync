package daemon

import (
	"strings"

	"github.com/ryan785/lync/internal/collector"
)

// Scope narrows what a scan looks at. An empty Scope means the full host.
type Scope struct {
	Packages   []string `json:"packages,omitempty"`
	Services   []string `json:"services,omitempty"`
	KernelOnly bool     `json:"kernel_only,omitempty"`
}

func (s Scope) IsAll() bool {
	return len(s.Packages) == 0 && len(s.Services) == 0 && !s.KernelOnly
}

// Describe returns a short human label for the scope, suitable for logs and
// status output. Example: "pkg=openssh,svc=sshd" or "kernel" or "all".
func (s Scope) Describe() string {
	if s.IsAll() {
		return "all"
	}
	var parts []string
	for _, p := range s.Packages {
		parts = append(parts, "pkg="+p)
	}
	for _, svc := range s.Services {
		parts = append(parts, "svc="+svc)
	}
	if s.KernelOnly {
		parts = append(parts, "kernel")
	}
	return strings.Join(parts, ",")
}

// Apply returns a copy of facts narrowed to the packages this scope selects.
// The host/OS/kernel/services metadata is preserved so reports still render
// header information.
func (s Scope) Apply(facts *collector.Facts) *collector.Facts {
	if s.IsAll() {
		return facts
	}
	keep := map[string]bool{}
	for _, p := range s.Packages {
		keep[p] = true
	}
	for _, query := range s.Services {
		for _, svc := range facts.Services {
			if matchService(svc.Name, query) && svc.Package != "" {
				keep[svc.Package] = true
			}
		}
	}
	if s.KernelOnly {
		keep["kernel"] = true
	}

	narrowed := *facts
	pkgs := make([]collector.Package, 0, len(facts.Packages))
	for _, p := range facts.Packages {
		if keep[p.Name] {
			pkgs = append(pkgs, p)
		}
	}
	narrowed.Packages = pkgs
	return &narrowed
}

// matchService accepts either the bare name ("sshd") or the full unit name
// ("sshd.service") and matches both.
func matchService(unitName, query string) bool {
	if unitName == query {
		return true
	}
	if !strings.HasSuffix(query, ".service") && unitName == query+".service" {
		return true
	}
	return false
}

// parseScope reads Scope from IPC Args. JSON decode produces float64/string/bool,
// so we type-assert defensively.
func parseScope(args map[string]any) Scope {
	var s Scope
	if v, ok := args["package"].(string); ok && v != "" {
		s.Packages = append(s.Packages, v)
	}
	if v, ok := args["service"].(string); ok && v != "" {
		s.Services = append(s.Services, v)
	}
	if v, ok := args["kernel"].(bool); ok {
		s.KernelOnly = v
	}
	return s
}
