package collector

import (
	"fmt"
	"strings"
	"time"
)

type Facts struct {
	Hostname  string     `json:"hostname"`
	OS        OSInfo     `json:"os"`
	Kernel    KernelInfo `json:"kernel"`
	Packages  []Package  `json:"packages"`
	Services  []Service  `json:"services,omitempty"`
	Collected time.Time  `json:"collected"`
}

type Service struct {
	Name    string `json:"name"`
	Package string `json:"package,omitempty"`
}

type OSInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	VersionID  string   `json:"version_id"`
	IDLike     []string `json:"id_like,omitempty"`
	PrettyName string   `json:"pretty_name"`
	CPEName    string   `json:"cpe_name,omitempty"`
}

type KernelInfo struct {
	Release string `json:"release"`
	Version string `json:"version"`
	Machine string `json:"machine"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release,omitempty"`
	Epoch   int    `json:"epoch,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"`
	// SourceVersion is the source package version when it differs from
	// Version (dpkg binNMUs, packages versioned apart from their source).
	SourceVersion string `json:"source_version,omitempty"`
	Manager       string `json:"manager"`
}

func (p Package) NEVRA() string {
	epoch := ""
	if p.Epoch > 0 {
		epoch = fmt.Sprintf("%d:", p.Epoch)
	}
	rel := ""
	if p.Release != "" {
		rel = "-" + p.Release
	}
	arch := ""
	if p.Arch != "" {
		arch = "." + p.Arch
	}
	return fmt.Sprintf("%s-%s%s%s%s", p.Name, epoch, p.Version, rel, arch)
}

func (p Package) NEVR() string {
	epoch := ""
	if p.Epoch > 0 {
		epoch = fmt.Sprintf("%d:", p.Epoch)
	}
	rel := ""
	if p.Release != "" {
		rel = "-" + p.Release
	}
	return fmt.Sprintf("%s%s%s", epoch, p.Version, rel)
}

// SourceName returns the name of the source package this binary package was
// built from, or "" if unknown. RPM: "php-8.0.30-1.module+el8.10.0+1.src.rpm"
// -> "php" (the last two dash-separated fields are version and release).
// dpkg: ${source:Package} is already a bare name.
func (p Package) SourceName() string {
	src := p.Source
	if src == "" || src == "(none)" {
		return ""
	}
	if p.Manager == "rpm" || strings.HasSuffix(src, ".src.rpm") {
		base := strings.TrimSuffix(src, ".src.rpm")
		if base == src {
			return ""
		}
		rel := strings.LastIndex(base, "-")
		if rel <= 0 {
			return ""
		}
		ver := strings.LastIndex(base[:rel], "-")
		if ver <= 0 {
			return ""
		}
		return base[:ver]
	}
	if i := strings.IndexByte(src, ' '); i > 0 {
		src = src[:i]
	}
	return src
}
