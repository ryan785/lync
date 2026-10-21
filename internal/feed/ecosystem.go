package feed

import (
	"strings"

	"github.com/ryan785/lync/internal/collector"
)

// HostEcosystem says how one host maps onto OSV.dev data.
type HostEcosystem struct {
	// Name is the human label ("Debian:12").
	Name string
	// Query lists the ecosystem strings sent to the OSV query API. RHEL
	// splits its packages across repository ecosystems.
	Query []string
	// Bulk is the bucket name of the all.zip export (full mode).
	Bulk string
	// Distro is the matcher filter stamped on converted entries.
	Distro string
	// Manager is the host package manager: rpm, dpkg or apk.
	Manager string
	// PerCVE lists templates for distro records keyed by CVE id
	// ("DEBIAN-%s"), fetched directly by `lync cve`.
	PerCVE []string
	// AdvisoryPrefixes are distro advisory id prefixes ("RLSA-") followed
	// from a CVE record's related[] list by `lync cve`.
	AdvisoryPrefixes []string

	accept []string // record ecosystems accepted: exact, or prefix if ending in ":"
}

// Accept reports whether an affected[] entry's ecosystem belongs to this
// host. Ubuntu's ":LTS" suffix is optional on either side; Ubuntu Pro and
// FIPS streams ("Ubuntu:Pro:22.04:LTS") are not accepted.
func (e HostEcosystem) Accept(eco string) bool {
	eco = strings.TrimSuffix(eco, ":LTS")
	for _, a := range e.accept {
		a = strings.TrimSuffix(a, ":LTS")
		if eco == a || (strings.HasSuffix(a, ":") && strings.HasPrefix(eco, a)) {
			return true
		}
	}
	return false
}

func majorOf(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

// EcosystemForOS maps os-release data to OSV ecosystems. ok=false means
// OSV has no data for this distro (Fedora, Oracle Linux, CentOS Stream,
// SUSE in lookup mode): the report then says the CVE section is
// incomplete instead of claiming the host is clean.
func EcosystemForOS(os collector.OSInfo) (HostEcosystem, bool) {
	major := majorOf(os.VersionID)
	if os.VersionID == "" {
		return HostEcosystem{}, false
	}
	switch os.ID {
	case "rocky":
		e := "Rocky Linux:" + major
		return HostEcosystem{Name: e, Query: []string{e}, Bulk: e, Distro: "rhel:" + major, Manager: "rpm",
			AdvisoryPrefixes: []string{"RLSA-"}, accept: []string{e}}, true
	case "almalinux":
		e := "AlmaLinux:" + major
		return HostEcosystem{Name: e, Query: []string{e}, Bulk: e, Distro: "rhel:" + major, Manager: "rpm",
			AdvisoryPrefixes: []string{"ALSA-"}, accept: []string{e}}, true
	case "rhel":
		p := "Red Hat:enterprise_linux:" + major + "::"
		return HostEcosystem{Name: "Red Hat:" + major, Query: []string{p + "baseos", p + "appstream"}, Bulk: "Red Hat",
			Distro: "rhel:" + major, Manager: "rpm", AdvisoryPrefixes: []string{"RHSA-", "RHBA-", "RHEA-"},
			accept: []string{p}}, true
	case "debian":
		e := "Debian:" + major
		return HostEcosystem{Name: e, Query: []string{e}, Bulk: e, Distro: "debian:" + major, Manager: "dpkg",
			PerCVE: []string{"DEBIAN-%s"}, AdvisoryPrefixes: []string{"DSA-", "DLA-"}, accept: []string{e}}, true
	case "ubuntu":
		e := "Ubuntu:" + os.VersionID
		if strings.Contains(os.Version, "LTS") {
			e += ":LTS"
		}
		return HostEcosystem{Name: e, Query: []string{e}, Bulk: e, Distro: "ubuntu:" + os.VersionID, Manager: "dpkg",
			PerCVE: []string{"UBUNTU-%s"}, AdvisoryPrefixes: []string{"USN-"}, accept: []string{e}}, true
	case "alpine":
		parts := strings.SplitN(os.VersionID, ".", 3)
		mm := parts[0]
		if len(parts) > 1 {
			mm += "." + parts[1]
		}
		e := "Alpine:v" + mm
		return HostEcosystem{Name: e, Query: []string{e}, Bulk: e, Distro: "alpine:" + mm, Manager: "apk",
			PerCVE: []string{"ALPINE-%s"}, accept: []string{e}}, true
	}
	return HostEcosystem{}, false
}

// QueryName and QueryVersion: OSV keys Debian, Ubuntu and Alpine records
// by source package; Rocky by source RPM name, Alma and RHEL by binary
// name. RPM versions carry the epoch when it is non-zero ("1:3.0.7-28.el9").
func osvQueries(p collector.Package) (names []string, version string) {
	switch p.Manager {
	case "rpm":
		version = p.NEVR()
		names = append(names, p.Name)
		if src := p.SourceName(); src != "" && src != p.Name {
			names = append(names, src)
		}
	case "dpkg":
		version = p.Version
		if p.SourceVersion != "" {
			version = p.SourceVersion
		}
		name := p.SourceName()
		if name == "" {
			name, _, _ = strings.Cut(p.Name, ":")
		}
		names = append(names, name)
	default:
		version = p.Version
		name := p.SourceName()
		if name == "" {
			name = p.Name
		}
		names = append(names, name)
	}
	return names, version
}
