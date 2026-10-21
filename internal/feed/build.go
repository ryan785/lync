package feed

import "github.com/ryan785/lync/internal/config"

// Build constructs Source instances from config entries. Unknown source names
// are silently skipped; the daemon logs the active set after Build returns.
func Build(cfgs []config.FeedSourceCfg) []Source {
	var sources []Source
	for _, c := range cfgs {
		if !c.Enabled {
			continue
		}
		switch c.Name {
		case "nvd":
			sources = append(sources, NewNVD(c.APIKey))
		case "redhat":
			sources = append(sources, NewRedHat())
		case "debian":
			sources = append(sources, NewDebian())
		case "ubuntu":
			sources = append(sources, NewUbuntu())
		case "alpine":
			sources = append(sources, NewAlpine())
		case "osv":
			sources = append(sources, NewOSV())
		}
	}
	return sources
}

// AutoSourceNames picks the feeds that apply to a host: NVD and OSV
// everywhere, plus the distro's own feed. Debian's tracker JSON is large,
// so a Rocky host shouldn't download it (and vice versa).
func AutoSourceNames(osID string, idLike []string) []string {
	ids := map[string]bool{osID: true}
	for _, l := range idLike {
		ids[l] = true
	}
	var names []string
	switch {
	case ids["rhel"] || ids["centos"] || ids["fedora"] || ids["rocky"] || ids["almalinux"] || ids["ol"]:
		names = append(names, "redhat")
	case ids["ubuntu"]:
		names = append(names, "ubuntu")
	case ids["debian"]:
		names = append(names, "debian")
	case ids["alpine"]:
		names = append(names, "alpine")
	}
	return append(names, "osv", "nvd")
}
