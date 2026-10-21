package collector

import (
	"context"
	"log/slog"
	"os"
	"time"
)

func Collect(ctx context.Context, log *slog.Logger) (*Facts, error) {
	hostname, _ := os.Hostname()
	f := &Facts{
		Hostname:  hostname,
		Collected: time.Now(),
	}

	if osi, err := readOSRelease("/etc/os-release"); err != nil {
		log.Warn("os-release read failed", "err", err)
	} else {
		f.OS = osi
	}

	if k, err := readKernel(); err != nil {
		log.Warn("kernel read failed", "err", err)
	} else {
		f.Kernel = k
	}

	pkgs, err := readPackages(ctx, f.OS, log)
	if err != nil {
		log.Warn("package collection failed", "err", err)
	}
	f.Packages = pkgs

	if svcs, err := readServices(ctx); err != nil {
		log.Warn("services collection failed", "err", err)
	} else {
		f.Services = svcs
	}

	log.Info("facts collected",
		"hostname", f.Hostname,
		"os", f.OS.PrettyName,
		"kernel", f.Kernel.Release,
		"packages", len(f.Packages),
		"services", len(f.Services))
	return f, nil
}

// readPackages dispatches to the right package collector based on the host
// OS. Returns an empty slice + nil error on unsupported distros — the matcher
// just won't find anything to match against.
func readPackages(ctx context.Context, osInfo OSInfo, log *slog.Logger) ([]Package, error) {
	switch detectPackageManager(osInfo) {
	case "rpm":
		return readRPMPackages(ctx)
	case "dpkg":
		return readDpkgPackages(ctx)
	case "apk":
		return readApkPackages(ctx)
	}
	log.Warn("no package manager detected for this OS", "id", osInfo.ID, "id_like", osInfo.IDLike)
	return nil, nil
}

func detectPackageManager(osInfo OSInfo) string {
	rpmDistros := map[string]bool{
		"rhel": true, "centos": true, "fedora": true, "rocky": true,
		"almalinux": true, "ol": true, "amzn": true, "opensuse": true,
		"opensuse-leap": true, "opensuse-tumbleweed": true, "sles": true, "suse": true,
	}
	dpkgDistros := map[string]bool{
		"debian": true, "ubuntu": true, "linuxmint": true, "pop": true,
		"raspbian": true, "kali": true,
	}
	apkDistros := map[string]bool{
		"alpine": true, "postmarketos": true,
	}
	if rpmDistros[osInfo.ID] {
		return "rpm"
	}
	if dpkgDistros[osInfo.ID] {
		return "dpkg"
	}
	if apkDistros[osInfo.ID] {
		return "apk"
	}
	for _, like := range osInfo.IDLike {
		switch {
		case rpmDistros[like]:
			return "rpm"
		case dpkgDistros[like]:
			return "dpkg"
		case apkDistros[like]:
			return "apk"
		}
	}
	return ""
}
