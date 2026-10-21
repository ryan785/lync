package collector

import (
	"bufio"
	"os"
	"strings"
)

func readOSRelease(path string) (OSInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return OSInfo{}, err
	}
	defer f.Close()

	info := OSInfo{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			info.ID = v
		case "NAME":
			info.Name = v
		case "VERSION":
			info.Version = v
		case "VERSION_ID":
			info.VersionID = v
		case "PRETTY_NAME":
			info.PrettyName = v
		case "CPE_NAME":
			info.CPEName = v
		case "ID_LIKE":
			info.IDLike = strings.Fields(v)
		}
	}
	return info, s.Err()
}

// ReadOSRelease reads /etc/os-release (zero value if unreadable).
func ReadOSRelease() OSInfo {
	info, _ := readOSRelease("/etc/os-release")
	return info
}

// ReadOSReleaseFile reads an os-release file at path (zero value if
// unreadable).
func ReadOSReleaseFile(path string) OSInfo {
	info, _ := readOSRelease(path)
	return info
}
