package rules

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "runtime:eol-node", Rule: "runtimes", Severity: finding.SeverityHigh,
			Description: "Running node process uses an end-of-life Node.js major (incl. nvm installs)"},
		// Emitted by internal/upstream (not by RuntimesRule); registered
		// here so `lync checks` lists them and rules.disable can turn
		// them off.
		CheckInfo{ID: "upstream:node-security-release", Rule: "runtimes", Severity: finding.SeverityHigh,
			Description: "Non-distro Node.js (nvm, fnm, volta, asdf, n, tarball, NodeSource, node: image) is older than a security release on its major line (nodejs.org/dist/index.json)"},
		CheckInfo{ID: "upstream:node-cve", Rule: "runtimes", Severity: finding.SeverityCritical,
			Description: "Non-distro Node.js is inside a vulnerable range of a Node.js core CVE (nodejs/security-wg vuln/core, CVSS from NVD)"},
		CheckInfo{ID: "runtime:eol-python", Rule: "runtimes", Severity: finding.SeverityMedium,
			Description: "Running python process uses an end-of-life CPython outside distro paths (pyenv, /usr/local, conda)"},
		CheckInfo{ID: "container:latest-tag", Rule: "runtimes", Severity: finding.SeverityLow,
			Description: "Container runs an image referenced by :latest (or no tag): unpinned, unknown patch level"},
		CheckInfo{ID: "container:image-age", Rule: "runtimes", Severity: finding.SeverityMedium,
			Description: "Running container image built longer ago than rules.image_max_age_days (default 365)"},
		CheckInfo{ID: "container:restart-loop", Rule: "runtimes", Severity: finding.SeverityLow,
			Description: "Container with restart policy always/unless-stopped that is exited or restarting repeatedly"},
		CheckInfo{ID: "container:eol-base", Rule: "runtimes", Severity: finding.SeverityMedium,
			Description: "Image tag names an EOL runtime (postgres<=13, node<=20, php<=8.1, python<=3.9, mysql 5.x, redis<=6)"},
		CheckInfo{ID: "container:php-upload-progress", Rule: "runtimes", Severity: finding.SeverityHigh, DefaultOff: true,
			Description: "PHP inside running containers has session.upload_progress.enabled on (docker exec; opt-in)"},
	)
}

// RuntimesRule covers language runtimes in use and container hygiene.
type RuntimesRule struct{}

func NewRuntimesRule() *RuntimesRule { return &RuntimesRule{} }

func (r *RuntimesRule) Name() string { return "runtimes" }

// eolMajors maps runtime -> major (or major.minor) -> upstream EOL date.
var eolMajors = map[string]map[string]string{
	"node": {"10": "2021-04-30", "12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11", "17": "2022-06-01",
		"18": "2025-04-30", "19": "2023-06-01", "20": "2026-04-30", "21": "2024-06-01", "22": "2027-04-30", "23": "2025-06-01", "24": "2028-04-30"},
	"python": {"2.7": "2020-01-01", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31",
		"3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31", "3.13": "2029-10-31"},
	"postgres": {"9": "2021-11-11", "10": "2022-11-10", "11": "2023-11-09", "12": "2024-11-21", "13": "2025-11-13", "14": "2026-11-12", "15": "2027-11-11"},
	"php":      {"5": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31"},
	"mysql":    {"5.6": "2021-02-01", "5.7": "2023-10-31", "8.0": "2026-04-30"},
	"redis":    {"5": "2022-04-27", "6": "2025-02-28"},
	"mariadb":  {"10.3": "2023-05-25", "10.4": "2024-06-18", "10.5": "2025-06-24"},
}

// eolOverride holds EOL tables loaded from upstream data at scan time
// (Node.js: nodejs/Release schedule.json, see internal/upstream). Its
// entries win over eolMajors; keys it lacks fall back to the built-in
// table, which is what an offline scan uses.
var (
	eolMu       sync.RWMutex
	eolOverride = map[string]map[string]string{}
)

// SetRuntimeEOL sets the EOL dates for runtime ("node") from upstream
// data: major or major.minor -> YYYY-MM-DD. An empty tbl restores the
// built-in table.
func SetRuntimeEOL(runtime string, tbl map[string]string) {
	eolMu.Lock()
	defer eolMu.Unlock()
	if len(tbl) == 0 {
		delete(eolOverride, runtime)
		return
	}
	cp := make(map[string]string, len(tbl))
	for k, v := range tbl {
		cp[k] = v
	}
	eolOverride[runtime] = cp
}

func eolDate(runtime, key string) (string, bool) {
	eolMu.RLock()
	d, ok := eolOverride[runtime][key]
	eolMu.RUnlock()
	if ok {
		return d, true
	}
	d, ok = eolMajors[runtime][key]
	return d, ok
}

// eolFor returns (eolDate, true) if version's major / major.minor is past EOL.
func eolFor(runtime, version string, now time.Time) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	keys := []string{parts[0]}
	if len(parts) > 1 {
		keys = append([]string{parts[0] + "." + parts[1]}, keys...)
	}
	for _, k := range keys {
		if d, ok := eolDate(runtime, k); ok {
			t, err := time.Parse("2006-01-02", d)
			return k, d, err == nil && now.After(t)
		}
	}
	return "", "", false
}

var (
	nvmVersionRE    = regexp.MustCompile(`/v(\d+\.\d+\.\d+)/bin/node$`)
	pythonVersionRE = regexp.MustCompile(`python(\d\.\d+)$`)
	versionOutRE    = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)
	tagVersionRE    = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)
)

func (r *RuntimesRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	var out []finding.Finding
	if opts.on("runtime:eol-node") || opts.on("runtime:eol-python") {
		out = append(out, eolRuntimes(ctx, h, opts)...)
	}
	if opts.on("container:latest-tag") || opts.on("container:image-age") || opts.on("container:restart-loop") ||
		opts.on("container:eol-base") || opts.on("container:php-upload-progress") {
		out = append(out, containerHygiene(ctx, h, opts)...)
	}
	return out
}

// ProcessExes returns exe path -> example pid for every process. Shared
// with the upstream runtime detection (internal/upstream).
func ProcessExes(h *Host) map[string]string {
	exes := map[string]string{}
	for _, d := range h.ReadDir("/proc") {
		pid := d.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		exe, err := h.Readlink("/proc/" + pid + "/exe")
		if err != nil || exe == "" {
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if _, ok := exes[exe]; !ok {
			exes[exe] = pid
		}
	}
	return exes
}

func eolRuntimes(ctx context.Context, h *Host, opts Options) []finding.Finding {
	var out []finding.Finding
	now := h.now()
	exes := ProcessExes(h)
	paths := make([]string, 0, len(exes))
	for p := range exes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, exe := range paths {
		base := path.Base(exe)
		switch {
		case base == "node" && opts.on("runtime:eol-node"):
			ver := ""
			if m := nvmVersionRE.FindStringSubmatch(exe); m != nil {
				ver = m[1]
			} else if o, err := h.Run(ctx, exe, "--version"); err == nil {
				if m := versionOutRE.FindStringSubmatch(o); m != nil {
					ver = m[1]
				}
			}
			if ver == "" {
				continue
			}
			if major, eol, past := eolFor("node", ver, now); past {
				sev := finding.SeverityHigh
				note := ""
				if strings.HasPrefix(exe, "/usr/bin/") {
					sev = finding.SeverityMedium
					note = " Distro nodejs module builds may get backports until the stream retires (dnf module list nodejs)."
				}
				out = append(out, mkFinding(h, "runtime:eol-node", exe, finding.CategoryEOL, sev,
					fmt.Sprintf("Running Node.js %s is end-of-life (major %s, EOL %s)", ver, major, eol),
					fmt.Sprintf("%s (pid %s, e.g.) is Node %s; upstream support for %s ended %s.%s", exe, exes[exe], ver, major, eol, note),
					"Upgrade to a supported LTS (nvm install --lts && nvm alias default lts/*; or dnf module switch-to nodejs:22) and restart the app (pm2 restart all)",
					"https://endoflife.date/nodejs"))
			}
		case strings.HasPrefix(base, "python") && opts.on("runtime:eol-python"):
			if strings.HasPrefix(exe, "/usr/bin/") || strings.HasPrefix(exe, "/usr/libexec/") {
				continue // distro python: supported for the distro's life
			}
			ver := ""
			if m := pythonVersionRE.FindStringSubmatch(base); m != nil {
				ver = m[1]
			} else if o, err := h.Run(ctx, exe, "--version"); err == nil {
				if m := versionOutRE.FindStringSubmatch(o); m != nil {
					ver = m[1]
				}
			}
			if ver == "" {
				continue
			}
			if mm, eol, past := eolFor("python", ver, now); past {
				out = append(out, mkFinding(h, "runtime:eol-python", exe, finding.CategoryEOL, finding.SeverityMedium,
					fmt.Sprintf("Running Python %s is end-of-life (EOL %s)", mm, eol),
					fmt.Sprintf("%s (pid %s) is a non-distro Python %s; upstream security support ended %s", exe, exes[exe], ver, eol),
					"Rebuild the virtualenv on a supported Python (3.11+) and restart the service",
					"https://endoflife.date/python"))
			}
		}
	}
	return out
}

type containerInfo struct {
	Name, Image, ImageID, Restart, Status string
	Restarts                              int
	Running                               bool
}

// imageTagEOL maps image repo basenames to the runtime key in eolMajors.
var imageTagEOL = map[string]string{"postgres": "postgres", "postgis": "postgres", "node": "node", "php": "php",
	"python": "python", "mysql": "mysql", "redis": "redis", "mariadb": "mariadb"}

func containerHygiene(ctx context.Context, h *Host, opts Options) []finding.Finding {
	ids, err := h.Run(ctx, "docker", "ps", "-aq")
	if err != nil && ids == "" {
		return nil
	}
	idList := strings.Fields(ids)
	if len(idList) == 0 {
		return nil
	}
	args := append([]string{"inspect", "--format",
		"{{.Name}}|{{.Config.Image}}|{{.Image}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Status}}|{{.RestartCount}}|{{.State.Running}}"}, idList...)
	insp, err := h.Run(ctx, "docker", args...)
	if err != nil && insp == "" {
		return nil
	}
	var cs []containerInfo
	imageIDs := map[string]bool{}
	for _, line := range strings.Split(insp, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 7 {
			continue
		}
		n, _ := strconv.Atoi(f[5])
		c := containerInfo{Name: strings.TrimPrefix(f[0], "/"), Image: f[1], ImageID: f[2], Restart: f[3], Status: f[4], Restarts: n, Running: f[6] == "true"}
		cs = append(cs, c)
		imageIDs[c.ImageID] = true
	}
	created := map[string]time.Time{}
	if opts.on("container:image-age") && len(imageIDs) > 0 {
		iargs := []string{"image", "inspect", "--format", "{{.Id}}|{{.Created}}"}
		for id := range imageIDs {
			iargs = append(iargs, id)
		}
		sort.Strings(iargs[4:])
		if o, err := h.Run(ctx, "docker", iargs...); err == nil || o != "" {
			for _, line := range strings.Split(o, "\n") {
				id, ts, ok := strings.Cut(strings.TrimSpace(line), "|")
				if !ok {
					continue
				}
				if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
					created[id] = t
				}
			}
		}
	}
	maxAge := opts.ImageMaxAgeDays
	if maxAge <= 0 {
		maxAge = 365
	}
	now := h.now()
	var out []finding.Finding
	for _, c := range cs {
		repo, tag := splitImageRef(c.Image)
		if c.Running && opts.on("container:latest-tag") && (tag == "latest" || tag == "") && !strings.Contains(c.Image, "@sha256:") {
			out = append(out, mkFinding(h, "container:latest-tag", c.Name, finding.CategoryRuntime, finding.SeverityLow,
				fmt.Sprintf("Container %s runs unpinned image %s", c.Name, c.Image),
				"image referenced by :latest/no tag: the running patch level is unknown and `docker compose pull` may jump major versions",
				"Pin a version tag (or digest) in the compose file, e.g. image: "+repo+":<version>, and update deliberately"))
		}
		if c.Running && opts.on("container:image-age") {
			if t, ok := created[c.ImageID]; ok && now.Sub(t) > time.Duration(maxAge)*24*time.Hour {
				out = append(out, mkFinding(h, "container:image-age", c.Name, finding.CategoryRuntime, finding.SeverityMedium,
					fmt.Sprintf("Container %s runs an image built %d days ago", c.Name, ageDays(now.Sub(t))),
					fmt.Sprintf("%s (%s) created %s: OS packages inside have not been updated since", c.Image, shortID(c.ImageID), t.Format("2006-01-02")),
					"docker compose pull && docker compose up -d (or rebuild the image) for "+c.Name))
			}
		}
		if opts.on("container:restart-loop") && (c.Restart == "always" || c.Restart == "unless-stopped") &&
			(c.Status == "restarting" || (c.Status == "exited" && c.Restarts > 0) || c.Restarts >= 10) {
			out = append(out, mkFinding(h, "container:restart-loop", c.Name, finding.CategoryRuntime, finding.SeverityLow,
				fmt.Sprintf("Container %s keeps restarting (policy %s, %d restarts, status %s)", c.Name, c.Restart, c.Restarts, c.Status),
				"a crash-looping or abandoned app that Docker keeps resurrecting on every boot (and may expose ports when it comes up)",
				fmt.Sprintf("docker logs --tail 50 %s; if unused: docker update --restart=no %s && docker stop %s (or remove it from the compose file)", c.Name, c.Name, c.Name)))
		}
		if c.Running && opts.on("container:eol-base") {
			if key, ok := imageTagEOL[path.Base(repo)]; ok && tag != "" && tag != "latest" {
				if m := tagVersionRE.FindStringSubmatch(tag); m != nil {
					v := m[1]
					if mm, eol, past := eolFor(key, v, now); past {
						out = append(out, mkFinding(h, "container:eol-base", c.Name, finding.CategoryEOL, finding.SeverityMedium,
							fmt.Sprintf("Container %s runs EOL %s %s", c.Name, key, mm),
							fmt.Sprintf("image %s: %s %s reached end-of-life %s; the image no longer receives security rebuilds", c.Image, key, mm, eol),
							"Plan a major-version upgrade (dump/restore for databases) and pin the new tag",
							"https://endoflife.date/"+key))
					}
				}
			}
		}
		if c.Running && opts.on("container:php-upload-progress") {
			if f, ok := containerPHP(ctx, h, c); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func splitImageRef(ref string) (repo, tag string) {
	ref = strings.SplitN(ref, "@", 2)[0]
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// containerPHP runs `php -r` inside a running container (opt-in: it execs
// into containers). A container without php just errors and is skipped.
func containerPHP(ctx context.Context, h *Host, c containerInfo) (finding.Finding, bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	o, err := h.Run(ctx, "docker", "exec", c.Name, "php", "-r",
		`echo PHP_VERSION, "|", var_export((bool)ini_get("session.upload_progress.enabled"), true);`)
	if err != nil && o == "" {
		return finding.Finding{}, false
	}
	ver, enabled, ok := strings.Cut(strings.TrimSpace(o), "|")
	if !ok || enabled != "true" {
		return finding.Finding{}, false
	}
	return mkFinding(h, "container:php-upload-progress", c.Name, finding.CategoryConfig, finding.SeverityHigh,
		fmt.Sprintf("PHP %s in container %s has session.upload_progress.enabled on", ver, c.Name),
		fmt.Sprintf("docker exec %s php -r ...: PHP_VERSION=%s, session.upload_progress.enabled=On (CVE-2026-109618 / CVE-2026-109619 exposure until the image ships fixed PHP)", c.Name, ver),
		"Add an ini override in the image or a mounted conf.d file (session.upload_progress.enabled = Off), recreate the container, and pull the vendor's patched image when available",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-109618", "https://nvd.nist.gov/vuln/detail/CVE-2026-109619"), true
}
