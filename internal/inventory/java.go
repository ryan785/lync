package inventory

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// knownMavenGroups maps artifact IDs to group IDs for jars that carry no
// pom.properties (stripped or hand-built), so the components that matter
// most (log4j, spring, jackson...) are still identified from the file name
// or manifest.
var knownMavenGroups = map[string]string{
	"log4j-core": "org.apache.logging.log4j", "log4j-api": "org.apache.logging.log4j",
	"log4j-1.2-api": "org.apache.logging.log4j", "log4j": "log4j",
	"spring-core": "org.springframework", "spring-beans": "org.springframework",
	"spring-context": "org.springframework", "spring-web": "org.springframework",
	"spring-webmvc": "org.springframework", "spring-webflux": "org.springframework",
	"spring-expression": "org.springframework", "spring-boot": "org.springframework.boot",
	"spring-boot-autoconfigure": "org.springframework.boot", "spring-security-core": "org.springframework.security",
	"spring-security-web": "org.springframework.security",
	"jackson-databind":    "com.fasterxml.jackson.core", "jackson-core": "com.fasterxml.jackson.core",
	"jackson-annotations": "com.fasterxml.jackson.core",
	"commons-text":        "org.apache.commons", "commons-collections4": "org.apache.commons",
	"commons-compress": "org.apache.commons", "commons-collections": "commons-collections",
	"commons-io": "commons-io", "commons-fileupload": "commons-fileupload",
	"commons-beanutils": "commons-beanutils",
	"struts2-core":      "org.apache.struts", "snakeyaml": "org.yaml", "h2": "com.h2database",
	"tomcat-embed-core": "org.apache.tomcat.embed", "xstream": "com.thoughtworks.xstream",
	"guava": "com.google.guava", "logback-classic": "ch.qos.logback", "logback-core": "ch.qos.logback",
	"postgresql": "org.postgresql", "mysql-connector-java": "mysql", "shiro-core": "org.apache.shiro",
	"fastjson": "com.alibaba", "netty-codec-http": "io.netty", "netty-handler": "io.netty",
	"netty-codec-http2": "io.netty", "netty-common": "io.netty", "netty-all": "io.netty",
	"httpclient": "org.apache.httpcomponents", "bcprov-jdk15on": "org.bouncycastle",
	"bcprov-jdk18on": "org.bouncycastle", "protobuf-java": "com.google.protobuf",
	"jetty-server": "org.eclipse.jetty", "jetty-http": "org.eclipse.jetty",
	"activemq-client": "org.apache.activemq", "zookeeper": "org.apache.zookeeper",
}

var jarNameRE = regexp.MustCompile(`^(.+?)-(\d[0-9A-Za-z.+_-]*)\.(?:jar|war|ear)$`)

const maxArchiveEntries = 100000

// archive inventories one .jar/.war/.ear on disk.
func (c *collector) archive(hp, local string) {
	fi, err := os.Stat(local)
	if err != nil {
		return
	}
	if fi.Size() > c.opts.MaxArchive {
		c.warn("skip", hp, "archive larger than %d bytes", c.opts.MaxArchive)
		return
	}
	f, err := os.Open(local)
	if err != nil {
		c.warn("error", hp, "open: %v", err)
		return
	}
	defer f.Close()
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return // not a zip (or truncated); nothing to report
	}
	for _, comp := range c.scanZip(zr, hp, path.Base(hp), 0) {
		c.add(comp)
	}
}

// scanZip returns Maven components from one archive and its nested jars.
// Component paths are "outer.jar!inner/lib.jar" style.
func (c *collector) scanZip(zr *zip.Reader, display, base string, depth int) []Component {
	var out []Component
	if len(zr.File) > maxArchiveEntries {
		c.warn("limit", display, "archive has %d entries; only the first %d read", len(zr.File), maxArchiveEntries)
	}
	foundPom := false
	var manifest map[string]string
	nested := 0
	for i, f := range zr.File {
		if i >= maxArchiveEntries || !c.budgetLeft() {
			break
		}
		name := f.Name
		switch {
		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties"):
			props := readZipProps(f, 64<<10)
			g, a, v := props["groupId"], props["artifactId"], props["version"]
			if g == "" || a == "" || v == "" || strings.Contains(v, "${") {
				continue
			}
			foundPom = true
			out = append(out, Component{Ecosystem: EcoMaven, Name: g + ":" + a, Version: v,
				Paths: []string{display}, Source: SourceManifest})
		case name == "META-INF/MANIFEST.MF":
			manifest = readZipProps(f, 64<<10)
		case isArchiveName(name) && depth < c.opts.NestedDepth:
			if f.UncompressedSize64 > uint64(c.opts.MaxNested) {
				c.warn("skip", display+"!"+name, "nested archive larger than %d bytes", c.opts.MaxNested)
				continue
			}
			if nested++; nested > 2000 {
				continue
			}
			data, err := readZipEntry(f, c.opts.MaxNested)
			if err != nil {
				continue
			}
			inner, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				continue
			}
			out = append(out, c.scanZip(inner, display+"!"+name, path.Base(name), depth+1)...)
		}
	}
	if !foundPom {
		if comp, ok := jarFallback(base, manifest); ok {
			comp.Paths = []string{display}
			out = append(out, comp)
		}
	}
	return out
}

// pomProperties reads a loose META-INF/maven/<g>/<a>/pom.properties (an
// exploded archive, e.g. an unpacked webapp).
func (c *collector) pomProperties(hp, local string) {
	props := parseProps(readHead(local, 64<<10))
	g, a, v := props["groupId"], props["artifactId"], props["version"]
	if g == "" || a == "" || v == "" || strings.Contains(v, "${") {
		return
	}
	c.add(Component{Ecosystem: EcoMaven, Name: g + ":" + a, Version: v, Paths: []string{hp}, Source: SourceManifest})
}

func isArchiveName(n string) bool {
	l := strings.ToLower(n)
	return strings.HasSuffix(l, ".jar") || strings.HasSuffix(l, ".war") || strings.HasSuffix(l, ".ear")
}

// jarFallback identifies a jar without pom.properties from its file name
// and MANIFEST.MF. Unknown groups yield a name without "group:" which is
// inventoried but not queryable.
func jarFallback(base string, mf map[string]string) (Component, bool) {
	artifact, version := "", ""
	if m := jarNameRE.FindStringSubmatch(base); m != nil {
		artifact, version = m[1], m[2]
	}
	if v := mf["Implementation-Version"]; v != "" && !strings.Contains(v, "${") {
		version = v
	} else if v := mf["Bundle-Version"]; v != "" && version == "" {
		version = v
	}
	if artifact == "" {
		artifact = strings.TrimSuffix(strings.TrimSuffix(base, ".jar"), ".war")
	}
	if version == "" || artifact == "" {
		return Component{}, false
	}
	group := knownMavenGroups[artifact]
	if group == "" {
		group = mf["Implementation-Vendor-Id"]
	}
	name := artifact
	if group != "" {
		name = group + ":" + artifact
	}
	return Component{Ecosystem: EcoMaven, Name: name, Version: version, Source: SourceManifest}, true
}

func readZipEntry(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

// readZipProps parses key=value (pom.properties) or "Key: value"
// (MANIFEST.MF, continuation lines joined).
func readZipProps(f *zip.File, max int64) map[string]string {
	data, err := readZipEntry(f, max)
	if err != nil {
		return nil
	}
	return parseProps(data)
}

func parseProps(data []byte) map[string]string {
	out := map[string]string{}
	var last string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, " ") && last != "" { // manifest continuation
			out[last] += strings.TrimPrefix(line, " ")
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i <= 0 {
			continue
		}
		last = strings.TrimSpace(line[:i])
		out[last] = strings.TrimSpace(line[i+1:])
	}
	return out
}
