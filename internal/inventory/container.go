package inventory

import (
	"encoding/json"
	"strings"
)

// containers records the image of every running docker/podman container
// (metadata only: `ps` + `inspect`, nothing is exec'd inside containers and
// image layers are not read).
func (c *collector) containers() {
	for _, engine := range []string{"docker", "podman"} {
		if !c.budgetLeft() {
			return
		}
		out, err := c.h.Run(c.ctx, engine, "ps", "-q", "--no-trunc")
		if err != nil {
			continue
		}
		ids := strings.Fields(out)
		if len(ids) == 0 {
			continue
		}
		if len(ids) > 500 {
			c.warn("limit", engine, "%d running containers; only the first 500 inspected", len(ids))
			ids = ids[:500]
		}
		cout, err := c.h.Run(c.ctx, engine, append([]string{"inspect"}, ids...)...)
		if err != nil && cout == "" {
			c.warn("error", engine, "inspect containers: %v", err)
			continue
		}
		var ctrs []struct {
			Name   string `json:"Name"`
			Image  string `json:"Image"` // image ID
			Config struct {
				Image string `json:"Image"` // reference the container was started from
			} `json:"Config"`
			ImageName string `json:"ImageName"` // podman
		}
		if json.Unmarshal([]byte(cout), &ctrs) != nil {
			c.warn("error", engine, "inspect containers: unparseable output")
			continue
		}
		byImage := map[string][]string{}
		refs := map[string]string{}
		var imageIDs []string
		for _, ct := range ctrs {
			if ct.Image == "" {
				continue
			}
			if _, ok := byImage[ct.Image]; !ok {
				imageIDs = append(imageIDs, ct.Image)
			}
			byImage[ct.Image] = append(byImage[ct.Image], engine+":"+strings.TrimPrefix(ct.Name, "/"))
			ref := ct.Config.Image
			if ref == "" {
				ref = ct.ImageName
			}
			refs[ct.Image] = ref
		}
		if len(imageIDs) == 0 {
			continue
		}
		iout, err := c.h.Run(c.ctx, engine, append([]string{"image", "inspect"}, imageIDs...)...)
		if err != nil && iout == "" {
			c.warn("error", engine, "inspect images: %v", err)
			continue
		}
		var imgs []struct {
			ID           string   `json:"Id"`
			RepoTags     []string `json:"RepoTags"`
			RepoDigests  []string `json:"RepoDigests"`
			Os           string   `json:"Os"`
			Architecture string   `json:"Architecture"`
			Created      string   `json:"Created"`
			Config       struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if json.Unmarshal([]byte(iout), &imgs) != nil {
			c.warn("error", engine, "inspect images: unparseable output")
			continue
		}
		for _, img := range imgs {
			id := img.ID
			if _, ok := byImage[id]; !ok && !strings.HasPrefix(id, "sha256:") {
				id = "sha256:" + id // podman reports bare hex IDs
			}
			paths := byImage[img.ID]
			if paths == nil {
				paths = byImage[id]
			}
			ref := refs[img.ID]
			if ref == "" {
				ref = refs[id]
			}
			if ref == "" && len(img.RepoTags) > 0 {
				ref = img.RepoTags[0]
			}
			name, tag := splitImageRef(ref)
			if name == "" {
				name = "<untagged>"
			}
			meta := map[string]string{"engine": engine, "image_id": img.ID, "os": img.Os, "arch": img.Architecture}
			if len(img.RepoDigests) > 0 {
				meta["digest"] = img.RepoDigests[0]
			}
			if img.Created != "" {
				meta["created"] = img.Created
			}
			for _, l := range []string{"org.opencontainers.image.version", "org.opencontainers.image.base.name", "org.opencontainers.image.source"} {
				if v := img.Config.Labels[l]; v != "" && len(v) < 256 {
					meta[strings.TrimPrefix(l, "org.opencontainers.image.")] = v
				}
			}
			if tag == "" {
				tag = shortID(img.ID)
			}
			c.add(Component{Ecosystem: EcoContainerImage, Name: name, Version: tag, Paths: paths,
				Source: SourceMetadata, Scope: ScopeContainer, Meta: meta})
		}
	}
}

// splitImageRef splits "registry:5000/ns/app:1.2@sha256:..." into
// ("registry:5000/ns/app", "1.2").
func splitImageRef(ref string) (name, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}
