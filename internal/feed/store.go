package feed

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"os"
	"path/filepath"
	"time"
)

type Store struct {
	Dir string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

type Manifest struct {
	Source     string    `json:"source"`
	LastSync   time.Time `json:"last_sync"`
	EntryCount int       `json:"entry_count"`
}

func (s *Store) sourceDir(name string) string {
	return filepath.Join(s.Dir, name)
}

func (s *Store) PutVulns(source string, vulns []Vulnerability) error {
	dir := s.sourceDir(source)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "vulns.json")
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(vulns); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		audit.FileWritten(path, fi.Size())
	}
	return s.writeManifest(source, Manifest{
		Source:     source,
		LastSync:   time.Now(),
		EntryCount: len(vulns),
	})
}

func (s *Store) GetVulns(source string) ([]Vulnerability, error) {
	path := filepath.Join(s.sourceDir(source), "vulns.json")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var v []Vulnerability
	if err := json.NewDecoder(f).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode vulns for %s: %w", source, err)
	}
	return v, nil
}

func (s *Store) writeManifest(source string, m Manifest) error {
	path := filepath.Join(s.sourceDir(source), "manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	audit.FileWritten(path, int64(len(data)))
	return nil
}

func (s *Store) GetManifest(source string) (*Manifest, error) {
	path := filepath.Join(s.sourceDir(source), "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
