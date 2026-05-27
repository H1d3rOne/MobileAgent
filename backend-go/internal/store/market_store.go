package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/mobileagent/backend-go/internal/model"
)

type MarketStore struct {
	baseDir string
	mu      sync.Mutex
}

func NewMarketStore(baseDir string) (*MarketStore, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("create market dir: %w", err)
	}
	return &MarketStore{baseDir: baseDir}, nil
}

func (s *MarketStore) ListSources() ([]model.MarketSource, error) {
	return readSlice[model.MarketSource](s.filePath("market_sources.json"))
}

func (s *MarketStore) SaveSources(items []model.MarketSource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONFile(s.filePath("market_sources.json"), items)
}

func (s *MarketStore) ListInstalledSkills() ([]model.InstalledSkill, error) {
	items, err := readSlice[model.InstalledSkill](s.filePath("installed_skills.json"))
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (s *MarketStore) SaveInstalledSkills(items []model.InstalledSkill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONFile(s.filePath("installed_skills.json"), items)
}

func (s *MarketStore) ListInstalledMCPs() ([]model.InstalledMCP, error) {
	items, err := readSlice[model.InstalledMCP](s.filePath("installed_mcps.json"))
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (s *MarketStore) SaveInstalledMCPs(items []model.InstalledMCP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONFile(s.filePath("installed_mcps.json"), items)
}

func (s *MarketStore) LoadCatalog() (model.MarketCatalog, error) {
	var cat model.MarketCatalog
	path := s.filePath("market_catalog.json")
	if err := readJSONFile(path, &cat); err != nil {
		if os.IsNotExist(err) {
			return model.MarketCatalog{Version: "1"}, nil
		}
		return model.MarketCatalog{}, err
	}
	if cat.Version == "" {
		cat.Version = "1"
	}
	return cat, nil
}

func (s *MarketStore) SaveCatalog(cat model.MarketCatalog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cat.Version == "" {
		cat.Version = "1"
	}
	return writeJSONFile(s.filePath("market_catalog.json"), cat)
}

func (s *MarketStore) filePath(name string) string {
	return filepath.Join(s.baseDir, name)
}

func readSlice[T any](path string) ([]T, error) {
	var items []T
	if err := readJSONFile(path, &items); err != nil {
		if os.IsNotExist(err) {
			return []T{}, nil
		}
		return nil, err
	}
	if items == nil {
		items = []T{}
	}
	return items, nil
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
