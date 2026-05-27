package market

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mobileagent/backend-go/internal/agent"
	"github.com/mobileagent/backend-go/internal/agent/extskill"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/mcp"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type Service struct {
	store     *store.MarketStore
	registry  *agent.Registry
	mcp       *mcp.Manager
	cfg       *config.Config
	http      *http.Client
	manifests map[string]extskill.Manifest // id -> loaded manifest
}

type SkillInstallInput struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Version        string `json:"version"`
	BuiltinSkillID string `json:"builtin_skill_id"`
	Source         string `json:"source"`
	SourceID       string `json:"source_id"`
	Enabled        bool   `json:"enabled"`
	GitURL         string `json:"git_url"` // optional: clone external skill from this URL
}

type MCPInstallInput struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Command     []string          `json:"command"`
	Env         map[string]string `json:"env"`
	Cwd         string            `json:"cwd"`
	Source      string            `json:"source"`
	SourceID    string            `json:"source_id"`
	Enabled     bool              `json:"enabled"`
}

func NewService(ms *store.MarketStore, registry *agent.Registry, mgr *mcp.Manager, cfg *config.Config) *Service {
	return &Service{
		store:     ms,
		registry:  registry,
		mcp:       mgr,
		cfg:       cfg,
		http:      &http.Client{Timeout: 20 * time.Second},
		manifests: map[string]extskill.Manifest{},
	}
}

// LoadedManifests returns the currently loaded external skill manifests so the
// agent can include their workflow notes in the system prompt.
func (s *Service) LoadedManifests() []extskill.Manifest {
	out := make([]extskill.Manifest, 0, len(s.manifests))
	for _, m := range s.manifests {
		out = append(out, m)
	}
	return out
}

func (s *Service) Initialize(ctx context.Context) error {
	if _, err := s.ensureBuiltinSource(); err != nil {
		return err
	}
	// Re-scan data/skills/ and register all packs found there.
	if err := s.reloadExternalSkills(); err != nil {
		return err
	}
	if err := s.applyInstalledSkills(); err != nil {
		return err
	}
	if err := s.applyInstalledMCPs(ctx); err != nil {
		return err
	}
	_, err := s.RefreshCatalog(ctx)
	return err
}

func (s *Service) reloadExternalSkills() error {
	if s.cfg == nil || s.cfg.Storage.SkillsDir == "" {
		return nil
	}
	manifests, err := extskill.LoadAll(s.cfg.Storage.SkillsDir)
	if err != nil {
		return err
	}
	// Unregister anything we loaded previously, then re-register.
	for _, prev := range s.manifests {
		for _, name := range extskill.ToolNamesFor(prev) {
			s.registry.Unregister(name)
		}
	}
	s.manifests = map[string]extskill.Manifest{}
	for _, m := range manifests {
		s.manifests[m.ID] = m
		// Determine if all scripts in the manifest are dangerous.
		allDangerous := len(m.Scripts) > 0
		for _, sc := range m.Scripts {
			if !sc.Dangerous {
				allDangerous = false
				break
			}
		}
		for _, rs := range extskill.BuildSkills(m, extskill.RunOptions{}) {
			s.registry.RegisterWithMetadata(agent.Skill{
				Name:        rs.Name,
				Description: rs.Description,
				Parameters:  rs.Parameters,
				Run:         rs.Run,
			}, agent.SkillMetadata{
				ID:          rs.Name,
				Name:        rs.Name,
				Description: rs.Description,
				Tags:        rs.Tags,
				Source:      "external",
				Builtin:     false,
				Enabled:     true,
				Dangerous:   allDangerous,
			})
		}
	}
	return nil
}

func (s *Service) ListVisibleSkills() []map[string]any {
	items := s.registry.ListMetadata()
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		meta, _ := s.registry.Metadata(item.Name)
		skill, _ := s.registry.Get(item.Name)
		params := skill.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{
			"id": item.ID,
			"name": item.Name,
			"description": item.Description,
			"enabled": meta.Enabled,
			"builtin": meta.Builtin,
			"source": meta.Source,
			"tags": meta.Tags,
			"parameters": params,
		})
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
	return out
}

func (s *Service) ListInstalledSkills() ([]model.InstalledSkill, error) {
	return s.store.ListInstalledSkills()
}

func (s *Service) ListSkillCatalog() ([]model.SkillCatalogItem, error) {
	cat, err := s.store.LoadCatalog()
	if err != nil {
		return nil, err
	}
	installed, err := s.store.ListInstalledSkills()
	if err != nil {
		return nil, err
	}
	installedByID := map[string]model.InstalledSkill{}
	for _, item := range installed {
		installedByID[item.ID] = item
	}
	for i := range cat.Skills {
		if inst, ok := installedByID[cat.Skills[i].ID]; ok {
			cat.Skills[i].Installed = true
			cat.Skills[i].Enabled = inst.Enabled
			cat.Skills[i].Available = inst.Available
		} else if cat.Skills[i].Builtin || cat.Skills[i].Source == "builtin" {
			// Builtin skills live in the registry — they're always installed/usable.
			if meta, ok := s.registry.Metadata(cat.Skills[i].BuiltinSkillID); ok {
				cat.Skills[i].Installed = true
				cat.Skills[i].Enabled = meta.Enabled
				cat.Skills[i].Available = true
			}
		}
	}
	return cat.Skills, nil
}

func (s *Service) InstallSkill(input SkillInstallInput) (model.InstalledSkill, error) {
	if strings.TrimSpace(input.ID) == "" {
		return model.InstalledSkill{}, fmt.Errorf("id required")
	}
	if strings.TrimSpace(input.Name) == "" {
		input.Name = input.ID
	}

	// If a git_url is provided, clone the repo into data/skills/<id>/ and
	// reload external manifests so the package is picked up natively.
	if strings.TrimSpace(input.GitURL) != "" {
		if s.cfg == nil || s.cfg.Storage.SkillsDir == "" {
			return model.InstalledSkill{}, fmt.Errorf("skills_dir not configured")
		}
		if err := os.MkdirAll(s.cfg.Storage.SkillsDir, 0o755); err != nil {
			return model.InstalledSkill{}, err
		}
		dest := filepath.Join(s.cfg.Storage.SkillsDir, sanitizePathID(input.ID))
		// Wipe any previous install so reinstall is idempotent.
		_ = os.RemoveAll(dest)
		if err := gitClone(input.GitURL, dest); err != nil {
			return model.InstalledSkill{}, err
		}
		if err := s.reloadExternalSkills(); err != nil {
			return model.InstalledSkill{}, err
		}
	}

	if strings.TrimSpace(input.BuiltinSkillID) == "" {
		input.BuiltinSkillID = input.ID
	}
	meta, ok := s.registry.Metadata(input.BuiltinSkillID)
	available := ok
	if ok && input.Description == "" {
		input.Description = meta.Description
	}
	// External skills don't bind to a single registry skill — mark as available
	// when their manifest is loaded.
	if !available {
		if _, found := s.manifests[input.ID]; found {
			available = true
		}
	}
	items, err := s.store.ListInstalledSkills()
	if err != nil {
		return model.InstalledSkill{}, err
	}
	now := time.Now()
	item := model.InstalledSkill{
		ID:             input.ID,
		Name:           input.Name,
		Description:    input.Description,
		Version:        input.Version,
		BuiltinSkillID: input.BuiltinSkillID,
		Source:         defaultString(input.Source, "manual"),
		SourceID:       input.SourceID,
		Enabled:        input.Enabled && available,
		Available:      available,
		Builtin:        ok && meta.Builtin,
		InstalledAt:    now,
		UpdatedAt:      now,
	}
	updated := false
	for i := range items {
		if items[i].ID == item.ID {
			item.InstalledAt = items[i].InstalledAt
			items[i] = item
			updated = true
			break
		}
	}
	if !updated {
		items = append(items, item)
	}
	if err := s.store.SaveInstalledSkills(items); err != nil {
		return model.InstalledSkill{}, err
	}
	if ok {
		if err := s.registry.SetEnabled(input.BuiltinSkillID, item.Enabled); err != nil {
			return model.InstalledSkill{}, err
		}
	}
	return item, nil
}

func gitClone(url, dest string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", url, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone %s: %w\n%s", url, err, string(out))
	}
	return nil
}

func sanitizePathID(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "..", "_")
	return r.Replace(strings.TrimSpace(s))
}

func (s *Service) SetSkillEnabled(id string, enabled bool) (model.InstalledSkill, error) {
	items, err := s.store.ListInstalledSkills()
	if err != nil {
		return model.InstalledSkill{}, err
	}
	for i := range items {
		if items[i].ID != id {
			continue
		}
		items[i].Enabled = enabled && items[i].Available
		items[i].UpdatedAt = time.Now()
		if items[i].Available {
			if err := s.registry.SetEnabled(items[i].BuiltinSkillID, items[i].Enabled); err != nil {
				return model.InstalledSkill{}, err
			}
		}
		if err := s.store.SaveInstalledSkills(items); err != nil {
			return model.InstalledSkill{}, err
		}
		return items[i], nil
	}
	return model.InstalledSkill{}, fmt.Errorf("skill not found: %s", id)
}

func (s *Service) DeleteSkill(id string) error {
	items, err := s.store.ListInstalledSkills()
	if err != nil {
		return err
	}
	out := make([]model.InstalledSkill, 0, len(items))
	for _, item := range items {
		if item.ID == id {
			if item.Available && !item.Builtin {
				_ = s.registry.SetEnabled(item.BuiltinSkillID, true)
			}
			// Remove external skill artifacts and unregister its tools.
			if m, ok := s.manifests[id]; ok {
				for _, name := range extskill.ToolNamesFor(m) {
					s.registry.Unregister(name)
				}
				if m.Root != "" {
					_ = os.RemoveAll(m.Root)
				}
				delete(s.manifests, id)
			} else if s.cfg != nil && s.cfg.Storage.SkillsDir != "" {
				dest := filepath.Join(s.cfg.Storage.SkillsDir, sanitizePathID(id))
				if st, err := os.Stat(dest); err == nil && st.IsDir() {
					_ = os.RemoveAll(dest)
				}
			}
			continue
		}
		out = append(out, item)
	}
	return s.store.SaveInstalledSkills(out)
}

func (s *Service) ListSources() ([]model.MarketSource, error) {
	return s.store.ListSources()
}

func (s *Service) AddSource(name, url string) (model.MarketSource, error) {
	if strings.TrimSpace(url) == "" {
		return model.MarketSource{}, fmt.Errorf("url required")
	}
	items, err := s.store.ListSources()
	if err != nil {
		return model.MarketSource{}, err
	}
	now := time.Now()
	source := model.MarketSource{
		ID:        util.NewID(),
		Name:      defaultString(name, url),
		Type:      "remote",
		URL:       url,
		Enabled:   true,
		Builtin:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	items = append(items, source)
	if err := s.store.SaveSources(items); err != nil {
		return model.MarketSource{}, err
	}
	return source, nil
}

func (s *Service) DeleteSource(id string) error {
	items, err := s.store.ListSources()
	if err != nil {
		return err
	}
	out := make([]model.MarketSource, 0, len(items))
	for _, item := range items {
		if item.ID == id && !item.Builtin {
			continue
		}
		out = append(out, item)
	}
	return s.store.SaveSources(out)
}

func (s *Service) RefreshCatalog(ctx context.Context) (model.MarketCatalog, error) {
	sources, err := s.ensureBuiltinSource()
	if err != nil {
		return model.MarketCatalog{}, err
	}
	catalog := model.MarketCatalog{Version: "1"}
	catalog.Skills = append(catalog.Skills, s.builtinSkillsCatalog()...)
	catalog.MCPs = append(catalog.MCPs, s.builtinMCPCatalog()...)
	updatedSources := make([]model.MarketSource, 0, len(sources))
	for _, source := range sources {
		if !source.Enabled || source.Builtin || source.Type != "remote" || source.URL == "" {
			updatedSources = append(updatedSources, source)
			continue
		}
		remote, err := s.fetchRemoteCatalog(ctx, source.URL)
		source.UpdatedAt = time.Now()
		if err != nil {
			source.LastError = err.Error()
			updatedSources = append(updatedSources, source)
			continue
		}
		source.LastError = ""
		source.LastSyncedAt = time.Now()
		updatedSources = append(updatedSources, source)
		for _, item := range remote.Skills {
			item.Source = "remote"
			item.SourceID = source.ID
			catalog.Skills = append(catalog.Skills, item)
		}
		for _, item := range remote.MCPs {
			item.Source = "remote"
			item.SourceID = source.ID
			catalog.MCPs = append(catalog.MCPs, item)
		}
	}
	catalog.Skills = dedupeSkills(catalog.Skills)
	catalog.MCPs = dedupeMCPs(catalog.MCPs)
	if err := s.store.SaveCatalog(catalog); err != nil {
		return model.MarketCatalog{}, err
	}
	if err := s.store.SaveSources(updatedSources); err != nil {
		return model.MarketCatalog{}, err
	}
	return catalog, nil
}

func (s *Service) ListInstalledMCPs() ([]model.InstalledMCP, error) {
	return s.mcp.ListInstalled()
}

func (s *Service) ListMCPCatalog() ([]model.MCPCatalogItem, error) {
	cat, err := s.store.LoadCatalog()
	if err != nil {
		return nil, err
	}
	installed, err := s.mcp.ListInstalled()
	if err != nil {
		return nil, err
	}
	installedByID := map[string]model.InstalledMCP{}
	for _, item := range installed {
		installedByID[item.ID] = item
	}
	for i := range cat.MCPs {
		if inst, ok := installedByID[cat.MCPs[i].ID]; ok {
			cat.MCPs[i].Installed = true
			cat.MCPs[i].Enabled = inst.Enabled
		}
	}
	return cat.MCPs, nil
}

func (s *Service) InstallMCP(ctx context.Context, input MCPInstallInput) (model.InstalledMCP, error) {
	if strings.TrimSpace(input.ID) == "" {
		return model.InstalledMCP{}, fmt.Errorf("id required")
	}
	if len(input.Command) == 0 {
		return model.InstalledMCP{}, fmt.Errorf("command required")
	}
	item := model.InstalledMCP{
		ID:          input.ID,
		Name:        defaultString(input.Name, input.ID),
		Description: input.Description,
		Version:     input.Version,
		Command:     input.Command,
		Env:         input.Env,
		Cwd:         input.Cwd,
		Source:      defaultString(input.Source, "manual"),
		SourceID:    input.SourceID,
		Enabled:     input.Enabled,
	}
	return s.mcp.Upsert(ctx, item)
}

func (s *Service) SetMCPEnabled(ctx context.Context, id string, enabled bool) (model.InstalledMCP, error) {
	return s.mcp.SetEnabled(ctx, id, enabled)
}

func (s *Service) RestartMCP(ctx context.Context, id string) (model.InstalledMCP, error) {
	return s.mcp.Restart(ctx, id)
}

func (s *Service) DeleteMCP(id string) error {
	return s.mcp.Remove(id)
}

func (s *Service) ensureBuiltinSource() ([]model.MarketSource, error) {
	items, err := s.store.ListSources()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Builtin {
			return items, nil
		}
	}
	now := time.Now()
	items = append(items, model.MarketSource{
		ID:        "builtin",
		Name:      "Built-in Market",
		Type:      "builtin",
		Enabled:   true,
		Builtin:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	return items, s.store.SaveSources(items)
}

func (s *Service) applyInstalledSkills() error {
	items, err := s.store.ListInstalledSkills()
	if err != nil {
		return err
	}
	for i := range items {
		if !items[i].Available {
			if _, ok := s.registry.Metadata(items[i].BuiltinSkillID); ok {
				items[i].Available = true
			}
		}
		if items[i].Available {
			if err := s.registry.SetEnabled(items[i].BuiltinSkillID, items[i].Enabled); err != nil {
				return err
			}
		}
	}
	return s.store.SaveInstalledSkills(items)
}

func (s *Service) applyInstalledMCPs(ctx context.Context) error {
	items, err := s.store.ListInstalledMCPs()
	if err != nil {
		return err
	}
	return s.mcp.Load(ctx, items)
}

func (s *Service) builtinSkillsCatalog() []model.SkillCatalogItem {
	metas := s.registry.ListMetadata()
	out := make([]model.SkillCatalogItem, 0, len(metas))
	for _, meta := range metas {
		out = append(out, model.SkillCatalogItem{
			ID:             meta.ID,
			Name:           meta.Name,
			Description:    meta.Description,
			BuiltinSkillID: meta.Name,
			Source:         "builtin",
			SourceID:       "builtin",
			Enabled:        meta.Enabled,
			Available:      true,
			Builtin:        meta.Builtin || meta.Source == "builtin",
			Tags:           meta.Tags,
		})
	}
	return out
}

func (s *Service) builtinMCPCatalog() []model.MCPCatalogItem {
	items := s.mcp.BuiltinCatalog()
	for i := range items {
		items[i].Source = "builtin"
		items[i].SourceID = "builtin"
	}
	return items
}

func (s *Service) fetchRemoteCatalog(ctx context.Context, url string) (model.MarketCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.MarketCatalog{}, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return model.MarketCatalog{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return model.MarketCatalog{}, fmt.Errorf("market source returned %d", resp.StatusCode)
	}
	var cat model.MarketCatalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return model.MarketCatalog{}, err
	}
	if cat.Version == "" {
		cat.Version = "1"
	}
	return cat, nil
}

func dedupeSkills(items []model.SkillCatalogItem) []model.SkillCatalogItem {
	seen := map[string]model.SkillCatalogItem{}
	for _, item := range items {
		seen[item.ID] = item
	}
	out := make([]model.SkillCatalogItem, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func dedupeMCPs(items []model.MCPCatalogItem) []model.MCPCatalogItem {
	seen := map[string]model.MCPCatalogItem{}
	for _, item := range items {
		seen[item.ID] = item
	}
	out := make([]model.MCPCatalogItem, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
