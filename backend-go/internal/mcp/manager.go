package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/agent"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/store"
)

type serverState struct {
	config model.InstalledMCP
	server *Server
	tools  []string
}

// Manager owns the lifecycle of all configured MCP servers.
type Manager struct {
	cfg      *config.Config
	store    *store.MarketStore
	registry *agent.Registry
	servers  map[string]*serverState
	mu       sync.RWMutex
}

func NewManager(cfg *config.Config, ms *store.MarketStore) *Manager {
	return &Manager{cfg: cfg, store: ms, servers: map[string]*serverState{}}
}

func (m *Manager) AttachRegistry(registry *agent.Registry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = registry
}

func (m *Manager) Start(ctx context.Context, registry *agent.Registry) {
	m.AttachRegistry(registry)
	for _, item := range m.builtinConfigured() {
		if !item.Enabled {
			continue
		}
		if _, err := m.startServer(ctx, item); err != nil {
			zap.L().Warn("mcp server failed to start", zap.String("name", item.ID), zap.Error(err))
		}
	}
}

func (m *Manager) Stop() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.servers))
	for id := range m.servers {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.stopServer(id)
	}
}

func (m *Manager) Load(ctx context.Context, items []model.InstalledMCP) error {
	for _, item := range items {
		state := item
		if state.Enabled {
			if _, err := m.startServer(ctx, state); err != nil {
				state.LastError = err.Error()
				state.Alive = false
				if saveErr := m.upsertStored(state); saveErr != nil {
					return saveErr
				}
				continue
			}
		}
		m.mu.Lock()
		if existing, ok := m.servers[state.ID]; ok {
			existing.config = state
		} else {
			m.servers[state.ID] = &serverState{config: state}
		}
		m.mu.Unlock()
	}
	return nil
}

func (m *Manager) Upsert(ctx context.Context, item model.InstalledMCP) (model.InstalledMCP, error) {
	if strings.TrimSpace(item.ID) == "" {
		return model.InstalledMCP{}, fmt.Errorf("id required")
	}
	if len(item.Command) == 0 {
		return model.InstalledMCP{}, fmt.Errorf("command required")
	}
	now := time.Now()
	items, err := m.loadStored()
	if err != nil {
		return model.InstalledMCP{}, err
	}
	updated := false
	for i := range items {
		if items[i].ID != item.ID {
			continue
		}
		item.InstalledAt = items[i].InstalledAt
		if item.InstalledAt.IsZero() {
			item.InstalledAt = now
		}
		item.UpdatedAt = now
		items[i] = item
		updated = true
		break
	}
	if !updated {
		if item.InstalledAt.IsZero() {
			item.InstalledAt = now
		}
		item.UpdatedAt = now
		items = append(items, item)
	}
	if err := m.store.SaveInstalledMCPs(items); err != nil {
		return model.InstalledMCP{}, err
	}
	if item.Enabled {
		state, err := m.startServer(ctx, item)
		if err != nil {
			item.LastError = err.Error()
			item.Alive = false
			_ = m.upsertStored(item)
			return item, err
		}
		return state.config, nil
	}
	if err := m.stopServer(item.ID); err != nil {
		return model.InstalledMCP{}, err
	}
	m.mu.Lock()
	m.servers[item.ID] = &serverState{config: item}
	m.mu.Unlock()
	return item, nil
}

func (m *Manager) SetEnabled(ctx context.Context, id string, enabled bool) (model.InstalledMCP, error) {
	items, err := m.loadStored()
	if err != nil {
		return model.InstalledMCP{}, err
	}
	for i := range items {
		if items[i].ID != id {
			continue
		}
		items[i].Enabled = enabled
		items[i].UpdatedAt = time.Now()
		if err := m.store.SaveInstalledMCPs(items); err != nil {
			return model.InstalledMCP{}, err
		}
		if enabled {
			state, err := m.startServer(ctx, items[i])
			if err != nil {
				items[i].Alive = false
				items[i].LastError = err.Error()
				_ = m.store.SaveInstalledMCPs(items)
				return items[i], err
			}
			return state.config, nil
		}
		if err := m.stopServer(id); err != nil {
			return model.InstalledMCP{}, err
		}
		items[i].Alive = false
		items[i].ToolCount = 0
		items[i].LastError = ""
		_ = m.store.SaveInstalledMCPs(items)
		return items[i], nil
	}
	return model.InstalledMCP{}, fmt.Errorf("mcp not found: %s", id)
}

func (m *Manager) Restart(ctx context.Context, id string) (model.InstalledMCP, error) {
	items, err := m.loadStored()
	if err != nil {
		return model.InstalledMCP{}, err
	}
	for _, item := range items {
		if item.ID != id {
			continue
		}
		if err := m.stopServer(id); err != nil {
			return model.InstalledMCP{}, err
		}
		if !item.Enabled {
			return item, nil
		}
		state, err := m.startServer(ctx, item)
		if err != nil {
			item.Alive = false
			item.LastError = err.Error()
			_ = m.upsertStored(item)
			return item, err
		}
		return state.config, nil
	}
	return model.InstalledMCP{}, fmt.Errorf("mcp not found: %s", id)
}

func (m *Manager) Remove(id string) error {
	if err := m.stopServer(id); err != nil {
		return err
	}
	items, err := m.loadStored()
	if err != nil {
		return err
	}
	out := make([]model.InstalledMCP, 0, len(items))
	for _, item := range items {
		if item.ID == id {
			continue
		}
		out = append(out, item)
	}
	return m.store.SaveInstalledMCPs(out)
}

func (m *Manager) ListInstalled() ([]model.InstalledMCP, error) {
	stored, err := m.loadStored()
	if err != nil {
		return nil, err
	}
	byID := map[string]model.InstalledMCP{}
	for _, item := range stored {
		byID[item.ID] = item
	}
	for _, item := range m.builtinConfigured() {
		if _, ok := byID[item.ID]; !ok {
			byID[item.ID] = item
		}
	}
	m.mu.RLock()
	for id, state := range m.servers {
		item := byID[id]
		item = state.config
		if state.server != nil {
			item.Alive = true
			item.ToolCount = len(state.server.Tools())
		}
		byID[id] = item
	}
	m.mu.RUnlock()
	out := make([]model.InstalledMCP, 0, len(byID))
	for _, item := range byID {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) BuiltinCatalog() []model.MCPCatalogItem {
	items := m.builtinConfigured()
	out := make([]model.MCPCatalogItem, 0, len(items))
	for _, item := range items {
		out = append(out, model.MCPCatalogItem{
			ID:          item.ID,
			Name:        item.Name,
			Description: item.Description,
			Command:     item.Command,
			Env:         item.Env,
			Cwd:         item.Cwd,
			Enabled:     item.Enabled,
		})
	}
	return out
}

// Status returns name → status details.
func (m *Manager) Status() map[string]map[string]any {
	items, _ := m.ListInstalled()
	out := map[string]map[string]any{}
	for _, item := range items {
		out[item.ID] = map[string]any{
			"id": item.ID,
			"name": item.Name,
			"description": item.Description,
			"alive": item.Alive,
			"enabled": item.Enabled,
			"tool_count": item.ToolCount,
			"command": strings.Join(item.Command, " "),
			"source": item.Source,
			"cwd": item.Cwd,
			"last_error": item.LastError,
		}
	}
	return out
}

func (m *Manager) stopServer(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.servers[id]
	if !ok {
		return nil
	}
	for _, toolName := range state.tools {
		if m.registry != nil {
			m.registry.Unregister(toolName)
		}
	}
	if state.server != nil {
		_ = state.server.Close()
	}
	state.server = nil
	state.tools = nil
	state.config.Alive = false
	state.config.ToolCount = 0
	state.config.LastError = ""
	m.servers[id] = state
	return nil
}

func (m *Manager) startServer(ctx context.Context, item model.InstalledMCP) (*serverState, error) {
	if len(item.Command) == 0 {
		return nil, fmt.Errorf("empty command for mcp server %s", item.ID)
	}
	_ = m.stopServer(item.ID)
	srv, err := Start(ctx, item.ID, item.Command, item.Env)
	if err != nil {
		return nil, err
	}
	state := &serverState{config: item, server: srv}
	if m.registry != nil {
		for _, t := range srv.Tools() {
			toolName := "mcp_" + item.ID + "_" + sanitize(t.Name)
			state.tools = append(state.tools, toolName)
			tt := t
			sname := item.ID
			m.registry.RegisterWithMetadata(agent.Skill{
				Name:        toolName,
				Description: "[MCP " + item.ID + "] " + tt.Description,
				Parameters:  tt.InputSchema,
				Run: func(rctx context.Context, args map[string]any) (string, error) {
					m.mu.RLock()
					current := m.servers[sname]
					m.mu.RUnlock()
					if current == nil || current.server == nil {
						return "", errServerGone
					}
					return current.server.CallTool(rctx, tt.Name, args)
				},
			}, agent.SkillMetadata{
				ID:          toolName,
				Name:        toolName,
				Description: "[MCP " + item.ID + "] " + tt.Description,
				Source:      "mcp",
				Enabled:     item.Enabled,
			})
		}
	}
	state.config.Enabled = item.Enabled
	state.config.Alive = true
	state.config.ToolCount = len(srv.Tools())
	state.config.LastError = ""
	state.config.UpdatedAt = time.Now()
	m.mu.Lock()
	m.servers[item.ID] = state
	m.mu.Unlock()
	if err := m.upsertStored(state.config); err != nil {
		return nil, err
	}
	zap.L().Info("mcp server up", zap.String("name", item.ID), zap.Int("tools", len(srv.Tools())))
	return state, nil
}

func (m *Manager) upsertStored(item model.InstalledMCP) error {
	items, err := m.loadStored()
	if err != nil {
		return err
	}
	updated := false
	for i := range items {
		if items[i].ID == item.ID {
			if item.InstalledAt.IsZero() {
				item.InstalledAt = items[i].InstalledAt
			}
			items[i] = item
			updated = true
			break
		}
	}
	if !updated && item.Source != "builtin" {
		items = append(items, item)
	}
	return m.store.SaveInstalledMCPs(items)
}

func (m *Manager) loadStored() ([]model.InstalledMCP, error) {
	if m.store == nil {
		return []model.InstalledMCP{}, nil
	}
	return m.store.ListInstalledMCPs()
}

func (m *Manager) builtinConfigured() []model.InstalledMCP {
	out := make([]model.InstalledMCP, 0, len(m.cfg.MCP.Servers))
	for name, sc := range m.cfg.MCP.Servers {
		description := "Configured MCP server"
		if len(sc.Command) > 0 {
			description = "Configured MCP server: " + strings.Join(sc.Command, " ")
		}
		out = append(out, model.InstalledMCP{
			ID:          name,
			Name:        name,
			Description: description,
			Command:     sc.Command,
			Env:         sc.Env,
			Source:      "builtin",
			SourceID:    "builtin",
			Enabled:     true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sanitize(s string) string {
	return strings.NewReplacer(":", "_", "/", "_", " ", "_", "-", "_").Replace(s)
}

var errServerGone = simpleErr("mcp server unavailable")

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
