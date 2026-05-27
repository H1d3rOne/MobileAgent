package model

import "time"

type MarketSource struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	URL           string    `json:"url,omitempty"`
	Enabled       bool      `json:"enabled"`
	Builtin       bool      `json:"builtin"`
	LastError     string    `json:"last_error,omitempty"`
	LastSyncedAt  time.Time `json:"last_synced_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SkillCatalogItem struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Version          string         `json:"version,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	BuiltinSkillID   string         `json:"builtin_skill_id,omitempty"`
	Source           string         `json:"source"`
	SourceID         string         `json:"source_id,omitempty"`
	Installed        bool           `json:"installed"`
	Enabled          bool           `json:"enabled"`
	Available        bool           `json:"available"`
	Builtin          bool           `json:"builtin"`
	Manifest         map[string]any `json:"manifest,omitempty"`
}

type InstalledSkill struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Version          string         `json:"version,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	BuiltinSkillID   string         `json:"builtin_skill_id,omitempty"`
	Source           string         `json:"source"`
	SourceID         string         `json:"source_id,omitempty"`
	Enabled          bool           `json:"enabled"`
	Available        bool           `json:"available"`
	Builtin          bool           `json:"builtin"`
	Manifest         map[string]any `json:"manifest,omitempty"`
	InstalledAt      time.Time      `json:"installed_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type MCPCatalogItem struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Source      string            `json:"source"`
	SourceID    string            `json:"source_id,omitempty"`
	Installed   bool              `json:"installed"`
	Enabled     bool              `json:"enabled"`
	Manifest    map[string]any    `json:"manifest,omitempty"`
}

type InstalledMCP struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Command     []string          `json:"command"`
	Env         map[string]string `json:"env,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Source      string            `json:"source"`
	SourceID    string            `json:"source_id,omitempty"`
	Enabled     bool              `json:"enabled"`
	Alive       bool              `json:"alive"`
	ToolCount   int               `json:"tool_count"`
	LastError   string            `json:"last_error,omitempty"`
	Manifest    map[string]any    `json:"manifest,omitempty"`
	InstalledAt time.Time         `json:"installed_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type MarketCatalog struct {
	Version string             `json:"version"`
	Skills  []SkillCatalogItem `json:"skills"`
	MCPs    []MCPCatalogItem   `json:"mcps"`
}
