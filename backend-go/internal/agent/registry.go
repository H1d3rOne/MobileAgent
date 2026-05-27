package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mobileagent/backend-go/internal/llm"
)

// Skill is a tool the agent can invoke. Run executes synchronously and returns
// a string result (typically truncated). Errors are surfaced to the LLM.
type Skill struct {
	Name        string
	Description string
	Parameters  map[string]any // JSON Schema for the function's args
	Run         func(ctx context.Context, args map[string]any) (string, error)
}

type SkillMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Builtin     bool     `json:"builtin"`
	Source      string   `json:"source"`
	Enabled     bool     `json:"enabled"`
	Dangerous   bool     `json:"dangerous"`
}

type skillEntry struct {
	skill    Skill
	meta     SkillMetadata
	enabled  bool
}

// Registry holds all skills (built-in + MCP-provided).
type Registry struct {
	mu     sync.RWMutex
	skills map[string]skillEntry
}

func NewRegistry() *Registry {
	return &Registry{skills: map[string]skillEntry{}}
}

func (r *Registry) Register(s Skill) {
	r.RegisterWithMetadata(s, SkillMetadata{
		ID:          s.Name,
		Name:        s.Name,
		Description: s.Description,
		Source:      "builtin",
		Enabled:     true,
	})
}

func (r *Registry) RegisterWithMetadata(s Skill, meta SkillMetadata) {
	if meta.ID == "" {
		meta.ID = s.Name
	}
	if meta.Name == "" {
		meta.Name = s.Name
	}
	if meta.Description == "" {
		meta.Description = s.Description
	}
	if meta.Source == "" {
		meta.Source = "builtin"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skills[s.Name] = skillEntry{skill: s, meta: meta, enabled: meta.Enabled}
}

func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.skills, name)
}

func (r *Registry) SetEnabled(name string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.skills[name]
	if ok {
		entry.enabled = enabled
		entry.meta.Enabled = enabled
		r.skills[name] = entry
		return nil
	}
	// External skills register per-script tools with a sanitized prefix.
	// Try matching all tools that start with the sanitized package ID.
	prefix := sanitizeForPrefix(name) + "__"
	matched := false
	for k, e := range r.skills {
		if strings.HasPrefix(k, prefix) {
			e.enabled = enabled
			e.meta.Enabled = enabled
			r.skills[k] = e
			matched = true
		}
	}
	if matched {
		return nil
	}
	return fmt.Errorf("unknown skill: %s", name)
}

func sanitizeForPrefix(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "skill"
	}
	r := strings.NewReplacer("-", "_", " ", "_", "/", "_", "\\", "_", ":", "_", ".", "_")
	return r.Replace(s)
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.skills))
	for n := range r.skills {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) Get(name string) (Skill, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.skills[name]
	if !ok {
		return Skill{}, false
	}
	return entry.skill, true
}

func (r *Registry) Metadata(name string) (SkillMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.skills[name]
	if !ok {
		return SkillMetadata{}, false
	}
	return entry.meta, true
}

func (r *Registry) ListMetadata() []SkillMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SkillMetadata, 0, len(r.skills))
	for _, entry := range r.skills {
		meta := entry.meta
		meta.Enabled = entry.enabled
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AsLLMTools returns the OpenAI-style tools array for all enabled registered skills.
func (r *Registry) AsLLMTools() []llm.Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tools := make([]llm.Tool, 0, len(r.skills))
	for _, entry := range r.skills {
		if !entry.enabled {
			continue
		}
		params := entry.skill.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		tools = append(tools, llm.Tool{
			Type: "function",
			Function: llm.ToolFunction{
				Name:        entry.skill.Name,
				Description: entry.skill.Description,
				Parameters:  params,
			},
		})
	}
	return tools
}

// Call executes an enabled skill by name with parsed args.
func (r *Registry) Call(ctx context.Context, name string, args map[string]any) (string, error) {
	r.mu.RLock()
	entry, ok := r.skills[name]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown skill: %s", name)
	}
	if !entry.enabled {
		return "", fmt.Errorf("skill disabled: %s", name)
	}
	return entry.skill.Run(ctx, args)
}

// IsDangerous returns whether a skill is marked as dangerous.
func (r *Registry) IsDangerous(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.skills[name]
	return ok && entry.meta.Dangerous
}
