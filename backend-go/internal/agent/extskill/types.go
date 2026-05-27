package extskill

// Manifest is the in-memory representation of an external skill package found
// under data/skills/. It is built either from manifest.json (native format) or
// auto-detected from SKILL.md + scripts/ (Claude Code plugin format).
type Manifest struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version,omitempty"`
	Description string      `json:"description,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Prompt      string      `json:"prompt,omitempty"`     // SKILL.md content (truncated)
	Root        string      `json:"root"`                 // absolute path of the skill dir
	SkillRoot   string      `json:"skill_root,omitempty"` // CLAUDE_PLUGIN_ROOT-style root for scripts
	Scripts     []ScriptDef `json:"scripts,omitempty"`
}

// ScriptDef describes one executable script that becomes a registered skill.
type ScriptDef struct {
	Name        string `json:"name"`        // logical name (no extension)
	Path        string `json:"path"`        // absolute path to the script
	Description string `json:"description,omitempty"`
	Dangerous   bool   `json:"dangerous,omitempty"` // heuristic: contains sudo, rm -rf, curl|sh, etc.
}
