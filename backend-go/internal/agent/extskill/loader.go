package extskill

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxPromptBytes = 16 * 1024
	maxScripts     = 32
)

// LoadAll scans baseDir for skill packages and returns one Manifest per
// installed skill. Subdirectories that contain neither manifest.json nor
// SKILL.md are ignored.
func LoadAll(baseDir string) ([]Manifest, error) {
	if baseDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(baseDir, e.Name())
		m, err := LoadDir(dir)
		if err != nil || m == nil {
			continue
		}
		out = append(out, *m)
	}
	return out, nil
}

// LoadDir parses a single skill directory. Returns nil, nil if dir is not a
// recognizable skill package.
func LoadDir(dir string) (*Manifest, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	// Try native manifest.json first.
	if data, err := os.ReadFile(filepath.Join(abs, "manifest.json")); err == nil {
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("manifest.json: %w", err)
		}
		m.Root = abs
		if m.SkillRoot == "" {
			m.SkillRoot = abs
		}
		fillFromDisk(&m)
		return &m, nil
	}

	// Fall back to Claude Code plugin layout: scan recursively for SKILL.md.
	skillFile, err := findSkillFile(abs)
	if err != nil || skillFile == "" {
		return nil, nil
	}
	m, err := claudeCodeAutoManifest(abs, skillFile)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func findSkillFile(root string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(d.Name(), "SKILL.md") {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll {
		return "", err
	}
	return found, nil
}

// claudeCodeAutoManifest builds a Manifest from a Claude Code plugin layout:
//
//	<root>/
//	  plugins/<plugin>/
//	    .claude-plugin/plugin.json
//	    skills/<skill>/SKILL.md
//	    skills/<skill>/scripts/*.sh
//
// We index every script alongside SKILL.md as a runnable entry.
func claudeCodeAutoManifest(rootDir, skillFile string) (*Manifest, error) {
	skillDir := filepath.Dir(skillFile)
	id := filepath.Base(rootDir)
	name := id
	desc := ""
	body, _ := os.ReadFile(skillFile)
	front, prompt := splitFrontmatter(string(body))
	if v := front["name"]; v != "" {
		name = v
	}
	if v := front["description"]; v != "" {
		desc = v
	}
	tags := splitCSV(front["tags"])

	scriptsDir := filepath.Join(skillDir, "scripts")
	scripts := collectScripts(scriptsDir)
	if len(scripts) == 0 {
		// Look at a `commands` directory next to skill (Claude Code commands).
		cmdDir := filepath.Join(filepath.Dir(filepath.Dir(skillDir)), "commands")
		scripts = collectScripts(cmdDir)
	}

	m := &Manifest{
		ID:          id,
		Name:        name,
		Description: desc,
		Tags:        tags,
		Root:        rootDir,
		SkillRoot:   skillDir,
		Prompt:      truncate(prompt, maxPromptBytes),
		Scripts:     scripts,
	}
	return m, nil
}

func fillFromDisk(m *Manifest) {
	if m.Root == "" {
		return
	}
	if m.Prompt == "" {
		if data, err := os.ReadFile(filepath.Join(m.Root, "SKILL.md")); err == nil {
			_, prompt := splitFrontmatter(string(data))
			m.Prompt = truncate(prompt, maxPromptBytes)
		}
	}
	if len(m.Scripts) == 0 {
		base := m.SkillRoot
		if base == "" {
			base = m.Root
		}
		m.Scripts = collectScripts(filepath.Join(base, "scripts"))
	}
}

func collectScripts(dir string) []ScriptDef {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []ScriptDef
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".sh", ".bash", ".py", ".js", ".rb":
		default:
			continue
		}
		path := filepath.Join(dir, name)
		out = append(out, ScriptDef{
			Name:      strings.TrimSuffix(name, ext),
			Path:      path,
			Dangerous: looksDangerous(path),
		})
		if len(out) >= maxScripts {
			break
		}
	}
	return out
}

func looksDangerous(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "sudo ") ||
			strings.Contains(line, "rm -rf") ||
			strings.Contains(line, "curl ") && strings.Contains(line, "| sh") ||
			strings.Contains(line, "apt-get install") ||
			strings.Contains(line, "dnf install") ||
			strings.Contains(line, "pacman -S") {
			return true
		}
	}
	return false
}

func splitFrontmatter(text string) (map[string]string, string) {
	out := map[string]string{}
	if !strings.HasPrefix(text, "---") {
		return out, text
	}
	rest := strings.TrimPrefix(text, "---")
	rest = strings.TrimLeft(rest, "\r\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return out, text
	}
	front := rest[:end]
	body := rest[end+len("\n---"):]
	body = strings.TrimLeft(body, "\r\n")
	for _, line := range strings.Split(front, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")
		out[strings.ToLower(key)] = val
	}
	return out, body
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if max > 0 && len(s) > max {
		return s[:max] + "\n... [truncated]"
	}
	return s
}
