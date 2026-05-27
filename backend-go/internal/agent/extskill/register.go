package extskill

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultExecTimeout = 120 * time.Second
	maxOutputBytes     = 64 * 1024
)

// RunOptions controls runtime safety/limits for script execution.
type RunOptions struct {
	Timeout        time.Duration
	MaxOutputBytes int
	AllowDangerous bool
}

// RunnableSkill is a self-contained skill description that the agent package
// can register without creating an import cycle.
type RunnableSkill struct {
	Name        string
	Description string
	Tags        []string
	Parameters  map[string]any
	Run         func(ctx context.Context, args map[string]any) (string, error)
}

// BuildSkills converts a manifest into agent-registerable skill descriptors.
// Caller is responsible for registering them on the agent.Registry.
func BuildSkills(m Manifest, opts RunOptions) []RunnableSkill {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultExecTimeout
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = maxOutputBytes
	}
	out := make([]RunnableSkill, 0, len(m.Scripts))
	for _, sc := range m.Scripts {
		if sc.Dangerous && !opts.AllowDangerous {
			continue
		}
		toolName := fmt.Sprintf("%s__%s", SanitizeID(m.ID), SanitizeID(sc.Name))
		desc := sc.Description
		if desc == "" {
			desc = fmt.Sprintf("[%s] Run %s from external skill %s.", m.Name, filepath.Base(sc.Path), m.Name)
		}
		script := sc
		root := m.SkillRoot
		if root == "" {
			root = m.Root
		}
		out = append(out, RunnableSkill{
			Name:        toolName,
			Description: desc,
			Tags:        m.Tags,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"args": map[string]any{
						"type":        "string",
						"description": "Command line arguments passed verbatim to the script.",
					},
					"stdin": map[string]any{
						"type":        "string",
						"description": "Optional stdin to pipe into the script.",
					},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				return execScript(ctx, script, root, args, opts)
			},
		})
	}
	return out
}

// ToolNamesFor returns the registry skill names that BuildSkills would emit
// for a manifest, used by callers that need to unregister.
func ToolNamesFor(m Manifest) []string {
	names := make([]string, 0, len(m.Scripts))
	prefix := SanitizeID(m.ID) + "__"
	for _, sc := range m.Scripts {
		names = append(names, prefix+SanitizeID(sc.Name))
	}
	return names
}

func execScript(ctx context.Context, sc ScriptDef, root string, args map[string]any, opts RunOptions) (string, error) {
	rawArgs, _ := args["args"].(string)
	stdin, _ := args["stdin"].(string)

	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	interpreter := pickInterpreter(sc.Path)
	cmdArgs := append([]string{}, interpreter[1:]...)
	cmdArgs = append(cmdArgs, sc.Path)
	if rawArgs != "" {
		cmdArgs = append(cmdArgs, splitShellArgs(rawArgs)...)
	}
	cmd := exec.CommandContext(cctx, interpreter[0], cmdArgs...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Env = append(cmd.Environ(),
		"CLAUDE_PLUGIN_ROOT="+root,
		"SKILL_ROOT="+root,
	)
	cmd.Dir = root

	out, err := cmd.CombinedOutput()
	res := truncate(string(out), opts.MaxOutputBytes)
	payload := map[string]any{
		"script": sc.Name,
		"path":   sc.Path,
		"output": res,
	}
	if cctx.Err() == context.DeadlineExceeded {
		payload["timeout"] = true
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	b, _ := json.Marshal(payload)
	if err != nil {
		return string(b), fmt.Errorf("script %s failed: %w", sc.Name, err)
	}
	return string(b), nil
}

func pickInterpreter(path string) []string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash":
		return []string{"bash"}
	case ".py":
		return []string{"python3"}
	case ".js":
		return []string{"node"}
	case ".rb":
		return []string{"ruby"}
	default:
		return []string{"sh"}
	}
}

func splitShellArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// SanitizeID lowercases s and replaces special characters with underscores.
func SanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "skill"
	}
	r := strings.NewReplacer(
		"-", "_",
		" ", "_",
		"/", "_",
		"\\", "_",
		":", "_",
		".", "_",
	)
	return r.Replace(s)
}
