package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mobileagent/backend-go/internal/analyzer"
	"github.com/mobileagent/backend-go/internal/config"
	fridapkg "github.com/mobileagent/backend-go/internal/frida"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

// RegisterBuiltins wires the default device/apk/file/memory/shell/frida skills.
func RegisterBuiltins(r *Registry, adb *runner.ADBRunner, apk *runner.APKRunner, frida *runner.FridaRunner, agentStore *store.AgentStore, apkStore *store.APKStore, cfg *config.Config) {
	r.Register(deviceListSkill(adb))
	r.Register(deviceShellSkill(adb, cfg))
	r.Register(deviceScreenshotSkill(adb))
	r.Register(devicePackagesSkill(adb))
	r.Register(deviceInstallApkSkill(apk))
	r.Register(apkAnalyzeSkill(apk))
	r.Register(apkDecompileSkill(apk, cfg))
	r.Register(apkListSkill(apkStore))
	r.Register(fileReadSkill(cfg))
	r.Register(fileWriteSkill(cfg))
	r.Register(fileListSkill(cfg))
	r.Register(codeSearchSkill(cfg))
	r.Register(localShellSkill(cfg))
	r.Register(termuxShellSkill(cfg))
	r.Register(memorySaveSkill(agentStore))
	r.Register(memoryRecallSkill(agentStore))
	r.Register(fridaListProcessesSkill(frida))
	r.Register(fridaListAppsSkill(frida))
	r.Register(fridaHookSkill(frida, cfg))
	r.Register(fridaSnippetSkill(frida, cfg))
	r.Register(fridaSpawnSkill(frida, cfg))
	r.Register(fridaServerStatusSkill(frida, cfg))
	r.Register(fridaRunScriptSkill(frida, cfg))
	r.Register(fridaListScriptsSkill())
	r.Register(apkAntiDetectSkill(apkStore, cfg))
	r.Register(apkStringsSkill(apkStore, cfg))
	r.Register(apkCallGraphSkill(apkStore, cfg))
	r.Register(apkGenerateHooksSkill(apkStore, cfg))
}

// =========================================================================
// Helpers
// =========================================================================

func argString(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func argInt(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		}
	}
	return def
}

func truncate(s string, max int) string {
	if max > 0 && len(s) > max {
		return s[:max] + fmt.Sprintf("\n... [truncated %d bytes]", len(s)-max)
	}
	return s
}

// safeJoin: ensure target is inside base.
func safeJoin(base, rel string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("workspace base not configured")
	}
	abs, err := filepath.Abs(filepath.Join(base, rel))
	if err != nil {
		return "", err
	}
	baseAbs, _ := filepath.Abs(base)
	rp, err := filepath.Rel(baseAbs, abs)
	if err != nil || strings.HasPrefix(rp, "..") {
		return "", fmt.Errorf("path escapes workspace: %s", rel)
	}
	return abs, nil
}

// =========================================================================
// Device skills
// =========================================================================

func deviceListSkill(adb *runner.ADBRunner) Skill {
	return Skill{
		Name:        "device_list",
		Description: "List all connected Android devices (serial + adb status).",
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		Run: func(ctx context.Context, _ map[string]any) (string, error) {
			devices, err := adb.ListDevices()
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(devices)
			return string(b), nil
		},
	}
}

func deviceShellSkill(adb *runner.ADBRunner, cfg *config.Config) Skill {
	return Skill{
		Name:        "device_shell",
		Description: "Run an `adb shell` command on the given device serial. Returns stdout (and stderr).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":  map[string]any{"type": "string", "description": "Device serial (from device_list)."},
				"command": map[string]any{"type": "string", "description": "Shell command to execute."},
			},
			"required": []string{"serial", "command"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			cmd := argString(args, "command")
			if serial == "" || cmd == "" {
				return "", fmt.Errorf("serial and command are required")
			}
			out, err := adb.Shell(serial, cmd)
			if err != nil {
				return "", err
			}
			return truncate(out, cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func deviceScreenshotSkill(adb *runner.ADBRunner) Skill {
	return Skill{
		Name:        "device_screenshot",
		Description: "Capture a screenshot of the device. Returns local file path.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial": map[string]any{"type": "string"},
			},
			"required": []string{"serial"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			if serial == "" {
				return "", fmt.Errorf("serial required")
			}
			path, err := adb.Screenshot(serial)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"path":%q}`, path), nil
		},
	}
}

func devicePackagesSkill(adb *runner.ADBRunner) Skill {
	return Skill{
		Name:        "device_packages",
		Description: "List installed packages on a device. `filter` is an optional substring/flag passed to `pm list packages`.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial": map[string]any{"type": "string"},
				"filter": map[string]any{"type": "string"},
			},
			"required": []string{"serial"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			if serial == "" {
				return "", fmt.Errorf("serial required")
			}
			cmd := "pm list packages"
			if f := argString(args, "filter"); f != "" {
				cmd += " " + f
			}
			out, err := adb.Shell(serial, cmd)
			if err != nil {
				return "", err
			}
			return out, nil
		},
	}
}

func deviceInstallApkSkill(apk *runner.APKRunner) Skill {
	return Skill{
		Name:        "device_install_apk",
		Description: "Install an APK from a local path to the given device.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":   map[string]any{"type": "string"},
				"apk_path": map[string]any{"type": "string"},
			},
			"required": []string{"serial", "apk_path"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			apkPath := argString(args, "apk_path")
			if serial == "" || apkPath == "" {
				return "", fmt.Errorf("serial and apk_path required")
			}
			return apk.InstallToDevice(serial, apkPath)
		},
	}
}

// =========================================================================
// APK skills
// =========================================================================

func apkAnalyzeSkill(apk *runner.APKRunner) Skill {
	return Skill{
		Name:        "apk_analyze",
		Description: "Inspect an APK at the given path: package name, version, etc.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_path": map[string]any{"type": "string"},
			},
			"required": []string{"apk_path"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			path := argString(args, "apk_path")
			if path == "" {
				return "", fmt.Errorf("apk_path required")
			}
			a := &model.APK{ID: util.NewID(), FilePath: path}
			res, err := apk.Analyze(a)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(map[string]any{
				"package":     a.PackageName,
				"versionName": a.VersionName,
				"versionCode": a.VersionCode,
				"summary":     res.Result,
			})
			return string(b), nil
		},
	}
}

func apkDecompileSkill(apk *runner.APKRunner, cfg *config.Config) Skill {
	return Skill{
		Name:        "apk_decompile",
		Description: "Decompile an APK using apktool (default) or jadx. Returns the output directory.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_path": map[string]any{"type": "string"},
				"tool":     map[string]any{"type": "string", "enum": []string{"apktool", "jadx"}},
			},
			"required": []string{"apk_path"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			path := argString(args, "apk_path")
			if path == "" {
				return "", fmt.Errorf("apk_path required")
			}
			tool := argString(args, "tool")
			outDir := filepath.Join(cfg.Storage.WorkspaceDir, "decompiled", util.NewID()[:8])
			var err error
			if tool == "jadx" {
				_, err = apk.DecompileWithJADX(path, outDir)
			} else {
				_, err = apk.Decompile(path, outDir)
			}
			if err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"output_dir":%q}`, outDir), nil
		},
	}
}

func apkListSkill(apkStore *store.APKStore) Skill {
	return Skill{
		Name: "apk_list",
		Description: "List all uploaded APKs with their id, package name, version, file path, and decompiled output dir (if any). " +
			"Use this to discover what APKs exist and where their decompiled sources live before reading or searching code.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
		Run: func(ctx context.Context, _ map[string]any) (string, error) {
			if apkStore == nil {
				return "[]", nil
			}
			apks, err := apkStore.List()
			if err != nil {
				return "", err
			}
			out := make([]map[string]any, 0, len(apks))
			for _, a := range apks {
				out = append(out, map[string]any{
					"id":              a.ID,
					"filename":        a.Filename,
					"file_path":       a.FilePath,
					"package_name":    a.PackageName,
					"version_name":    a.VersionName,
					"version_code":    a.VersionCode,
					"decompiled_path": a.DecompiledPath,
					"decompiled_tool": a.DecompiledTool,
					"status":          a.Status,
				})
			}
			b, _ := json.Marshal(out)
			return string(b), nil
		},
	}
}

func codeSearchSkill(cfg *config.Config) Skill {
	return Skill{
		Name: "code_search",
		Description: "Recursively search a decompiled APK directory (or any workspace path) with a regex. " +
			"Returns matching lines as `file:line: content`. Default extensions: java, kt, smali, xml, json, properties, gradle. " +
			"Use this to find call sites, class names, URLs, crypto keys, intent actions, etc., across decompiled sources.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"dir":         map[string]any{"type": "string", "description": "Directory to search (use the decompiled_path from apk_list)."},
				"pattern":     map[string]any{"type": "string", "description": "Go regex (RE2). Use (?i) for case-insensitive."},
				"extensions":  map[string]any{"type": "string", "description": "Comma-separated extensions without dots (e.g. 'java,kt,smali'). Empty = defaults."},
				"max_results": map[string]any{"type": "integer", "description": "Max matches to return. Default 100."},
			},
			"required": []string{"dir", "pattern"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			dir := argString(args, "dir")
			pattern := argString(args, "pattern")
			if dir == "" || pattern == "" {
				return "", fmt.Errorf("dir and pattern required")
			}
			absDir, err := resolveSandbox(cfg, dir)
			if err != nil {
				return "", err
			}
			max := argInt(args, "max_results", 100)
			if max <= 0 || max > 1000 {
				max = 100
			}
			extList := strings.Split(argString(args, "extensions"), ",")
			exts := map[string]bool{}
			for _, e := range extList {
				e = strings.TrimSpace(strings.TrimPrefix(e, "."))
				if e != "" {
					exts["."+strings.ToLower(e)] = true
				}
			}
			if len(exts) == 0 {
				for _, e := range []string{".java", ".kt", ".smali", ".xml", ".json", ".properties", ".gradle", ".cfg", ".yaml", ".yml", ".txt"} {
					exts[e] = true
				}
			}
			return runCodeSearch(ctx, absDir, pattern, exts, max, cfg.Skills.ShellMaxOutputBytes)
		},
	}
}

// =========================================================================
// File skills (sandboxed to workspace + uploads)
// =========================================================================

func resolveSandbox(cfg *config.Config, p string) (string, error) {
	for _, base := range []string{cfg.Storage.WorkspaceDir, cfg.Storage.UploadDir} {
		if base == "" {
			continue
		}
		abs, err := safeJoin(base, p)
		if err == nil {
			return abs, nil
		}
	}
	// allow absolute paths that start with one of the bases
	abs, _ := filepath.Abs(p)
	for _, base := range []string{cfg.Storage.WorkspaceDir, cfg.Storage.UploadDir} {
		baseAbs, _ := filepath.Abs(base)
		if baseAbs != "" && strings.HasPrefix(abs, baseAbs+string(filepath.Separator)) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("path %q not within workspace or uploads", p)
}

func fileReadSkill(cfg *config.Config) Skill {
	return Skill{
		Name:        "file_read",
		Description: "Read a file from the workspace or uploads directory. Returns the text content (truncated).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
			"required": []string{"path"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			p, err := resolveSandbox(cfg, argString(args, "path"))
			if err != nil {
				return "", err
			}
			data, err := readFile(p)
			if err != nil {
				return "", err
			}
			return truncate(string(data), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func fileWriteSkill(cfg *config.Config) Skill {
	return Skill{
		Name:        "file_write",
		Description: "Write text content to a file in the workspace (overwrites). Creates parent dirs.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
			},
			"required": []string{"path", "content"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			p, err := safeJoin(cfg.Storage.WorkspaceDir, argString(args, "path"))
			if err != nil {
				return "", err
			}
			if err := writeFile(p, []byte(argString(args, "content"))); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"path":%q,"bytes":%d}`, p, len(argString(args, "content"))), nil
		},
	}
}

func fileListSkill(cfg *config.Config) Skill {
	return Skill{
		Name:        "file_list",
		Description: "List the contents of a directory under workspace or uploads.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			rel := argString(args, "path")
			if rel == "" {
				rel = "."
			}
			p, err := resolveSandbox(cfg, rel)
			if err != nil {
				return "", err
			}
			entries, err := listDir(p)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(entries)
			return string(b), nil
		},
	}
}

// =========================================================================
// Shell skills
// =========================================================================

func runShell(ctx context.Context, cfg *config.Config, command string) (string, error) {
	if command == "" {
		return "", fmt.Errorf("command required")
	}
	if !shellAllowed(cfg, command) {
		return "", fmt.Errorf("command not allowed by shell_allow_prefixes")
	}
	timeout := time.Duration(cfg.Skills.ShellTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	res := truncate(string(out), cfg.Skills.ShellMaxOutputBytes)
	if err != nil {
		return res, fmt.Errorf("shell exit: %w", err)
	}
	return res, nil
}

func shellAllowed(cfg *config.Config, cmd string) bool {
	if len(cfg.Skills.ShellAllowPrefixes) == 0 {
		return true
	}
	for _, p := range cfg.Skills.ShellAllowPrefixes {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return false
}

func localShellSkill(cfg *config.Config) Skill {
	return Skill{
		Name:        "local_shell",
		Description: "Execute a shell command on the host running the backend (sh -c). Output is truncated.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string"},
			},
			"required": []string{"command"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			return runShell(ctx, cfg, argString(args, "command"))
		},
	}
}

func termuxShellSkill(cfg *config.Config) Skill {
	return Skill{
		Name:        "termux_shell",
		Description: "When the backend runs inside Termux on Android, execute a Termux shell command. Otherwise returns an error.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string"},
			},
			"required": []string{"command"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			if !isTermux() {
				return "", fmt.Errorf("not running under Termux (host: %s/%s)", runtime.GOOS, runtime.GOARCH)
			}
			return runShell(ctx, cfg, argString(args, "command"))
		},
	}
}

// isTermux: heuristic check for Termux environment.
func isTermux() bool {
	// PREFIX is set by Termux to /data/data/com.termux/files/usr
	if p, _ := exec.LookPath("termux-info"); p != "" {
		return true
	}
	if p := envOr("PREFIX", ""); strings.Contains(p, "com.termux") {
		return true
	}
	return false
}

// =========================================================================
// Memory skills
// =========================================================================

func memorySaveSkill(s *store.AgentStore) Skill {
	return Skill{
		Name:        "memory_save",
		Description: "Persist a long-term note. `scope` is one of: global, session:<id>, device:<serial>.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"scope": map[string]any{"type": "string"},
				"key":   map[string]any{"type": "string"},
				"value": map[string]any{"type": "string"},
				"tags":  map[string]any{"type": "string", "description": "comma-separated tags"},
			},
			"required": []string{"key", "value"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			scope := argString(args, "scope")
			if scope == "" {
				scope = "global"
			}
			m := &model.AgentMemory{
				ID:    util.NewID(),
				Scope: scope,
				Key:   argString(args, "key"),
				Value: argString(args, "value"),
				Tags:  argString(args, "tags"),
			}
			if err := s.SaveMemory(m); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"id":%q}`, m.ID), nil
		},
	}
}

func memoryRecallSkill(s *store.AgentStore) Skill {
	return Skill{
		Name:        "memory_recall",
		Description: "Search long-term memory by substring across key/value/tags. Returns matching notes.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query":  map[string]any{"type": "string"},
				"scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"limit":  map[string]any{"type": "integer"},
			},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			query := argString(args, "query")
			limit := argInt(args, "limit", 10)
			var scopes []string
			if v, ok := args["scopes"]; ok {
				if arr, ok2 := v.([]any); ok2 {
					for _, x := range arr {
						if str, ok3 := x.(string); ok3 {
							scopes = append(scopes, str)
						}
					}
				}
			}
			rows, err := s.SearchMemory(scopes, query, limit)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(rows)
			return string(b), nil
		},
	}
}

// =========================================================================
// Frida skills
// =========================================================================

func fridaListProcessesSkill(frida *runner.FridaRunner) Skill {
	return Skill{
		Name:        "frida_list_processes",
		Description: "List running processes on the target device via Frida. Requires frida-server running on the device.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial": map[string]any{"type": "string", "description": "Device serial (from device_list)."},
			},
			"required": []string{"serial"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			if serial == "" {
				return "", fmt.Errorf("serial required")
			}
			return frida.ListProcesses(serial)
		},
	}
}

func fridaListAppsSkill(frida *runner.FridaRunner) Skill {
	return Skill{
		Name:        "frida_list_apps",
		Description: "List installed applications on the target device via Frida (includes package identifiers and PIDs for running apps).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial": map[string]any{"type": "string", "description": "Device serial."},
			},
			"required": []string{"serial"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			if serial == "" {
				return "", fmt.Errorf("serial required")
			}
			return frida.ListApps(serial)
		},
	}
}

func fridaHookSkill(frida *runner.FridaRunner, cfg *config.Config) Skill {
	return Skill{
		Name: "frida_hook",
		Description: "Inject a Frida JavaScript hook script into a running or spawned process. " +
			"Use this to intercept function calls, modify arguments/return values, trace crypto operations, bypass SSL pinning, etc. " +
			"The script runs for the specified timeout (default 30s) and returns captured output (console.log from the script).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":  map[string]any{"type": "string", "description": "Device serial."},
				"target":  map[string]any{"type": "string", "description": "Target process: package name (e.g. com.example.app) to spawn, or process name to attach."},
				"script":  map[string]any{"type": "string", "description": "Frida JavaScript code to inject."},
				"timeout": map[string]any{"type": "integer", "description": "Max seconds to run the hook (default 30, max 120)."},
			},
			"required": []string{"serial", "target", "script"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			target := argString(args, "target")
			script := argString(args, "script")
			if serial == "" || target == "" || script == "" {
				return "", fmt.Errorf("serial, target, and script are required")
			}
			timeout := time.Duration(argInt(args, "timeout", 30)) * time.Second
			if timeout > 120*time.Second {
				timeout = 120 * time.Second
			}
			out, err := frida.RunScript(ctx, serial, target, script, timeout)
			return truncate(out, cfg.Skills.ShellMaxOutputBytes), err
		},
	}
}

func fridaSnippetSkill(frida *runner.FridaRunner, cfg *config.Config) Skill {
	return Skill{
		Name: "frida_eval",
		Description: "Evaluate a short Frida JavaScript expression/snippet in a target process (uses frida -e). " +
			"Good for quick one-liners like enumerating loaded modules, reading memory, or calling a single method.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":  map[string]any{"type": "string", "description": "Device serial."},
				"target":  map[string]any{"type": "string", "description": "Target process name or package name."},
				"code":    map[string]any{"type": "string", "description": "JavaScript code to evaluate."},
				"timeout": map[string]any{"type": "integer", "description": "Max seconds (default 15)."},
			},
			"required": []string{"serial", "target", "code"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			target := argString(args, "target")
			code := argString(args, "code")
			if serial == "" || target == "" || code == "" {
				return "", fmt.Errorf("serial, target, and code are required")
			}
			timeout := time.Duration(argInt(args, "timeout", 15)) * time.Second
			if timeout > 60*time.Second {
				timeout = 60 * time.Second
			}
			out, err := frida.RunSnippet(ctx, serial, target, code, timeout)
			return truncate(out, cfg.Skills.ShellMaxOutputBytes), err
		},
	}
}

func fridaSpawnSkill(frida *runner.FridaRunner, cfg *config.Config) Skill {
	return Skill{
		Name: "frida_spawn",
		Description: "Spawn an app with Frida instrumentation from the very start (before any code runs). " +
			"This is essential for hooking early initialization, constructor methods, or anti-tamper checks that run at startup.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":  map[string]any{"type": "string", "description": "Device serial."},
				"package": map[string]any{"type": "string", "description": "Package name to spawn (e.g. com.example.app)."},
				"script":  map[string]any{"type": "string", "description": "Frida JavaScript code to inject at spawn."},
				"timeout": map[string]any{"type": "integer", "description": "Max seconds (default 30, max 120)."},
			},
			"required": []string{"serial", "package", "script"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			pkg := argString(args, "package")
			script := argString(args, "script")
			if serial == "" || pkg == "" || script == "" {
				return "", fmt.Errorf("serial, package, and script are required")
			}
			timeout := time.Duration(argInt(args, "timeout", 30)) * time.Second
			if timeout > 120*time.Second {
				timeout = 120 * time.Second
			}
			out, err := frida.SpawnAndHook(ctx, serial, pkg, script, timeout)
			return truncate(out, cfg.Skills.ShellMaxOutputBytes), err
		},
	}
}

func fridaServerStatusSkill(frida *runner.FridaRunner, cfg *config.Config) Skill {
	return Skill{
		Name:        "frida_server_status",
		Description: "Check if frida-server is running on the target device and report its version.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial": map[string]any{"type": "string", "description": "Device serial."},
			},
			"required": []string{"serial"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			if serial == "" {
				return "", fmt.Errorf("serial required")
			}
			_, err := frida.GetServerStatus(serial, cfg.ADB.Path)
			if err != nil {
				return err.Error(), nil
			}
			return `{"running":false}`, nil
		},
	}
}

func fridaRunScriptSkill(fr *runner.FridaRunner, cfg *config.Config) Skill {
	return Skill{
		Name: "frida_run_script",
		Description: "Run a pre-built Frida script from the built-in library on a target app. " +
			"Available scripts: ssl-pinning-bypass, root-detection-bypass, anti-frida-bypass, " +
			"emulator-detection-bypass, crypto-monitor, http-traffic-logger, shared-prefs-monitor, " +
			"activity-lifecycle, clipboard-monitor, intent-monitor, keystore-dump, dynamic-dex-loader. " +
			"Use frida_list_scripts to see all available scripts with descriptions.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"serial":    map[string]any{"type": "string", "description": "Device serial."},
				"target":    map[string]any{"type": "string", "description": "Target package name (e.g. com.example.app)."},
				"script_id": map[string]any{"type": "string", "description": "ID of the pre-built script to run."},
				"timeout":   map[string]any{"type": "integer", "description": "Max seconds to run (default 30, max 120)."},
			},
			"required": []string{"serial", "target", "script_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			serial := argString(args, "serial")
			target := argString(args, "target")
			scriptID := argString(args, "script_id")
			if serial == "" || target == "" || scriptID == "" {
				return "", fmt.Errorf("serial, target, and script_id are required")
			}
			script := fridapkg.GetScript(scriptID)
			if script == nil {
				return "", fmt.Errorf("unknown script: %s. Use frida_list_scripts to see available scripts", scriptID)
			}
			timeout := time.Duration(argInt(args, "timeout", 30)) * time.Second
			if timeout > 120*time.Second {
				timeout = 120 * time.Second
			}
			out, err := fr.RunScript(ctx, serial, target, script.Code, timeout)
			return truncate(out, cfg.Skills.ShellMaxOutputBytes), err
		},
	}
}

func fridaListScriptsSkill() Skill {
	return Skill{
		Name:        "frida_list_scripts",
		Description: "List all available pre-built Frida scripts in the library, optionally filtered by category.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": map[string]any{"type": "string", "description": "Filter by category (network, security, monitoring, crypto). Leave empty for all."},
			},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			category := argString(args, "category")
			var scripts []fridapkg.Script
			if category != "" {
				scripts = fridapkg.ListByCategory(category)
			} else {
				scripts = fridapkg.ListScripts()
			}
			type scriptInfo struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Category    string `json:"category"`
				Description string `json:"description"`
				Target      string `json:"target"`
			}
			infos := make([]scriptInfo, len(scripts))
			for i, s := range scripts {
				infos[i] = scriptInfo{ID: s.ID, Name: s.Name, Category: s.Category, Description: s.Description, Target: s.Target}
			}
			b, _ := json.Marshal(infos)
			return string(b), nil
		},
	}
}

func apkAntiDetectSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_anti_detect",
		Description: "Scan a decompiled APK for anti-analysis protections: root detection, frida detection, emulator detection, " +
			"debug detection, and tamper detection. Returns findings with file locations and a protection level assessment.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id": map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			apk, err := apkStore.Get(id)
			if err != nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			if apk.DecompiledPath == "" {
				return "", fmt.Errorf("APK must be decompiled first")
			}
			result, err := analyzer.DetectAntiDetection(apk.DecompiledPath)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(result)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkStringsSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_strings",
		Description: "Deep string and config extraction from a decompiled APK. Finds Firebase configs, classifies domains/IPs, " +
			"detects crypto algorithm usage (weak vs strong), and extracts cloud service configs (AWS, Azure, GCP).",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id": map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			apk, err := apkStore.Get(id)
			if err != nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			if apk.DecompiledPath == "" {
				return "", fmt.Errorf("APK must be decompiled first")
			}
			result, err := analyzer.ScanStrings(apk.DecompiledPath)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(result)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkCallGraphSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_callgraph",
		Description: "Build a method call graph from smali code. Identifies entry points, hot methods (high in/out degree), " +
			"and taint analysis paths (source→sink data flows). Optionally filter by package name for focused analysis.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id":  map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
				"package": map[string]any{"type": "string", "description": "Filter to a specific package (e.g. com.example.app). Empty = all."},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			apk, err := apkStore.Get(id)
			if err != nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			if apk.DecompiledPath == "" {
				return "", fmt.Errorf("APK must be decompiled first")
			}
			pkg := argString(args, "package")
			result, err := analyzer.BuildCallGraph(apk.DecompiledPath, pkg)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(result)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkGenerateHooksSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_generate_hooks",
		Description: "Auto-generate targeted Frida hook scripts based on analysis of the APK. Analyzes anti-detection patterns, " +
			"crypto usage, and Firebase config to produce ready-to-run bypass and monitoring hooks.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id": map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			apk, err := apkStore.Get(id)
			if err != nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			if apk.DecompiledPath == "" {
				return "", fmt.Errorf("APK must be decompiled first")
			}
			antiDetect, _ := analyzer.DetectAntiDetection(apk.DecompiledPath)
			stringsResult, _ := analyzer.ScanStrings(apk.DecompiledPath)
			var cryptoFindings []analyzer.CryptoFinding
			if stringsResult != nil {
				cryptoFindings = stringsResult.CryptoUsage
			}
			hooks := fridapkg.GenerateHooksFromAnalysis(antiDetect, cryptoFindings, stringsResult)
			b, _ := json.Marshal(hooks)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}
