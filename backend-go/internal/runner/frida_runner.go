package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mobileagent/backend-go/internal/config"
)

type FridaRunner struct {
	cfg *config.Config
}

func NewFridaRunner(cfg *config.Config) *FridaRunner {
	return &FridaRunner{cfg: cfg}
}

func (r *FridaRunner) fridaBin() string {
	if r.cfg.Tools.Frida != "" {
		return r.cfg.Tools.Frida
	}
	return "frida"
}

func (r *FridaRunner) IsAvailable() bool {
	_, err := exec.LookPath(r.fridaBin())
	return err == nil
}

func (r *FridaRunner) ListProcesses(serial string) (string, error) {
	args := []string{"-D", serial, "-ps", "-o", "json"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.fridaBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("frida-ps: %w\n%s", err, string(out))
	}
	return string(out), nil
}

func (r *FridaRunner) ListApps(serial string) (string, error) {
	args := []string{"-D", serial, "-ps", "-ai", "-o", "json"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.fridaBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("frida-ps: %w\n%s", err, string(out))
	}
	return string(out), nil
}

func (r *FridaRunner) RunScript(ctx context.Context, serial, target, script string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("frida_hook_%d.js", time.Now().UnixNano()))
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write script: %w", err)
	}
	defer os.Remove(scriptPath)

	args := []string{"-D", serial, "-l", scriptPath}
	if isPackageName(target) {
		args = append(args, "-f", target, "--no-pause")
	} else {
		args = append(args, "-n", target)
	}

	cmd := exec.CommandContext(cctx, r.fridaBin(), args...)
	out, err := cmd.CombinedOutput()
	result := string(out)
	if cctx.Err() == context.DeadlineExceeded {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("frida: %w\n%s", err, result)
	}
	return result, nil
}

func (r *FridaRunner) RunSnippet(ctx context.Context, serial, target, code string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-D", serial, "-e", code}
	if isPackageName(target) {
		args = append(args, "-f", target, "--no-pause")
	} else {
		args = append(args, "-n", target)
	}

	cmd := exec.CommandContext(cctx, r.fridaBin(), args...)
	out, err := cmd.CombinedOutput()
	result := string(out)
	if cctx.Err() == context.DeadlineExceeded {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("frida: %w\n%s", err, result)
	}
	return result, nil
}

func (r *FridaRunner) SpawnAndHook(ctx context.Context, serial, pkg, script string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("frida_spawn_%d.js", time.Now().UnixNano()))
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write script: %w", err)
	}
	defer os.Remove(scriptPath)

	args := []string{"-D", serial, "-f", pkg, "-l", scriptPath, "--no-pause"}
	cmd := exec.CommandContext(cctx, r.fridaBin(), args...)
	out, err := cmd.CombinedOutput()
	result := string(out)
	if cctx.Err() == context.DeadlineExceeded {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("frida: %w\n%s", err, result)
	}
	return result, nil
}

func (r *FridaRunner) GetServerStatus(serial string, adbPath string) (map[string]any, error) {
	if adbPath == "" {
		adbPath = "adb"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, adbPath, "-s", serial, "shell", "ps -A | grep frida-server")
	out, err := cmd.CombinedOutput()
	running := err == nil && strings.Contains(string(out), "frida-server")

	result := map[string]any{
		"running": running,
		"output":  strings.TrimSpace(string(out)),
	}

	if running {
		cmd2 := exec.CommandContext(ctx, adbPath, "-s", serial, "shell", "frida-server --version 2>/dev/null || echo unknown")
		ver, _ := cmd2.CombinedOutput()
		result["version"] = strings.TrimSpace(string(ver))
	}

	b, _ := json.Marshal(result)
	return result, fmt.Errorf("%s", string(b))
}

func isPackageName(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, " ")
}
