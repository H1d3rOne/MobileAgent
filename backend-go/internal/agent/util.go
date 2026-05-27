package agent

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func readFile(p string) ([]byte, error) {
	return os.ReadFile(p)
}

func writeFile(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func listDir(p string) ([]map[string]any, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		info, _ := e.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		out = append(out, map[string]any{
			"name":  name,
			"isDir": e.IsDir(),
			"size":  size,
		})
	}
	return out, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func runCodeSearch(ctx context.Context, root, pattern string, exts map[string]bool, maxResults, maxBytes int) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex: %w", err)
	}
	const maxFileBytes = 2 * 1024 * 1024
	var b strings.Builder
	matches := 0
	filesScanned := 0
	truncated := false

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			name := d.Name()
			if name == "build" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !exts[ext] {
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > maxFileBytes {
			return nil
		}
		filesScanned++
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer f.Close()
		rel, _ := filepath.Rel(root, path)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			if !re.MatchString(line) {
				continue
			}
			matches++
			fmt.Fprintf(&b, "%s:%d: %s\n", rel, lineNo, truncate(line, 400))
			if matches >= maxResults {
				truncated = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll && ctx.Err() == nil {
		return "", err
	}

	header := fmt.Sprintf("matches=%d files_scanned=%d", matches, filesScanned)
	if truncated {
		header += " truncated=true"
	}
	out := header + "\n" + b.String()
	if maxBytes > 0 {
		out = truncate(out, maxBytes)
	}
	return out, nil
}

