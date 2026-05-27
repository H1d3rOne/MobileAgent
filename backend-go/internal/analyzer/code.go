package analyzer

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxFilesScanned = 4000
const maxFileSize = 2 * 1024 * 1024

var (
	reURL          = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;%=\-]+`)
	reAWSKey       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGenericKey   = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|access[_-]?key|auth)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`)
	reJWT          = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	rePrivateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----`)
	reGoogleAPIKey = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
)

var dangerousAPIs = []string{
	"Runtime.getRuntime().exec",
	"DexClassLoader",
	"PathClassLoader",
	"setJavaScriptEnabled",
	"addJavascriptInterface",
	"setAllowFileAccess",
	"loadLibrary",
	"loadDex",
	"WebView",
	"setHostnameVerifier(ALLOW_ALL",
	"TrustAllCerts",
	"checkServerTrusted",
	"setWebContentsDebuggingEnabled",
	"MODE_WORLD_READABLE",
	"MODE_WORLD_WRITEABLE",
	"openFileOutput",
}

func ScanCode(decompiledDir string) (*CodeResult, error) {
	res := &CodeResult{}
	if decompiledDir == "" {
		return res, nil
	}
	endpoints := map[string]bool{}
	scanned := 0

	err := filepath.WalkDir(decompiledDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "build" || name == "kotlin" || strings.HasPrefix(name, ".") {
				return nil
			}
			return nil
		}
		if scanned >= maxFilesScanned {
			res.Truncated = true
			return filepath.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !isScannable(ext) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanned++
		rel, _ := filepath.Rel(decompiledDir, path)

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()

			for _, m := range reURL.FindAllString(line, -1) {
				if !shouldSkipURL(m) {
					endpoints[m] = true
				}
			}
			if m := reAWSKey.FindString(line); m != "" {
				res.Secrets = append(res.Secrets, CodeFinding{Kind: "aws_access_key", Pattern: "AKIA…", Value: m, File: rel, Line: lineNo})
			}
			if m := reGoogleAPIKey.FindString(line); m != "" {
				res.Secrets = append(res.Secrets, CodeFinding{Kind: "google_api_key", Pattern: "AIza…", Value: m, File: rel, Line: lineNo})
			}
			if m := reJWT.FindString(line); m != "" {
				res.Secrets = append(res.Secrets, CodeFinding{Kind: "jwt", Pattern: "JWT", Value: trimValue(m), File: rel, Line: lineNo})
			}
			if rePrivateKey.MatchString(line) {
				res.Secrets = append(res.Secrets, CodeFinding{Kind: "private_key", Pattern: "PEM", Value: line, File: rel, Line: lineNo})
			}
			for _, m := range reGenericKey.FindAllString(line, -1) {
				res.Secrets = append(res.Secrets, CodeFinding{Kind: "generic_credential", Pattern: "key=value", Value: trimValue(m), File: rel, Line: lineNo})
			}
			for _, api := range dangerousAPIs {
				if strings.Contains(line, api) {
					res.DangerousAPIs = append(res.DangerousAPIs, CodeFinding{Kind: "dangerous_api", Pattern: api, Value: trimValue(strings.TrimSpace(line)), File: rel, Line: lineNo})
				}
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	res.FilesScanned = scanned
	for ep := range endpoints {
		res.Endpoints = append(res.Endpoints, ep)
	}
	if len(res.Endpoints) > 500 {
		res.Endpoints = res.Endpoints[:500]
		res.Truncated = true
	}
	if len(res.Secrets) > 200 {
		res.Secrets = res.Secrets[:200]
		res.Truncated = true
	}
	if len(res.DangerousAPIs) > 500 {
		res.DangerousAPIs = res.DangerousAPIs[:500]
		res.Truncated = true
	}
	return res, nil
}

func isScannable(ext string) bool {
	switch ext {
	case ".java", ".kt", ".smali", ".xml", ".json", ".js", ".html", ".txt", ".properties", ".gradle", ".cfg", ".yaml", ".yml":
		return true
	}
	return false
}

func shouldSkipURL(u string) bool {
	low := strings.ToLower(u)
	for _, suffix := range []string{
		"w3.org", "schemas.android.com", "xmlns.jcp.org", "apache.org/xml",
	} {
		if strings.Contains(low, suffix) {
			return true
		}
	}
	return false
}

func trimValue(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
