package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultAllowedCommands is the default whitelist of command binaries that are
// permitted to run via the /tools/run endpoint.
var DefaultAllowedCommands = []string{
	"apktool", "jadx", "r2", "androguard", "androaxml",
	"aapt", "aapt2", "adb", "frida", "objection",
	"mitmdump", "mitmproxy", "mitmweb",
	"dex2jar", "d2j-dex2jar", "jarsigner", "apksigner", "zipalign", "keytool",
	"file", "strings", "grep", "find", "ls", "cat", "head", "tail",
	"wc", "sha256sum", "md5sum", "xxd", "hexdump",
}

// Checker validates commands against a whitelist of allowed binaries.
type Checker struct {
	allowed map[string]bool
}

// NewChecker creates a Checker from the given list of allowed command names.
// If the list is nil, DefaultAllowedCommands is used.
func NewChecker(allowedCommands []string) *Checker {
	if allowedCommands == nil {
		allowedCommands = DefaultAllowedCommands
	}
	m := make(map[string]bool, len(allowedCommands))
	for _, cmd := range allowedCommands {
		m[strings.TrimSpace(cmd)] = true
	}
	return &Checker{allowed: m}
}

// Validate checks whether the given shell command string is allowed.
// It extracts the first token (the binary name) and checks it against the whitelist.
// Returns nil if allowed, or an error describing why the command was rejected.
func (ch *Checker) Validate(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("empty command")
	}

	// Extract the first token from the command string.
	// Handle common shell patterns: env vars, sudo, path prefixes.
	binary := extractBinary(command)
	if binary == "" {
		return fmt.Errorf("could not determine command binary from: %q", command)
	}

	// Strip path to get just the binary name (e.g. /usr/bin/grep -> grep)
	base := filepath.Base(binary)

	if !ch.allowed[base] {
		return fmt.Errorf("command %q is not in the allowed commands whitelist", base)
	}
	return nil
}

// IsAllowed is a convenience method that returns true if the command passes validation.
func (ch *Checker) IsAllowed(command string) bool {
	return ch.Validate(command) == nil
}

// extractBinary parses the first meaningful binary name from a shell command string.
// It skips leading environment variable assignments (FOO=bar) and common wrappers.
func extractBinary(command string) string {
	// Split on spaces/tabs to get tokens
	tokens := strings.Fields(command)
	for _, tok := range tokens {
		// Skip environment variable assignments (e.g. PATH=/foo:$PATH)
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") {
			continue
		}
		// Skip shell operators that might appear at the start
		if tok == "&&" || tok == "||" || tok == "|" || tok == ";" {
			break // stop at pipe/chain — only validate the first command
		}
		return tok
	}
	return ""
}
