package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const TypeReport = "report"

type ReportSection struct {
	Title    string `json:"title"`
	Status   string `json:"status"` // pass, warn, fail, info
	Summary  string `json:"summary"`
	Details  []string `json:"details,omitempty"`
	Category string `json:"category"` // MASVS category
}

type SecurityReport struct {
	GeneratedAt   time.Time       `json:"generated_at"`
	Package       string          `json:"package"`
	Version       string          `json:"version"`
	OverallScore  float64         `json:"overall_score"`  // 0-100, higher = more secure
	RiskLevel     string          `json:"risk_level"`     // critical, high, medium, low
	Sections      []ReportSection `json:"sections"`
	Statistics    ReportStats     `json:"statistics"`
	Manifest      *ManifestResult     `json:"manifest,omitempty"`
	Certificate   *CertificateResult  `json:"certificate,omitempty"`
	CodeFindings  *CodeResult         `json:"code_findings,omitempty"`
	SDKs          *SDKResult          `json:"sdks,omitempty"`
	Risks         *RiskResult         `json:"risks,omitempty"`
	Packer        *PackerResult       `json:"packer,omitempty"`
}

type ReportStats struct {
	TotalPermissions    int `json:"total_permissions"`
	DangerousPerms      int `json:"dangerous_permissions"`
	ExportedComponents  int `json:"exported_components"`
	SecretsFound        int `json:"secrets_found"`
	DangerousAPIs       int `json:"dangerous_apis"`
	Endpoints           int `json:"endpoints"`
	SDKCount            int `json:"sdk_count"`
	HighRisks           int `json:"high_risks"`
	MediumRisks         int `json:"medium_risks"`
	LowRisks            int `json:"low_risks"`
}

func GenerateReport(apkPath, decompiledPath string) (*SecurityReport, error) {
	report := &SecurityReport{
		GeneratedAt: time.Now(),
	}

	manifest, _ := ParseManifest(apkPath)
	report.Manifest = manifest

	cert, _ := ParseCertificate(apkPath)
	report.Certificate = cert

	var code *CodeResult
	if decompiledPath != "" {
		code, _ = ScanCode(decompiledPath)
		report.CodeFindings = code
	}

	var sdks *SDKResult
	if decompiledPath != "" {
		sdks, _ = DetectSDKs(decompiledPath)
		report.SDKs = sdks
	}

	risk := EvaluateRisk(manifest, cert)
	report.Risks = risk

	var packer *PackerResult
	if decompiledPath != "" {
		packer, _ = DetectPacker(apkPath, decompiledPath)
		report.Packer = packer
	}

	if manifest != nil {
		report.Package = manifest.Package
		report.Version = manifest.VersionName
	}

	report.Sections = buildSections(manifest, cert, code, sdks, risk, packer)
	report.Statistics = buildStats(manifest, cert, code, sdks, risk)
	report.OverallScore = calculateScore(report.Statistics, report.Sections)
	report.RiskLevel = scoreToLevel(report.OverallScore)

	return report, nil
}

func buildSections(m *ManifestResult, c *CertificateResult, code *CodeResult, sdks *SDKResult, risk *RiskResult, packer *PackerResult) []ReportSection {
	var sections []ReportSection

	// MASVS-STORAGE: Data Storage
	sections = append(sections, evaluateStorage(m, code)...)

	// MASVS-CRYPTO: Cryptography
	sections = append(sections, evaluateCrypto(code)...)

	// MASVS-AUTH: Authentication (limited without dynamic analysis)
	sections = append(sections, evaluateAuth(code)...)

	// MASVS-NETWORK: Network Communication
	sections = append(sections, evaluateNetwork(m, code)...)

	// MASVS-PLATFORM: Platform Interaction
	sections = append(sections, evaluatePlatform(m)...)

	// MASVS-CODE: Code Quality
	sections = append(sections, evaluateCodeQuality(m, c, code)...)

	// MASVS-RESILIENCE: Reverse Engineering Resilience
	sections = append(sections, evaluateResilience(m, code, sdks)...)

	// MASVS-RESILIENCE: Packer/Protection Detection
	sections = append(sections, evaluatePacker(packer)...)

	return sections
}

func evaluateStorage(m *ManifestResult, code *CodeResult) []ReportSection {
	var sections []ReportSection

	if m != nil && m.AllowBackup {
		sections = append(sections, ReportSection{
			Title:    "Backup Allowed",
			Status:   "fail",
			Summary:  "Application data can be extracted via adb backup",
			Details:  []string{"Set android:allowBackup=\"false\" in AndroidManifest.xml"},
			Category: "MASVS-STORAGE",
		})
	} else if m != nil {
		sections = append(sections, ReportSection{
			Title:    "Backup Disabled",
			Status:   "pass",
			Summary:  "Application backup is properly disabled",
			Category: "MASVS-STORAGE",
		})
	}

	if code != nil && len(code.Secrets) > 0 {
		details := make([]string, 0, min(len(code.Secrets), 10))
		for i, s := range code.Secrets {
			if i >= 10 {
				details = append(details, fmt.Sprintf("... and %d more", len(code.Secrets)-10))
				break
			}
			details = append(details, fmt.Sprintf("[%s] %s:%d", s.Kind, s.File, s.Line))
		}
		sections = append(sections, ReportSection{
			Title:    "Hardcoded Secrets",
			Status:   "fail",
			Summary:  fmt.Sprintf("Found %d hardcoded credentials/keys in source", len(code.Secrets)),
			Details:  details,
			Category: "MASVS-STORAGE",
		})
	} else {
		sections = append(sections, ReportSection{
			Title:    "No Hardcoded Secrets",
			Status:   "pass",
			Summary:  "No obvious hardcoded credentials detected",
			Category: "MASVS-STORAGE",
		})
	}

	if code != nil {
		worldReadable := 0
		for _, api := range code.DangerousAPIs {
			if strings.Contains(api.Pattern, "MODE_WORLD_READABLE") || strings.Contains(api.Pattern, "MODE_WORLD_WRITEABLE") {
				worldReadable++
			}
		}
		if worldReadable > 0 {
			sections = append(sections, ReportSection{
				Title:    "World-Readable/Writable Files",
				Status:   "fail",
				Summary:  fmt.Sprintf("%d instances of world-accessible file operations", worldReadable),
				Category: "MASVS-STORAGE",
			})
		}
	}

	return sections
}

func evaluateCrypto(code *CodeResult) []ReportSection {
	var sections []ReportSection

	if code == nil {
		return sections
	}

	weakCrypto := 0
	for _, api := range code.DangerousAPIs {
		val := strings.ToLower(api.Value)
		if strings.Contains(val, "des") || strings.Contains(val, "ecb") || strings.Contains(val, "md5") {
			weakCrypto++
		}
	}

	if weakCrypto > 0 {
		sections = append(sections, ReportSection{
			Title:    "Weak Cryptography",
			Status:   "warn",
			Summary:  fmt.Sprintf("Detected %d potential uses of weak crypto (DES/ECB/MD5)", weakCrypto),
			Category: "MASVS-CRYPTO",
		})
	} else {
		sections = append(sections, ReportSection{
			Title:    "Cryptography",
			Status:   "info",
			Summary:  "No obvious weak cryptography detected (deeper analysis recommended)",
			Category: "MASVS-CRYPTO",
		})
	}

	return sections
}

func evaluateAuth(code *CodeResult) []ReportSection {
	var sections []ReportSection

	if code == nil {
		return sections
	}

	webviewIssues := 0
	for _, api := range code.DangerousAPIs {
		if strings.Contains(api.Pattern, "setJavaScriptEnabled") || strings.Contains(api.Pattern, "addJavascriptInterface") {
			webviewIssues++
		}
	}

	if webviewIssues > 0 {
		sections = append(sections, ReportSection{
			Title:    "WebView JavaScript Enabled",
			Status:   "warn",
			Summary:  fmt.Sprintf("%d WebView instances with JavaScript enabled — potential XSS vector", webviewIssues),
			Category: "MASVS-AUTH",
		})
	}

	return sections
}

func evaluateNetwork(m *ManifestResult, code *CodeResult) []ReportSection {
	var sections []ReportSection

	if m != nil && m.UsesCleartextTraffic {
		sections = append(sections, ReportSection{
			Title:    "Cleartext Traffic Allowed",
			Status:   "fail",
			Summary:  "App permits unencrypted HTTP connections",
			Details:  []string{"Set android:usesCleartextTraffic=\"false\"", "Implement Network Security Config for exceptions"},
			Category: "MASVS-NETWORK",
		})
	} else if m != nil {
		sections = append(sections, ReportSection{
			Title:    "Cleartext Traffic Blocked",
			Status:   "pass",
			Summary:  "App does not allow cleartext HTTP traffic",
			Category: "MASVS-NETWORK",
		})
	}

	if code != nil {
		sslBypass := 0
		for _, api := range code.DangerousAPIs {
			if strings.Contains(api.Pattern, "TrustAllCerts") ||
				strings.Contains(api.Pattern, "checkServerTrusted") ||
				strings.Contains(api.Pattern, "ALLOW_ALL") {
				sslBypass++
			}
		}
		if sslBypass > 0 {
			sections = append(sections, ReportSection{
				Title:    "SSL/TLS Validation Bypass",
				Status:   "fail",
				Summary:  fmt.Sprintf("%d instances of certificate validation bypass", sslBypass),
				Details:  []string{"Remove custom TrustManagers that accept all certificates", "Do not use ALLOW_ALL hostname verifiers"},
				Category: "MASVS-NETWORK",
			})
		}
	}

	if m != nil && m.NetworkSecurityCfg != "" {
		sections = append(sections, ReportSection{
			Title:    "Network Security Config",
			Status:   "pass",
			Summary:  "App uses Network Security Configuration",
			Category: "MASVS-NETWORK",
		})
	}

	return sections
}

func evaluatePlatform(m *ManifestResult) []ReportSection {
	var sections []ReportSection

	if m == nil {
		return sections
	}

	exported := 0
	exportedNoFilter := 0
	for _, list := range [][]Component{m.Activities, m.Services, m.Receivers, m.Providers} {
		for _, comp := range list {
			if comp.Exported != nil && *comp.Exported {
				exported++
				if len(comp.IntentFilters) == 0 {
					exportedNoFilter++
				}
			}
		}
	}

	if exportedNoFilter > 0 {
		sections = append(sections, ReportSection{
			Title:    "Unprotected Exported Components",
			Status:   "fail",
			Summary:  fmt.Sprintf("%d exported components without intent filters (attack surface)", exportedNoFilter),
			Details:  []string{"Add permission checks or remove android:exported=\"true\""},
			Category: "MASVS-PLATFORM",
		})
	}

	if exported > 0 {
		sections = append(sections, ReportSection{
			Title:    "Exported Components",
			Status:   "info",
			Summary:  fmt.Sprintf("%d total exported components", exported),
			Category: "MASVS-PLATFORM",
		})
	}

	dangerous := 0
	var dangerousList []string
	for _, p := range m.Permissions {
		if dangerousPermissions[p] {
			dangerous++
			short := p
			if idx := strings.LastIndex(p, "."); idx >= 0 {
				short = p[idx+1:]
			}
			dangerousList = append(dangerousList, short)
		}
	}

	if dangerous >= 5 {
		sections = append(sections, ReportSection{
			Title:    "Excessive Dangerous Permissions",
			Status:   "warn",
			Summary:  fmt.Sprintf("%d dangerous permissions requested", dangerous),
			Details:  dangerousList,
			Category: "MASVS-PLATFORM",
		})
	} else if dangerous > 0 {
		sections = append(sections, ReportSection{
			Title:    "Dangerous Permissions",
			Status:   "info",
			Summary:  fmt.Sprintf("%d dangerous permissions requested", dangerous),
			Details:  dangerousList,
			Category: "MASVS-PLATFORM",
		})
	}

	return sections
}

func evaluateCodeQuality(m *ManifestResult, c *CertificateResult, code *CodeResult) []ReportSection {
	var sections []ReportSection

	if m != nil && m.Debuggable {
		sections = append(sections, ReportSection{
			Title:    "Debuggable Application",
			Status:   "fail",
			Summary:  "App is debuggable — allows runtime inspection and data extraction",
			Details:  []string{"Set android:debuggable=\"false\" for release builds"},
			Category: "MASVS-CODE",
		})
	} else if m != nil {
		sections = append(sections, ReportSection{
			Title:    "Not Debuggable",
			Status:   "pass",
			Summary:  "Application is not debuggable",
			Category: "MASVS-CODE",
		})
	}

	if c != nil {
		if c.Debug {
			sections = append(sections, ReportSection{
				Title:    "Debug Certificate",
				Status:   "fail",
				Summary:  "Signed with Android debug key — not suitable for distribution",
				Category: "MASVS-CODE",
			})
		}
		if !c.V2Verified && !c.V3Verified {
			sections = append(sections, ReportSection{
				Title:    "Weak Signature Scheme",
				Status:   "warn",
				Summary:  "Only v1 (JAR) signature — vulnerable to Janus-style attacks",
				Details:  []string{"Use apksigner with --v2-signing-enabled and --v3-signing-enabled"},
				Category: "MASVS-CODE",
			})
		} else {
			scheme := "v2"
			if c.V3Verified {
				scheme = "v3"
			}
			sections = append(sections, ReportSection{
				Title:    "Strong Signature Scheme",
				Status:   "pass",
				Summary:  fmt.Sprintf("APK uses %s signature scheme", scheme),
				Category: "MASVS-CODE",
			})
		}
	}

	if m != nil && m.MinSDK > 0 && m.MinSDK < 24 {
		sections = append(sections, ReportSection{
			Title:    "Low Minimum SDK",
			Status:   "warn",
			Summary:  fmt.Sprintf("minSdkVersion=%d — misses security features from API 24+", m.MinSDK),
			Category: "MASVS-CODE",
		})
	}

	if code != nil {
		dynLoad := 0
		for _, api := range code.DangerousAPIs {
			if strings.Contains(api.Pattern, "DexClassLoader") || strings.Contains(api.Pattern, "loadDex") {
				dynLoad++
			}
		}
		if dynLoad > 0 {
			sections = append(sections, ReportSection{
				Title:    "Dynamic Code Loading",
				Status:   "warn",
				Summary:  fmt.Sprintf("%d instances of dynamic DEX loading", dynLoad),
				Details:  []string{"Dynamic code loading can be used to hide malicious behavior"},
				Category: "MASVS-CODE",
			})
		}
	}

	return sections
}

func evaluateResilience(m *ManifestResult, code *CodeResult, sdks *SDKResult) []ReportSection {
	var sections []ReportSection

	hasObfuscation := false
	if sdks != nil {
		for _, sdk := range sdks.SDKs {
			if strings.Contains(strings.ToLower(sdk.Name), "proguard") ||
				strings.Contains(strings.ToLower(sdk.Name), "dexguard") ||
				strings.Contains(strings.ToLower(sdk.Name), "r8") {
				hasObfuscation = true
				break
			}
		}
	}

	if !hasObfuscation {
		sections = append(sections, ReportSection{
			Title:    "No Obfuscation Detected",
			Status:   "info",
			Summary:  "No code obfuscation tool detected (ProGuard/R8/DexGuard)",
			Details:  []string{"Consider enabling R8/ProGuard for release builds"},
			Category: "MASVS-RESILIENCE",
		})
	}

	if code != nil {
		execCalls := 0
		for _, api := range code.DangerousAPIs {
			if strings.Contains(api.Pattern, "Runtime.getRuntime().exec") {
				execCalls++
			}
		}
		if execCalls > 0 {
			sections = append(sections, ReportSection{
				Title:    "Shell Command Execution",
				Status:   "warn",
				Summary:  fmt.Sprintf("%d instances of Runtime.exec() — potential root/tamper detection or command injection", execCalls),
				Category: "MASVS-RESILIENCE",
			})
		}
	}

	return sections
}

func evaluatePacker(packer *PackerResult) []ReportSection {
	var sections []ReportSection

	if packer == nil {
		return sections
	}

	if packer.HasPacker {
		details := make([]string, 0, len(packer.Detected))
		for _, d := range packer.Detected {
			details = append(details, fmt.Sprintf("%s (%s) — confidence: %s", d.Name, d.Vendor, d.Confidence))
		}
		details = append(details, packer.Suggestions...)
		sections = append(sections, ReportSection{
			Title:    "App Protection Detected",
			Status:   "info",
			Summary:  fmt.Sprintf("%d packer/protector(s) detected — runtime unpacking may be required", len(packer.Detected)),
			Details:  details,
			Category: "MASVS-RESILIENCE",
		})
	} else {
		sections = append(sections, ReportSection{
			Title:    "No Packer Detected",
			Status:   "info",
			Summary:  "No known app protector/packer signatures found",
			Category: "MASVS-RESILIENCE",
		})
	}

	if packer.MultiDex {
		sections = append(sections, ReportSection{
			Title:    "Multi-DEX",
			Status:   "info",
			Summary:  fmt.Sprintf("APK contains %d DEX files", packer.DexCount),
			Category: "MASVS-RESILIENCE",
		})
	}

	return sections
}

func buildStats(m *ManifestResult, c *CertificateResult, code *CodeResult, sdks *SDKResult, risk *RiskResult) ReportStats {
	stats := ReportStats{}

	if m != nil {
		stats.TotalPermissions = len(m.Permissions)
		for _, p := range m.Permissions {
			if dangerousPermissions[p] {
				stats.DangerousPerms++
			}
		}
		for _, list := range [][]Component{m.Activities, m.Services, m.Receivers, m.Providers} {
			for _, comp := range list {
				if comp.Exported != nil && *comp.Exported {
					stats.ExportedComponents++
				}
			}
		}
	}

	if code != nil {
		stats.SecretsFound = len(code.Secrets)
		stats.DangerousAPIs = len(code.DangerousAPIs)
		stats.Endpoints = len(code.Endpoints)
	}

	if sdks != nil {
		stats.SDKCount = len(sdks.SDKs)
	}

	if risk != nil {
		for _, r := range risk.Risks {
			switch r.Level {
			case "high":
				stats.HighRisks++
			case "medium":
				stats.MediumRisks++
			case "low":
				stats.LowRisks++
			}
		}
	}

	return stats
}

func calculateScore(stats ReportStats, sections []ReportSection) float64 {
	score := 100.0

	for _, s := range sections {
		switch s.Status {
		case "fail":
			score -= 15
		case "warn":
			score -= 7
		}
	}

	score -= float64(stats.SecretsFound) * 5
	if score < 0 {
		score = 0
	}
	return score
}

func scoreToLevel(score float64) string {
	switch {
	case score >= 80:
		return "low"
	case score >= 60:
		return "medium"
	case score >= 40:
		return "high"
	default:
		return "critical"
	}
}

func FormatReportText(r *SecurityReport) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Security Report: %s v%s\n", r.Package, r.Version))
	b.WriteString(fmt.Sprintf("Generated: %s\n", r.GeneratedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("Overall Score: %.0f/100 (%s risk)\n\n", r.OverallScore, strings.ToUpper(r.RiskLevel)))

	b.WriteString("## Summary\n")
	b.WriteString(fmt.Sprintf("- Permissions: %d total, %d dangerous\n", r.Statistics.TotalPermissions, r.Statistics.DangerousPerms))
	b.WriteString(fmt.Sprintf("- Exported components: %d\n", r.Statistics.ExportedComponents))
	b.WriteString(fmt.Sprintf("- Hardcoded secrets: %d\n", r.Statistics.SecretsFound))
	b.WriteString(fmt.Sprintf("- Dangerous API calls: %d\n", r.Statistics.DangerousAPIs))
	b.WriteString(fmt.Sprintf("- Network endpoints: %d\n", r.Statistics.Endpoints))
	b.WriteString(fmt.Sprintf("- Third-party SDKs: %d\n", r.Statistics.SDKCount))
	b.WriteString(fmt.Sprintf("- Risks: %d high, %d medium, %d low\n\n", r.Statistics.HighRisks, r.Statistics.MediumRisks, r.Statistics.LowRisks))

	categories := []string{"MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK", "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE"}
	for _, cat := range categories {
		catSections := filterByCategory(r.Sections, cat)
		if len(catSections) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s\n", cat))
		for _, s := range catSections {
			icon := statusIcon(s.Status)
			b.WriteString(fmt.Sprintf("%s %s — %s\n", icon, s.Title, s.Summary))
			for _, d := range s.Details {
				b.WriteString(fmt.Sprintf("    • %s\n", d))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func filterByCategory(sections []ReportSection, cat string) []ReportSection {
	var out []ReportSection
	for _, s := range sections {
		if s.Category == cat {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		order := map[string]int{"fail": 0, "warn": 1, "info": 2, "pass": 3}
		return order[out[i].Status] < order[out[j].Status]
	})
	return out
}

func statusIcon(status string) string {
	switch status {
	case "pass":
		return "[PASS]"
	case "warn":
		return "[WARN]"
	case "fail":
		return "[FAIL]"
	default:
		return "[INFO]"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
