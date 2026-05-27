package analyzer

import "time"

const (
	TypeManifest        = "manifest"
	TypeCertificate     = "certificate"
	TypeRisk            = "risk"
	TypeCode            = "code"
	TypeSDK             = "sdk"
	TypeAttackSurface   = "attack_surface"
	TypeEntryTrace      = "entry_trace"
	TypeTriage          = "triage"
	TypeRuntimePlan     = "runtime_plan"
	TypeReversePlan     = "reverse_plan"
		TypeRuntimeEvidence = "runtime_evidence"
)

type Component struct {
	Name                string         `json:"name"`
	Exported            *bool          `json:"exported,omitempty"`
	Permission          string         `json:"permission,omitempty"`
	ReadPermission      string         `json:"read_permission,omitempty"`
	WritePermission     string         `json:"write_permission,omitempty"`
	Authorities         []string       `json:"authorities,omitempty"`
	GrantURIPermissions bool           `json:"grant_uri_permissions,omitempty"`
	IsLauncher          bool           `json:"is_launcher,omitempty"`
	IntentFilters       []IntentFilter `json:"intent_filters,omitempty"`
}

type IntentFilter struct {
	Actions      []string `json:"actions,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	Schemes      []string `json:"schemes,omitempty"`
	Hosts        []string `json:"hosts,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	PathPatterns []string `json:"path_patterns,omitempty"`
	MimeTypes    []string `json:"mime_types,omitempty"`
	AutoVerify   bool     `json:"auto_verify,omitempty"`
}

type ManifestResult struct {
	Package              string      `json:"package"`
	VersionName          string      `json:"version_name"`
	VersionCode          int         `json:"version_code"`
	MinSDK               int         `json:"min_sdk"`
	TargetSDK            int         `json:"target_sdk"`
	Permissions          []string    `json:"permissions"`
	Activities           []Component `json:"activities"`
	Services             []Component `json:"services"`
	Receivers            []Component `json:"receivers"`
	Providers            []Component `json:"providers"`
	Debuggable           bool        `json:"debuggable"`
	AllowBackup          bool        `json:"allow_backup"`
	UsesCleartextTraffic bool        `json:"uses_cleartext_traffic"`
	NetworkSecurityCfg   string      `json:"network_security_config,omitempty"`
	LauncherActivity     string      `json:"launcher_activity,omitempty"`
}

type CertificateResult struct {
	SHA1       string    `json:"sha1,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	SerialHex  string    `json:"serial_hex,omitempty"`
	Algorithm  string    `json:"algorithm,omitempty"`
	Debug      bool      `json:"debug"`
	V1Verified bool      `json:"v1_verified,omitempty"`
	V2Verified bool      `json:"v2_verified,omitempty"`
	V3Verified bool      `json:"v3_verified,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	Raw        string    `json:"raw,omitempty"`
}

type Risk struct {
	Level       string `json:"level"`
	Code        string `json:"code"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

type RiskResult struct {
	Score float64 `json:"score"`
	Risks []Risk  `json:"risks"`
}

type CodeFinding struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

type CodeResult struct {
	Endpoints     []string      `json:"endpoints"`
	Secrets       []CodeFinding `json:"secrets"`
	DangerousAPIs []CodeFinding `json:"dangerous_apis"`
	FilesScanned  int           `json:"files_scanned"`
	Truncated     bool          `json:"truncated,omitempty"`
}

type SDK struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Match    string `json:"match"`
}

type SDKResult struct {
	SDKs []SDK `json:"sdks"`
}
