package analyzer

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const TypeStrings = "strings"

type StringsResult struct {
	Firebase     *FirebaseConfig   `json:"firebase,omitempty"`
	Domains      []ClassifiedHost  `json:"domains,omitempty"`
	IPs          []ClassifiedIP    `json:"ips,omitempty"`
	CryptoUsage  []CryptoFinding   `json:"crypto_usage,omitempty"`
	Configs      []ConfigFinding   `json:"configs,omitempty"`
	FilesScanned int               `json:"files_scanned"`
}

type FirebaseConfig struct {
	ProjectID     string `json:"project_id,omitempty"`
	ProjectNumber string `json:"project_number,omitempty"`
	StorageBucket string `json:"storage_bucket,omitempty"`
	AppID         string `json:"app_id,omitempty"`
	APIKey        string `json:"api_key,omitempty"`
	DatabaseURL   string `json:"database_url,omitempty"`
	SenderID      string `json:"sender_id,omitempty"`
}

type ClassifiedHost struct {
	Host     string `json:"host"`
	Category string `json:"category"` // internal, cdn, cloud, analytics, ad, social, payment, unknown
	Source   string `json:"source"`
}

type ClassifiedIP struct {
	IP       string `json:"ip"`
	Category string `json:"category"` // private, loopback, public, multicast
	Source   string `json:"source"`
}

type CryptoFinding struct {
	Algorithm string `json:"algorithm"`
	Strength  string `json:"strength"` // weak, moderate, strong
	Context   string `json:"context"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type ConfigFinding struct {
	Type  string `json:"type"` // firebase, aws, azure, gcp, custom
	Key   string `json:"key"`
	Value string `json:"value"`
	File  string `json:"file"`
}

var (
	reIPv4       = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reDomainName = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:[a-z]{2,})(?:\.[a-z]{2,})?)\b`)
	reCryptoAlgo = regexp.MustCompile(`(?i)(DES|3DES|RC4|RC2|MD5|SHA-?1|SHA-?256|SHA-?384|SHA-?512|AES|RSA|ECDSA|ECDH|Blowfish|ChaCha20|PBKDF2|bcrypt|scrypt|argon2)`)
	reCryptoCall = regexp.MustCompile(`(?i)(Cipher\.getInstance|MessageDigest\.getInstance|KeyGenerator\.getInstance|SecretKeySpec|Mac\.getInstance|Signature\.getInstance|KeyPairGenerator\.getInstance)\s*\(\s*"([^"]+)"`)
)

var cdnDomains = []string{
	"cloudfront.net", "akamai", "fastly", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
	"unpkg.com", "cloudflare.com", "azureedge.net", "googleapis.com/storage",
}

var cloudDomains = []string{
	"amazonaws.com", "azure.com", "azure.net", "googleapis.com",
	"firebaseio.com", "firebase.google.com", "appspot.com",
	"digitalocean.com", "heroku.com", "vercel.app", "netlify.app",
}

var analyticsDomains = []string{
	"google-analytics.com", "analytics.google.com", "mixpanel.com",
	"segment.io", "amplitude.com", "flurry.com", "appsflyer.com",
	"adjust.com", "branch.io", "firebase.googleapis.com",
	"crashlytics.com", "bugsnag.com", "sentry.io",
}

var adDomains = []string{
	"admob.com", "doubleclick.net", "googlesyndication.com",
	"facebook.com/ads", "mopub.com", "unity3d.com/ads",
	"applovin.com", "vungle.com", "chartboost.com",
	"inmobi.com", "adcolony.com",
}

var socialDomains = []string{
	"facebook.com", "graph.facebook.com", "twitter.com", "api.twitter.com",
	"instagram.com", "linkedin.com", "weibo.com", "qq.com",
	"wechat.com", "line.me", "telegram.org",
}

var paymentDomains = []string{
	"stripe.com", "paypal.com", "braintree", "square.com",
	"alipay.com", "wxpay", "tenpay.com",
}

var weakCrypto = map[string]bool{
	"des": true, "3des": true, "rc4": true, "rc2": true,
	"md5": true, "sha1": true, "sha-1": true, "blowfish": true,
	"desede": true, "des/ecb": true, "des/cbc": true,
	"aes/ecb": true,
}

var strongCrypto = map[string]bool{
	"aes": true, "aes/gcm": true, "aes/cbc": true, "aes/ctr": true,
	"sha-256": true, "sha256": true, "sha-384": true, "sha384": true,
	"sha-512": true, "sha512": true, "rsa": true, "ecdsa": true,
	"ecdh": true, "chacha20": true, "pbkdf2": true, "bcrypt": true,
	"scrypt": true, "argon2": true,
}

func ScanStrings(decompiledDir string) (*StringsResult, error) {
	res := &StringsResult{}
	if decompiledDir == "" {
		return res, nil
	}

	res.Firebase = findFirebaseConfig(decompiledDir)

	domainSet := map[string]string{}
	ipSet := map[string]string{}
	scanned := 0

	_ = filepath.WalkDir(decompiledDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if scanned >= maxFilesScanned {
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

			for _, m := range reIPv4.FindAllString(line, -1) {
				if isValidIP(m) {
					ipSet[m] = rel
				}
			}

			for _, m := range reDomainName.FindAllString(line, 5) {
				if isLikelyDomain(m) {
					domainSet[m] = rel
				}
			}

			if matches := reCryptoCall.FindAllStringSubmatch(line, -1); len(matches) > 0 {
				for _, match := range matches {
					algo := match[2]
					res.CryptoUsage = append(res.CryptoUsage, CryptoFinding{
						Algorithm: algo,
						Strength:  classifyCryptoStrength(algo),
						Context:   trimValue(strings.TrimSpace(line)),
						File:      rel,
						Line:      lineNo,
					})
				}
			} else if m := reCryptoAlgo.FindString(line); m != "" {
				if strings.Contains(line, "Cipher") || strings.Contains(line, "Digest") ||
					strings.Contains(line, "encrypt") || strings.Contains(line, "decrypt") ||
					strings.Contains(line, "hash") || strings.Contains(line, "sign") {
					res.CryptoUsage = append(res.CryptoUsage, CryptoFinding{
						Algorithm: m,
						Strength:  classifyCryptoStrength(m),
						Context:   trimValue(strings.TrimSpace(line)),
						File:      rel,
						Line:      lineNo,
					})
				}
			}

			scanConfigLine(line, rel, res)
		}
		return nil
	})

	for host, src := range domainSet {
		res.Domains = append(res.Domains, ClassifiedHost{
			Host:     host,
			Category: classifyDomain(host),
			Source:   src,
		})
	}
	for ip, src := range ipSet {
		res.IPs = append(res.IPs, ClassifiedIP{
			IP:       ip,
			Category: classifyIP(ip),
			Source:   src,
		})
	}

	if len(res.Domains) > 200 {
		res.Domains = res.Domains[:200]
	}
	if len(res.IPs) > 100 {
		res.IPs = res.IPs[:100]
	}
	if len(res.CryptoUsage) > 200 {
		res.CryptoUsage = res.CryptoUsage[:200]
	}
	res.FilesScanned = scanned
	return res, nil
}

func findFirebaseConfig(dir string) *FirebaseConfig {
	candidates := []string{
		filepath.Join(dir, "assets", "google-services.json"),
		filepath.Join(dir, "res", "values", "strings.xml"),
	}

	for _, path := range candidates {
		if strings.HasSuffix(path, "google-services.json") {
			cfg := parseGoogleServicesJSON(path)
			if cfg != nil {
				return cfg
			}
		}
	}

	var fc *FirebaseConfig
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == "google-services.json" {
			fc = parseGoogleServicesJSON(path)
			if fc != nil {
				return filepath.SkipAll
			}
		}
		return nil
	})

	if fc == nil {
		fc = scanForFirebaseValues(dir)
	}
	return fc
}

func parseGoogleServicesJSON(path string) *FirebaseConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	fc := &FirebaseConfig{}
	if pi, ok := raw["project_info"].(map[string]any); ok {
		fc.ProjectID, _ = pi["project_id"].(string)
		fc.ProjectNumber, _ = pi["project_number"].(string)
		fc.StorageBucket, _ = pi["storage_bucket"].(string)
		fc.DatabaseURL, _ = pi["firebase_url"].(string)
	}

	if clients, ok := raw["client"].([]any); ok && len(clients) > 0 {
		if client, ok := clients[0].(map[string]any); ok {
			if ci, ok := client["client_info"].(map[string]any); ok {
				fc.AppID, _ = ci["mobilesdk_app_id"].(string)
			}
			if apiKeys, ok := client["api_key"].([]any); ok && len(apiKeys) > 0 {
				if ak, ok := apiKeys[0].(map[string]any); ok {
					fc.APIKey, _ = ak["current_key"].(string)
				}
			}
		}
	}

	if fc.ProjectID == "" && fc.AppID == "" {
		return nil
	}
	return fc
}

func scanForFirebaseValues(dir string) *FirebaseConfig {
	stringsPath := filepath.Join(dir, "res", "values", "strings.xml")
	data, err := os.ReadFile(stringsPath)
	if err != nil {
		return nil
	}
	content := string(data)

	fc := &FirebaseConfig{}
	fc.ProjectID = extractXMLString(content, "project_id")
	fc.APIKey = extractXMLString(content, "google_api_key")
	fc.AppID = extractXMLString(content, "google_app_id")
	fc.StorageBucket = extractXMLString(content, "google_storage_bucket")
	fc.DatabaseURL = extractXMLString(content, "firebase_database_url")
	fc.SenderID = extractXMLString(content, "gcm_defaultSenderId")

	if fc.ProjectID == "" && fc.AppID == "" && fc.APIKey == "" {
		return nil
	}
	return fc
}

var reXMLString = regexp.MustCompile(`<string name="([^"]+)">([^<]+)</string>`)

func extractXMLString(content, name string) string {
	for _, m := range reXMLString.FindAllStringSubmatch(content, -1) {
		if m[1] == name {
			return m[2]
		}
	}
	return ""
}

func isValidIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if s == "0.0.0.0" || s == "255.255.255.255" {
		return false
	}
	return true
}

func classifyIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return "unknown"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsMulticast() {
		return "multicast"
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "public"
}

func isLikelyDomain(s string) bool {
	s = strings.ToLower(s)
	if len(s) < 4 {
		return false
	}
	skipSuffixes := []string{".class", ".smali", ".java", ".kt", ".xml", ".png", ".jpg", ".gif", ".so"}
	for _, suf := range skipSuffixes {
		if strings.HasSuffix(s, suf) {
			return false
		}
	}
	skipPrefixes := []string{"com.android.", "android.", "java.", "javax.", "kotlin.", "org.w3c.", "org.xml."}
	for _, pre := range skipPrefixes {
		if strings.HasPrefix(s, pre) {
			return false
		}
	}
	if !strings.Contains(s, ".") {
		return false
	}
	parts := strings.Split(s, ".")
	tld := parts[len(parts)-1]
	validTLDs := map[string]bool{
		"com": true, "net": true, "org": true, "io": true, "co": true,
		"cn": true, "jp": true, "kr": true, "de": true, "fr": true,
		"uk": true, "ru": true, "in": true, "br": true, "app": true,
		"dev": true, "me": true, "tv": true, "cc": true, "us": true,
		"info": true, "biz": true, "xyz": true, "top": true,
	}
	return validTLDs[tld]
}

func classifyDomain(host string) string {
	low := strings.ToLower(host)
	for _, d := range cdnDomains {
		if strings.Contains(low, d) {
			return "cdn"
		}
	}
	for _, d := range analyticsDomains {
		if strings.Contains(low, d) {
			return "analytics"
		}
	}
	for _, d := range adDomains {
		if strings.Contains(low, d) {
			return "ad"
		}
	}
	for _, d := range socialDomains {
		if strings.Contains(low, d) {
			return "social"
		}
	}
	for _, d := range paymentDomains {
		if strings.Contains(low, d) {
			return "payment"
		}
	}
	for _, d := range cloudDomains {
		if strings.Contains(low, d) {
			return "cloud"
		}
	}
	if strings.Contains(low, "localhost") || strings.Contains(low, "internal") || strings.Contains(low, "local") {
		return "internal"
	}
	return "unknown"
}

func classifyCryptoStrength(algo string) string {
	low := strings.ToLower(strings.ReplaceAll(algo, " ", ""))
	low = strings.ReplaceAll(low, "/", "/")
	if weakCrypto[low] {
		return "weak"
	}
	if strongCrypto[low] {
		return "strong"
	}
	if strings.Contains(low, "ecb") {
		return "weak"
	}
	if strings.Contains(low, "gcm") || strings.Contains(low, "ctr") {
		return "strong"
	}
	return "moderate"
}

var (
	reAWSConfig   = regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|aws_region|aws_bucket)\s*[=:]\s*['"]?([^'"\s]+)`)
	reAzureConfig = regexp.MustCompile(`(?i)(azure_storage_account|azure_connection_string|azure_tenant_id)\s*[=:]\s*['"]?([^'"\s]+)`)
	reGCPConfig   = regexp.MustCompile(`(?i)(gcp_project|google_cloud_project|gcloud_project)\s*[=:]\s*['"]?([^'"\s]+)`)
)

func scanConfigLine(line, file string, res *StringsResult) {
	if m := reAWSConfig.FindStringSubmatch(line); len(m) == 3 {
		res.Configs = append(res.Configs, ConfigFinding{Type: "aws", Key: m[1], Value: maskValue(m[2]), File: file})
	}
	if m := reAzureConfig.FindStringSubmatch(line); len(m) == 3 {
		res.Configs = append(res.Configs, ConfigFinding{Type: "azure", Key: m[1], Value: maskValue(m[2]), File: file})
	}
	if m := reGCPConfig.FindStringSubmatch(line); len(m) == 3 {
		res.Configs = append(res.Configs, ConfigFinding{Type: "gcp", Key: m[1], Value: maskValue(m[2]), File: file})
	}
}

func maskValue(v string) string {
	if len(v) <= 8 {
		return v[:1] + "***"
	}
	return v[:4] + "***" + v[len(v)-4:]
}
