package analyzer

import "strings"

var dangerousPermissions = map[string]bool{
	"android.permission.READ_SMS":              true,
	"android.permission.SEND_SMS":              true,
	"android.permission.RECEIVE_SMS":           true,
	"android.permission.READ_CONTACTS":         true,
	"android.permission.WRITE_CONTACTS":        true,
	"android.permission.READ_CALL_LOG":         true,
	"android.permission.WRITE_CALL_LOG":        true,
	"android.permission.RECORD_AUDIO":          true,
	"android.permission.CAMERA":                true,
	"android.permission.ACCESS_FINE_LOCATION":  true,
	"android.permission.ACCESS_BACKGROUND_LOCATION": true,
	"android.permission.READ_EXTERNAL_STORAGE": true,
	"android.permission.WRITE_EXTERNAL_STORAGE": true,
	"android.permission.SYSTEM_ALERT_WINDOW":   true,
	"android.permission.REQUEST_INSTALL_PACKAGES": true,
	"android.permission.PACKAGE_USAGE_STATS":   true,
	"android.permission.BIND_ACCESSIBILITY_SERVICE": true,
	"android.permission.BIND_DEVICE_ADMIN":     true,
}

func EvaluateRisk(m *ManifestResult, c *CertificateResult) *RiskResult {
	res := &RiskResult{}

	if m != nil {
		if m.Debuggable {
			res.Risks = append(res.Risks, Risk{
				Level: "high", Code: "MANIFEST_DEBUGGABLE",
				Title:       "Application is debuggable",
				Description: "android:debuggable=true allows attaching a debugger and exposes runtime internals. Should be false in production builds.",
			})
		}
		if m.AllowBackup {
			res.Risks = append(res.Risks, Risk{
				Level: "medium", Code: "MANIFEST_ALLOW_BACKUP",
				Title:       "Backup is allowed",
				Description: "android:allowBackup=true lets adb backup extract app data on debuggable devices.",
			})
		}
		if m.UsesCleartextTraffic {
			res.Risks = append(res.Risks, Risk{
				Level: "high", Code: "MANIFEST_CLEARTEXT_TRAFFIC",
				Title:       "Cleartext (HTTP) traffic enabled",
				Description: "android:usesCleartextTraffic=true permits plaintext HTTP, exposing data to MITM.",
			})
		}
		if m.MinSDK > 0 && m.MinSDK < 24 {
			res.Risks = append(res.Risks, Risk{
				Level: "medium", Code: "MANIFEST_LOW_MIN_SDK",
				Title:       "minSdkVersion < 24",
				Description: "Old Android versions miss key security mitigations (e.g. v2 signature default, Network Security Config).",
			})
		}
		dangerous := 0
		for _, p := range m.Permissions {
			if dangerousPermissions[p] {
				dangerous++
			}
		}
		if dangerous >= 5 {
			res.Risks = append(res.Risks, Risk{
				Level: "medium", Code: "PERM_MANY_DANGEROUS",
				Title:       "Many dangerous permissions",
				Description: "App requests several sensitive permissions; review necessity to limit attack surface.",
			})
		}
		exportedNoFilter := 0
		for _, list := range [][]Component{m.Activities, m.Services, m.Receivers, m.Providers} {
			for _, comp := range list {
				if comp.Exported != nil && *comp.Exported && len(comp.IntentFilters) == 0 {
					exportedNoFilter++
				}
			}
		}
		if exportedNoFilter > 0 {
			res.Risks = append(res.Risks, Risk{
				Level: "medium", Code: "EXPORTED_WITHOUT_FILTER",
				Title:       "Exported components without intent filter",
				Description: "Components exposed to other apps without intent filters can be abused if not properly guarded.",
			})
		}
	}

	if c != nil {
		if c.Debug || strings.Contains(strings.ToLower(c.Subject), "android debug") {
			res.Risks = append(res.Risks, Risk{
				Level: "high", Code: "CERT_DEBUG_KEY",
				Title:       "Signed with Android debug key",
				Description: "APK is signed with the well-known debug keystore. Not suitable for distribution.",
			})
		}
		if !c.V2Verified && !c.V3Verified && c.V1Verified {
			res.Risks = append(res.Risks, Risk{
				Level: "medium", Code: "CERT_V1_ONLY",
				Title:       "Only v1 (JAR) signature scheme",
				Description: "Only v1 signature scheme is verified, exposing the APK to Janus-style attacks. Use v2/v3.",
			})
		}
	}

	score := 0.0
	for _, r := range res.Risks {
		switch r.Level {
		case "high":
			score += 30
		case "medium":
			score += 15
		case "low":
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	res.Score = score
	return res
}
