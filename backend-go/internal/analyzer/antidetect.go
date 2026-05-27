package analyzer

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	TypeAntiDetect       = "antidetect"
	TypeAntiDetectLegacy = "anti_detect"
)

type AntiDetectResult struct {
	RootDetection     []DetectionFinding `json:"root_detection,omitempty"`
	FridaDetection    []DetectionFinding `json:"frida_detection,omitempty"`
	EmulatorDetection []DetectionFinding `json:"emulator_detection,omitempty"`
	DebugDetection    []DetectionFinding `json:"debug_detection,omitempty"`
	TamperDetection   []DetectionFinding `json:"tamper_detection,omitempty"`
	Summary           DetectionSummary   `json:"summary"`
}

type DetectionFinding struct {
	Pattern    string `json:"pattern"`
	Evidence   string `json:"evidence"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Confidence string `json:"confidence"`
}

type DetectionSummary struct {
	HasRootDetection     bool   `json:"has_root_detection"`
	HasFridaDetection    bool   `json:"has_frida_detection"`
	HasEmulatorDetection bool   `json:"has_emulator_detection"`
	HasDebugDetection    bool   `json:"has_debug_detection"`
	HasTamperDetection   bool   `json:"has_tamper_detection"`
	TotalFindings        int    `json:"total_findings"`
	ProtectionLevel      string `json:"protection_level"` // none, basic, moderate, strong
}

var rootPatterns = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"su binary check", regexp.MustCompile(`(?i)(/system/xbin/su|/system/bin/su|/sbin/su|/system/app/Superuser)`)},
	{"root packages", regexp.MustCompile(`(?i)(com\.noshufou\.android\.su|com\.thirdparty\.superuser|eu\.chainfire\.supersu|com\.koushikdutta\.superuser|com\.topjohnwu\.magisk)`)},
	{"RootBeer library", regexp.MustCompile(`(?i)(com/scottyab/rootbeer|RootBeer|isRooted|detectRootManagementApps)`)},
	{"build.prop check", regexp.MustCompile(`(?i)(ro\.debuggable|ro\.secure|test-keys|ro\.build\.tags)`)},
	{"which su", regexp.MustCompile(`(?i)(which\s+su|Runtime.*exec.*su)`)},
	{"busybox check", regexp.MustCompile(`(?i)(/system/xbin/busybox|/system/bin/busybox)`)},
	{"SafetyNet", regexp.MustCompile(`(?i)(SafetyNet|safetynet|GoogleApiAvailability|SafeBrowsing)`)},
	{"Play Integrity", regexp.MustCompile(`(?i)(PlayIntegrity|IntegrityTokenRequest|integrity.*verdict)`)},
}

var fridaPatterns = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"frida port check", regexp.MustCompile(`(?i)(27042|27043)`)},
	{"frida binary", regexp.MustCompile(`(?i)(frida-server|frida-agent|frida-gadget|libfrida)`)},
	{"frida pipe", regexp.MustCompile(`(?i)(linjector|frida.*tmp|re\.frida\.server)`)},
	{"frida module scan", regexp.MustCompile(`(?i)(/proc/self/maps.*frida|frida-agent.*\.so)`)},
	{"frida D-Bus", regexp.MustCompile(`(?i)(REJECT.*frida|frida.*AUTH)`)},
	{"Xposed check", regexp.MustCompile(`(?i)(de/robv/android/xposed|XposedBridge|XposedHelpers|xposed\.jar)`)},
	{"Substrate check", regexp.MustCompile(`(?i)(com\.saurik\.substrate|SubstrateHook|MSHookFunction)`)},
}

var emulatorPatterns = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"emulator build props", regexp.MustCompile(`(?i)(generic.*Build|unknown.*Build|google_sdk|Emulator|sdk_gphone|vbox86|goldfish)`)},
	{"emulator files", regexp.MustCompile(`(?i)(/dev/socket/qemud|/dev/qemu_pipe|/system/lib/libc_malloc_debug_qemu|qemu\.hw\.mainkeys)`)},
	{"emulator telephony", regexp.MustCompile(`(?i)(000000000000000|e21833235b6eef10|012345678912345|15555215554)`)},
	{"emulator hardware", regexp.MustCompile(`(?i)(hardware.*goldfish|hardware.*ranchu|ro\.hardware\.audio\.primary.*goldfish)`)},
	{"BlueStacks", regexp.MustCompile(`(?i)(com\.bluestacks|bst\.ime|BstSharedFolder)`)},
	{"Genymotion", regexp.MustCompile(`(?i)(com\.genymotion|genymotion|/dev/socket/genyd)`)},
	{"NOX/MEmu", regexp.MustCompile(`(?i)(nox|bignox|com\.bignox|memu|microvirt)`)},
}

var debugPatterns = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"debugger check", regexp.MustCompile(`(?i)(android\.os\.Debug\.isDebuggerConnected|Debug\.isDebuggerConnected|waitForDebugger)`)},
	{"TracerPid", regexp.MustCompile(`(?i)(/proc/self/status.*TracerPid|TracerPid)`)},
	{"ptrace check", regexp.MustCompile(`(?i)(ptrace\(PTRACE_TRACEME|PTRACE_ATTACH|anti_debug|antiDebug)`)},
	{"timing check", regexp.MustCompile(`(?i)(System\.nanoTime.*diff|uptimeMillis.*check|Debug\.threadCpuTimeNanos)`)},
	{"debuggable flag", regexp.MustCompile(`(?i)(ApplicationInfo\.FLAG_DEBUGGABLE|FLAG_DEBUGGABLE)`)},
}

var tamperPatterns = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"signature check", regexp.MustCompile(`(?i)(PackageInfo.*signatures|GET_SIGNATURES|getPackageInfo.*64|checkSignature)`)},
	{"installer check", regexp.MustCompile(`(?i)(getInstallerPackageName|com\.android\.vending|getInstallSourceInfo)`)},
	{"CRC check", regexp.MustCompile(`(?i)(classes\.dex.*crc|ZipEntry.*getCrc|dex.*checksum)`)},
	{"APK hash", regexp.MustCompile(`(?i)(sourceDir.*digest|apk.*sha256|apk.*md5|getPackageCodePath.*hash)`)},
	{"certificate pinning", regexp.MustCompile(`(?i)(CertificatePinner|sha256/|X509TrustManager.*check|networkSecurityConfig)`)},
}

func DetectAntiDetection(decompiledPath string) (*AntiDetectResult, error) {
	result := &AntiDetectResult{}
	if decompiledPath == "" {
		return result, nil
	}

	_ = filepath.WalkDir(decompiledPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".smali" && ext != ".java" && ext != ".kt" && ext != ".xml" {
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

		rel, _ := filepath.Rel(decompiledPath, path)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0

		for scanner.Scan() {
			lineNo++
			line := scanner.Text()

			for _, p := range rootPatterns {
				if p.re.MatchString(line) {
					result.RootDetection = append(result.RootDetection, DetectionFinding{
						Pattern:    p.pattern,
						Evidence:   trimValue(strings.TrimSpace(line)),
						File:       rel,
						Line:       lineNo,
						Confidence: "high",
					})
				}
			}
			for _, p := range fridaPatterns {
				if p.re.MatchString(line) {
					conf := "high"
					if p.pattern == "frida port check" {
						conf = "medium"
					}
					result.FridaDetection = append(result.FridaDetection, DetectionFinding{
						Pattern:    p.pattern,
						Evidence:   trimValue(strings.TrimSpace(line)),
						File:       rel,
						Line:       lineNo,
						Confidence: conf,
					})
				}
			}
			for _, p := range emulatorPatterns {
				if p.re.MatchString(line) {
					result.EmulatorDetection = append(result.EmulatorDetection, DetectionFinding{
						Pattern:    p.pattern,
						Evidence:   trimValue(strings.TrimSpace(line)),
						File:       rel,
						Line:       lineNo,
						Confidence: "high",
					})
				}
			}
			for _, p := range debugPatterns {
				if p.re.MatchString(line) {
					result.DebugDetection = append(result.DebugDetection, DetectionFinding{
						Pattern:    p.pattern,
						Evidence:   trimValue(strings.TrimSpace(line)),
						File:       rel,
						Line:       lineNo,
						Confidence: "high",
					})
				}
			}
			for _, p := range tamperPatterns {
				if p.re.MatchString(line) {
					result.TamperDetection = append(result.TamperDetection, DetectionFinding{
						Pattern:    p.pattern,
						Evidence:   trimValue(strings.TrimSpace(line)),
						File:       rel,
						Line:       lineNo,
						Confidence: "high",
					})
				}
			}
		}
		return nil
	})

	capFindings(&result.RootDetection, 100)
	capFindings(&result.FridaDetection, 100)
	capFindings(&result.EmulatorDetection, 100)
	capFindings(&result.DebugDetection, 100)
	capFindings(&result.TamperDetection, 100)

	result.Summary.HasRootDetection = len(result.RootDetection) > 0
	result.Summary.HasFridaDetection = len(result.FridaDetection) > 0
	result.Summary.HasEmulatorDetection = len(result.EmulatorDetection) > 0
	result.Summary.HasDebugDetection = len(result.DebugDetection) > 0
	result.Summary.HasTamperDetection = len(result.TamperDetection) > 0
	result.Summary.TotalFindings = len(result.RootDetection) + len(result.FridaDetection) +
		len(result.EmulatorDetection) + len(result.DebugDetection) + len(result.TamperDetection)

	categories := 0
	if result.Summary.HasRootDetection {
		categories++
	}
	if result.Summary.HasFridaDetection {
		categories++
	}
	if result.Summary.HasEmulatorDetection {
		categories++
	}
	if result.Summary.HasDebugDetection {
		categories++
	}
	if result.Summary.HasTamperDetection {
		categories++
	}

	switch {
	case categories == 0:
		result.Summary.ProtectionLevel = "none"
	case categories <= 2:
		result.Summary.ProtectionLevel = "basic"
	case categories <= 3:
		result.Summary.ProtectionLevel = "moderate"
	default:
		result.Summary.ProtectionLevel = "strong"
	}

	return result, nil
}

func capFindings(findings *[]DetectionFinding, max int) {
	if len(*findings) > max {
		*findings = (*findings)[:max]
	}
}
