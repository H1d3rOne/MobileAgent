package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
	registerBuiltin(r, deviceListSkill(adb), []string{"device", "read"}, false)
	registerBuiltin(r, deviceShellSkill(adb, cfg), []string{"device", "shell"}, true)
	registerBuiltin(r, deviceScreenshotSkill(adb), []string{"device", "read"}, false)
	registerBuiltin(r, devicePackagesSkill(adb), []string{"device", "read"}, false)
	registerBuiltin(r, deviceInstallApkSkill(apk), []string{"device", "install"}, true)
	registerBuiltin(r, apkAnalyzeSkill(apk), []string{"apk", "read"}, false)
	registerBuiltin(r, apkDecompileSkill(apk, cfg), []string{"apk", "workspace"}, false)
	registerBuiltin(r, apkListSkill(apkStore), []string{"apk", "read"}, false)
	registerBuiltin(r, apkTriageSkill(apkStore, cfg), []string{"apk", "reverse", "triage"}, false)
	registerBuiltin(r, apkAttackSurfaceSkill(apkStore, cfg), []string{"apk", "reverse", "entrypoint"}, false)
	registerBuiltin(r, apkEntryTraceSkill(apkStore, cfg), []string{"apk", "reverse", "entrypoint", "trace"}, false)
	registerBuiltin(r, fileReadSkill(cfg), []string{"file", "read"}, false)
	registerBuiltin(r, fileWriteSkill(cfg), []string{"file", "write"}, false)
	registerBuiltin(r, fileListSkill(cfg), []string{"file", "read"}, false)
	registerBuiltin(r, codeSearchSkill(cfg), []string{"code", "read"}, false)
	registerBuiltin(r, localShellSkill(cfg), []string{"host", "shell"}, true)
	registerBuiltin(r, termuxShellSkill(cfg), []string{"termux", "shell"}, true)
	registerBuiltin(r, memorySaveSkill(agentStore), []string{"memory"}, false)
	registerBuiltin(r, memoryRecallSkill(agentStore), []string{"memory", "read"}, false)
	registerBuiltin(r, fridaListProcessesSkill(frida), []string{"frida", "read"}, false)
	registerBuiltin(r, fridaListAppsSkill(frida), []string{"frida", "read"}, false)
	registerBuiltin(r, fridaHookSkill(frida, cfg), []string{"frida", "runtime"}, true)
	registerBuiltin(r, fridaSnippetSkill(frida, cfg), []string{"frida", "runtime"}, true)
	registerBuiltin(r, fridaSpawnSkill(frida, cfg), []string{"frida", "runtime"}, true)
	registerBuiltin(r, fridaServerStatusSkill(frida, cfg), []string{"frida", "read"}, false)
	registerBuiltin(r, fridaRunScriptSkill(frida, cfg), []string{"frida", "runtime"}, true)
	registerBuiltin(r, fridaListScriptsSkill(), []string{"frida", "read"}, false)
	registerBuiltin(r, apkAntiDetectSkill(apkStore, cfg), []string{"apk", "reverse", "read"}, false)
	registerBuiltin(r, apkStringsSkill(apkStore, cfg), []string{"apk", "reverse", "read"}, false)
	registerBuiltin(r, apkCallGraphSkill(apkStore, cfg), []string{"apk", "reverse", "read"}, false)
	registerBuiltin(r, apkGenerateHooksSkill(apkStore, cfg), []string{"apk", "frida", "generate"}, false)
	registerBuiltin(r, apkRuntimePlanSkill(apkStore, cfg), []string{"apk", "reverse", "frida", "plan"}, false)
	registerBuiltin(r, apkEvidencePackageSkill(apkStore, cfg), []string{"apk", "reverse", "evidence", "report"}, false)
	registerBuiltin(r, apkReversePlanSkill(apkStore, cfg), []string{"apk", "reverse", "plan"}, false)
	registerBuiltin(r, apkReverseValidateSkill(apkStore, cfg), []string{"apk", "reverse", "validate"}, false)
}

func registerBuiltin(r *Registry, s Skill, tags []string, dangerous bool) {
	r.RegisterWithMetadata(s, SkillMetadata{
		ID:          s.Name,
		Name:        s.Name,
		Description: s.Description,
		Tags:        tags,
		Builtin:     true,
		Source:      "builtin",
		Enabled:     true,
		Dangerous:   dangerous,
	})
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

func apkTriageSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_triage",
		Description: "Run an autonomous first-pass Android reverse-engineering triage for an uploaded APK. " +
			"Combines manifest, certificate, risk, packer, code, SDK, string/config, anti-analysis, optional call graph, " +
			"and Frida hook suggestions into a concise JSON summary with prioritized next steps.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id": map[string]any{"type": "string", "description": "APK ID from apk_list."},
				"include_callgraph": map[string]any{
					"type":        "boolean",
					"description": "Whether to include call graph/taint analysis. It can be slower on large APKs. Default false.",
				},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			includeCallgraph := argBool(args, "include_callgraph", false)
			out, err := RunAPKTriage(apkStore, cfg, id, includeCallgraph)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(out)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

// RunAPKTriage runs the reusable APK reverse-engineering first-pass analysis used by
// both the LLM-facing apk_triage skill and the HTTP API.
func RunAPKTriage(apkStore *store.APKStore, cfg *config.Config, id string, includeCallgraph bool) (map[string]any, error) {
	if apkStore == nil {
		return nil, fmt.Errorf("apk store unavailable")
	}
	if id == "" {
		return nil, fmt.Errorf("apk_id required")
	}
	apk, err := apkStore.Get(id)
	if err != nil {
		return nil, err
	}
	if apk == nil {
		return nil, fmt.Errorf("APK not found: %s", id)
	}

	out := map[string]any{
		"apk": map[string]any{
			"id":              apk.ID,
			"filename":        apk.Filename,
			"file_path":       apk.FilePath,
			"package_name":    apk.PackageName,
			"version_name":    apk.VersionName,
			"version_code":    apk.VersionCode,
			"decompiled_path": apk.DecompiledPath,
			"decompiled_tool": apk.DecompiledTool,
		},
	}
	coverage := map[string]string{}
	findings := map[string]any{}
	nextSteps := []string{}

	var manifest *analyzer.ManifestResult
	if m, err := analyzer.ParseManifest(apk.FilePath); err == nil {
		manifest = m
		coverage[analyzer.TypeManifest] = "ok"
		findings[analyzer.TypeManifest] = summarizeManifest(m)
		saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeManifest, m)
	} else {
		coverage[analyzer.TypeManifest] = err.Error()
	}

	var cert *analyzer.CertificateResult
	if c, err := analyzer.ParseCertificate(apk.FilePath); err == nil {
		cert = c
		coverage[analyzer.TypeCertificate] = "ok"
		findings[analyzer.TypeCertificate] = summarizeCertificate(c)
		saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeCertificate, c)
	} else {
		coverage[analyzer.TypeCertificate] = err.Error()
	}

	risk := analyzer.EvaluateRisk(manifest, cert)
	coverage[analyzer.TypeRisk] = "ok"
	findings[analyzer.TypeRisk] = summarizeRisk(risk)
	saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeRisk, risk)

	if manifest != nil {
		attackSurface := analyzer.AnalyzeAttackSurface(manifest)
		coverage[analyzer.TypeAttackSurface] = "ok"
		findings[analyzer.TypeAttackSurface] = summarizeAttackSurface(attackSurface)
		saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeAttackSurface, attackSurface)
		if attackSurface.Summary.RiskLevel == "high" || attackSurface.Summary.RiskLevel == "medium" {
			nextSteps = append(nextSteps, "Prioritize exported components/deeplinks from attack_surface and replay suggested adb commands to verify access control.")
		}
	} else {
		coverage[analyzer.TypeAttackSurface] = "skipped: manifest unavailable"
	}

	var stringsResult *analyzer.StringsResult
	var antiDetect *analyzer.AntiDetectResult
	var entryTrace *analyzer.EntryTraceResult
	if apk.DecompiledPath == "" {
		coverage["decompiled_artifacts"] = "missing: run apk_decompile first for code, strings, SDK, packer, anti-detect, entry_trace and callgraph analysis"
		coverage[analyzer.TypeEntryTrace] = "skipped: decompile required"
		nextSteps = append(nextSteps, "Run apk_decompile, then rerun apk_triage for source/smali-level analysis.")
	} else {
		coverage["decompiled_artifacts"] = "ok"

		if p, err := analyzer.DetectPacker(apk.FilePath, apk.DecompiledPath); err == nil {
			coverage[analyzer.TypePacker] = "ok"
			findings[analyzer.TypePacker] = summarizePacker(p)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypePacker, p)
			if p.HasPacker {
				nextSteps = append(nextSteps, "Packed/protected APK detected: prioritize runtime dex dump and anti-Frida/anti-debug checks before deep static tracing.")
			}
		} else {
			coverage[analyzer.TypePacker] = err.Error()
		}

		if code, err := analyzer.ScanCode(apk.DecompiledPath); err == nil {
			coverage[analyzer.TypeCode] = "ok"
			findings[analyzer.TypeCode] = summarizeCode(code)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeCode, code)
			if len(code.Secrets) > 0 {
				nextSteps = append(nextSteps, "Review hardcoded secret findings and trace how they are used before reporting impact.")
			}
			if len(code.DangerousAPIs) > 0 {
				nextSteps = append(nextSteps, "Use code_search + file_read around dangerous API call sites to confirm exploitability.")
			}
		} else {
			coverage[analyzer.TypeCode] = err.Error()
		}

		if manifest != nil {
			if et, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, ""); err == nil {
				entryTrace = et
				coverage[analyzer.TypeEntryTrace] = "ok"
				findings[analyzer.TypeEntryTrace] = summarizeEntryTrace(et)
				saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeEntryTrace, et)
				if et.Summary.RiskLevel == "high" || et.Summary.RiskLevel == "medium" {
					nextSteps = append(nextSteps, "Use entry_trace results to inspect exact handler lines for exported inputs before dynamic replay.")
				}
				if et.Summary.FlowsFound > 0 {
					nextSteps = append(nextSteps, "Run apk_generate_hooks and use the generated entry-trace Frida monitors while replaying exported component inputs.")
				}
			} else {
				coverage[analyzer.TypeEntryTrace] = err.Error()
			}
		} else {
			coverage[analyzer.TypeEntryTrace] = "skipped: manifest unavailable"
		}

		if sdk, err := analyzer.DetectSDKs(apk.DecompiledPath); err == nil {
			coverage[analyzer.TypeSDK] = "ok"
			findings[analyzer.TypeSDK] = summarizeSDKs(sdk)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeSDK, sdk)
		} else {
			coverage[analyzer.TypeSDK] = err.Error()
		}

		if sr, err := analyzer.ScanStrings(apk.DecompiledPath); err == nil {
			stringsResult = sr
			coverage[analyzer.TypeStrings] = "ok"
			findings[analyzer.TypeStrings] = summarizeStrings(sr)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeStrings, sr)
			if len(sr.CryptoUsage) > 0 {
				nextSteps = append(nextSteps, "Inspect crypto usage and generated Frida crypto monitor hooks for keys/IVs/algorithms at runtime.")
			}
		} else {
			coverage[analyzer.TypeStrings] = err.Error()
		}

		if ad, err := analyzer.DetectAntiDetection(apk.DecompiledPath); err == nil {
			antiDetect = ad
			coverage[analyzer.TypeAntiDetect] = "ok"
			findings[analyzer.TypeAntiDetect] = summarizeAntiDetect(ad)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeAntiDetect, ad)
			if ad.Summary.TotalFindings > 0 {
				nextSteps = append(nextSteps, "Generate and test targeted Frida bypass hooks before dynamic analysis.")
			}
		} else {
			coverage[analyzer.TypeAntiDetect] = err.Error()
		}

		if includeCallgraph {
			pkg := ""
			if manifest != nil {
				pkg = manifest.Package
			}
			if cg, err := analyzer.BuildCallGraph(apk.DecompiledPath, pkg); err == nil {
				coverage[analyzer.TypeCallGraph] = "ok"
				findings[analyzer.TypeCallGraph] = summarizeCallGraph(cg)
				saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeCallGraph, cg)
			} else {
				coverage[analyzer.TypeCallGraph] = err.Error()
			}
		} else {
			coverage[analyzer.TypeCallGraph] = "skipped: include_callgraph=false"
		}

		var crypto []analyzer.CryptoFinding
		if stringsResult != nil {
			crypto = stringsResult.CryptoUsage
		}
		hooks := fridapkg.GenerateHooksFromAnalysis(antiDetect, crypto, stringsResult, entryTrace)
		findings["generated_hooks"] = summarizeHooks(hooks)
	}

	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
		if summary, _, ok := analyzer.SummarizeRuntimeEvidenceJSON(row.Result, 10); ok {
			if planRow, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan); planRow != nil {
				if verified := analyzer.RuntimeEvidenceVerifiedFlows(summary, planRow.Result, 10); len(verified) > 0 {
					summary["verified_flows"] = verified
				}
			}
			coverage[analyzer.TypeRuntimeEvidence] = "ok"
			findings[analyzer.TypeRuntimeEvidence] = summary
			nextSteps = append(nextSteps, "Use persisted runtime_evidence to mark exact flow_id hits as dynamically verified in the final report.")
		}
	} else {
		coverage[analyzer.TypeRuntimeEvidence] = "skipped: no persisted runtime evidence"
	}

	if risk.Score >= 60 {
		nextSteps = append([]string{"Start with high-risk findings from the risk summary before broad exploration."}, nextSteps...)
	}
	if len(nextSteps) == 0 {
		nextSteps = append(nextSteps, "No critical triage finding surfaced; continue with targeted user-requested code_search/file_read tracing.")
	}
	out["coverage"] = coverage
	out["findings"] = findings
	out["next_steps"] = dedupeStrings(nextSteps)

	return out, nil
}

// RunAPKRuntimePlan builds an execution-ready dynamic validation plan from
// entry_trace flows, generated Frida hooks, and adb replay commands. It does not
// touch a device; dangerous runtime execution remains delegated to frida_* or
// device_shell skills with an explicit serial/target.
func RunAPKRuntimePlan(apkStore *store.APKStore, cfg *config.Config, id, serial string) (map[string]any, error) {
	if apkStore == nil {
		return nil, fmt.Errorf("apk store unavailable")
	}
	apk, err := apkStore.Get(id)
	if err != nil {
		return nil, err
	}
	if apk == nil {
		return nil, fmt.Errorf("APK not found: %s", id)
	}
	if apk.DecompiledPath == "" {
		return nil, fmt.Errorf("APK must be decompiled first")
	}

	manifest, err := analyzer.ParseManifest(apk.FilePath)
	if err != nil {
		return nil, err
	}
	entryTrace, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, "")
	if err != nil {
		return nil, err
	}
	saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeManifest, manifest)
	saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeEntryTrace, entryTrace)

	antiDetect, _ := analyzer.DetectAntiDetection(apk.DecompiledPath)
	stringsResult, _ := analyzer.ScanStrings(apk.DecompiledPath)
	var crypto []analyzer.CryptoFinding
	if stringsResult != nil {
		crypto = stringsResult.CryptoUsage
	}
	hooks := fridapkg.GenerateHooksFromAnalysis(antiDetect, crypto, stringsResult, entryTrace)

	targetPackage := manifest.Package
	if targetPackage == "" {
		targetPackage = apk.PackageName
	}

	out := map[string]any{
		"apk": map[string]any{
			"id":              apk.ID,
			"filename":        apk.Filename,
			"package_name":    targetPackage,
			"decompiled_path": apk.DecompiledPath,
			"decompiled_tool": apk.DecompiledTool,
		},
		"target": map[string]any{
			"serial":          serial,
			"package":         targetPackage,
			"ready_to_run":    serial != "" && targetPackage != "",
			"requires_device": serial == "",
		},
		"entry_trace":        summarizeEntryTrace(entryTrace),
		"flows":              runtimePlanFlows(entryTrace, 20),
		"adb_replay":         runtimePlanReplayCommands(entryTrace, 20),
		"generated_hooks":    runtimePlanHooks(hooks, serial, targetPackage, 10),
		"validation_steps":   runtimeValidationSteps(serial, targetPackage, entryTrace.Summary.FlowsFound, len(hooks)),
		"execution_boundary": "plan only: run device_shell/frida_hook/frida_spawn explicitly to touch a device",
	}
	return out, nil
}

func RunAPKEvidencePackage(apkStore *store.APKStore, cfg *config.Config, id string) (map[string]any, error) {
	if apkStore == nil {
		return nil, fmt.Errorf("apk store unavailable")
	}
	apk, err := apkStore.Get(id)
	if err != nil {
		return nil, err
	}
	if apk == nil {
		return nil, fmt.Errorf("APK not found: %s", id)
	}
	out := map[string]any{
		"apk": map[string]any{
			"id":              apk.ID,
			"filename":        apk.Filename,
			"package_name":    apk.PackageName,
			"version_name":    apk.VersionName,
			"version_code":    apk.VersionCode,
			"file_path":       apk.FilePath,
			"decompiled_path": apk.DecompiledPath,
			"decompiled_tool": apk.DecompiledTool,
		},
	}
	var runtimePlan map[string]any
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan); row != nil {
		_ = json.Unmarshal([]byte(row.Result), &runtimePlan)
		if runtimePlan != nil {
			out["runtime_plan"] = runtimePlan
		}
	}
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
		if summary, details, ok := analyzer.SummarizeRuntimeEvidenceJSON(row.Result, 20); ok {
			if runtimePlan != nil {
				if verified := analyzer.RuntimeEvidenceVerifiedFlows(summary, evidenceJSONString(runtimePlan), 20); len(verified) > 0 {
					summary["verified_flows"] = verified
				}
			}
			out["runtime_evidence"] = summary
			out["evidence_details"] = details
		}
	}
	out["markdown"] = formatAPKEvidencePackageMarkdown(out)
	if cfg != nil && cfg.Storage.WorkspaceDir != "" {
		if artifacts, err := writeEvidencePackageArtifacts(cfg.Storage.WorkspaceDir, apk.ID, out); err == nil {
			out["artifacts"] = artifacts
		} else {
			out["artifact_error"] = err.Error()
		}
	}
	return out, nil
}

func writeEvidencePackageArtifacts(workspaceDir, apkID string, pkg map[string]any) (map[string]string, error) {
	dir := filepath.Join(workspaceDir, "evidence_packages")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	stamp := time.Now().Format("20060102_150405")
	base := fmt.Sprintf("%s_%s", apkID, stamp)
	mdPath := filepath.Join(dir, base+".md")
	jsonPath := filepath.Join(dir, base+".json")
	if err := os.WriteFile(mdPath, []byte(fmt.Sprint(pkg["markdown"])), 0o644); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
		return nil, err
	}
	return map[string]string{"markdown": mdPath, "json": jsonPath}, nil
}

func evidenceJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func formatAPKEvidencePackageMarkdown(pkg map[string]any) string {
	apk := evidenceMap(pkg["apk"])
	runtimeEvidence := evidenceMap(pkg["runtime_evidence"])
	runtimePlan := evidenceMap(pkg["runtime_plan"])
	var sb strings.Builder
	sb.WriteString("# APK Runtime Evidence Package\n\n")
	fmt.Fprintf(&sb, "- APK ID: `%v`\n", apk["id"])
	fmt.Fprintf(&sb, "- File: `%v`\n", apk["filename"])
	fmt.Fprintf(&sb, "- Package: `%v`\n\n", apk["package_name"])
	if len(runtimeEvidence) > 0 {
		fmt.Fprintf(&sb, "## Runtime Evidence\n\n")
		fmt.Fprintf(&sb, "- ENTRY_TRACE hits: `%v`\n", runtimeEvidence["entry_trace"])
		fmt.Fprintf(&sb, "- Flow IDs: `%s`\n\n", strings.Join(evidenceStringList(runtimeEvidence["flow_ids"]), "`, `"))
		if verified := evidenceList(runtimeEvidence["verified_flows"]); len(verified) > 0 {
			sb.WriteString("## Verified Flows\n\n")
			for _, raw := range verified {
				flow := evidenceMap(raw)
				source := evidenceMap(flow["source"])
				sink := evidenceMap(flow["sink"])
				fmt.Fprintf(&sb, "### %v\n\n", flow["flow_id"])
				fmt.Fprintf(&sb, "- Component: `%v`\n", flow["component"])
				fmt.Fprintf(&sb, "- Method: `%v`\n", flow["method"])
				fmt.Fprintf(&sb, "- Source: `%v` line `%v`\n", source["kind"], source["line"])
				fmt.Fprintf(&sb, "- Sink: `%v` `%v` line `%v`\n\n", sink["kind"], sink["pattern"], sink["line"])
			}
		}
	}
	if replay := evidenceStringList(runtimePlan["adb_replay"]); len(replay) > 0 {
		sb.WriteString("## ADB Replay Commands\n\n")
		for _, cmd := range replay {
			fmt.Fprintf(&sb, "```bash\n%s\n```\n\n", cmd)
		}
	}
	if details := evidenceStringList(pkg["evidence_details"]); len(details) > 0 {
		sb.WriteString("## Runtime Event Details\n\n")
		for _, d := range details {
			fmt.Fprintf(&sb, "- %s\n", d)
		}
	}
	return sb.String()
}

func evidenceMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func evidenceList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if l, ok := v.([]map[string]any); ok {
		out := make([]any, 0, len(l))
		for _, item := range l {
			out = append(out, item)
		}
		return out
	}
	return nil
}

func evidenceStringList(v any) []string {
	if l, ok := v.([]string); ok {
		return l
	}
	out := []string{}
	for _, item := range evidenceList(v) {
		if s := fmt.Sprint(item); s != "" && s != "<nil>" {
			out = append(out, s)
		}
	}
	return out
}


func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case float32:
		return int(x), true
	case float64:
		return int(x), true
	case json.Number:
		n, err := x.Int64()
		return int(n), err == nil
	default:
		return 0, false
	}
}
func argBool(args map[string]any, key string, def bool) bool {
	if v, ok := args[key]; ok {
		switch x := v.(type) {
		case bool:
			return x
		case string:
			return strings.EqualFold(x, "true") || x == "1" || strings.EqualFold(x, "yes")
		case float64:
			return x != 0
		case int:
			return x != 0
		}
	}
	return def
}

func saveAPKAnalysis(apkStore *store.APKStore, apkID, typ string, payload any) {
	if apkStore == nil || apkID == "" {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = apkStore.UpsertAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apkID,
		Type:      typ,
		Result:    string(raw),
		CreatedAt: time.Now(),
	})
}

func summarizeManifest(m *analyzer.ManifestResult) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return map[string]any{
		"package":                m.Package,
		"version_name":           m.VersionName,
		"version_code":           m.VersionCode,
		"min_sdk":                m.MinSDK,
		"target_sdk":             m.TargetSDK,
		"debuggable":             m.Debuggable,
		"allow_backup":           m.AllowBackup,
		"uses_cleartext_traffic": m.UsesCleartextTraffic,
		"launcher_activity":      m.LauncherActivity,
		"permissions_count":      len(m.Permissions),
		"dangerous_permissions":  dangerousPermissionList(m.Permissions),
		"exported_components":    exportedComponents(m),
	}
}

func summarizeCertificate(c *analyzer.CertificateResult) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"sha1":        c.SHA1,
		"sha256":      c.SHA256,
		"subject":     c.Subject,
		"issuer":      c.Issuer,
		"debug":       c.Debug,
		"v1_verified": c.V1Verified,
		"v2_verified": c.V2Verified,
		"v3_verified": c.V3Verified,
		"tool":        c.Tool,
	}
}

func summarizeRisk(r *analyzer.RiskResult) map[string]any {
	if r == nil {
		return map[string]any{}
	}
	levels := map[string]int{}
	top := make([]analyzer.Risk, 0, minInt(len(r.Risks), 10))
	for i, item := range r.Risks {
		levels[item.Level]++
		if i < 10 {
			top = append(top, item)
		}
	}
	return map[string]any{
		"score":        r.Score,
		"by_level":     levels,
		"top_findings": top,
	}
}

func summarizePacker(p *analyzer.PackerResult) map[string]any {
	if p == nil {
		return map[string]any{}
	}
	libs := p.NativeLibs
	if len(libs) > 30 {
		libs = libs[:30]
	}
	return map[string]any{
		"has_packer":  p.HasPacker,
		"detected":    p.Detected,
		"multi_dex":   p.MultiDex,
		"dex_count":   p.DexCount,
		"native_libs": libs,
		"suggestions": p.Suggestions,
	}
}

func summarizeCode(c *analyzer.CodeResult) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"files_scanned":        c.FilesScanned,
		"truncated":            c.Truncated,
		"endpoints_count":      len(c.Endpoints),
		"endpoints_sample":     firstStrings(c.Endpoints, 20),
		"secrets_count":        len(c.Secrets),
		"secrets_sample":       firstCodeFindings(c.Secrets, 20),
		"dangerous_api_count":  len(c.DangerousAPIs),
		"dangerous_api_sample": firstCodeFindings(c.DangerousAPIs, 30),
	}
}

func summarizeSDKs(s *analyzer.SDKResult) map[string]any {
	if s == nil {
		return map[string]any{}
	}
	byCategory := map[string]int{}
	for _, sdk := range s.SDKs {
		byCategory[sdk.Category]++
	}
	sample := s.SDKs
	if len(sample) > 30 {
		sample = sample[:30]
	}
	return map[string]any{
		"count":       len(s.SDKs),
		"by_category": byCategory,
		"sample":      sample,
	}
}

func summarizeStrings(s *analyzer.StringsResult) map[string]any {
	if s == nil {
		return map[string]any{}
	}
	return map[string]any{
		"files_scanned":      s.FilesScanned,
		"firebase":           s.Firebase,
		"domains_count":      len(s.Domains),
		"domains_sample":     firstHosts(s.Domains, 30),
		"ips_count":          len(s.IPs),
		"ips_sample":         firstIPs(s.IPs, 20),
		"crypto_usage_count": len(s.CryptoUsage),
		"crypto_sample":      firstCryptoFindings(s.CryptoUsage, 30),
		"configs_count":      len(s.Configs),
		"configs_sample":     firstConfigs(s.Configs, 20),
	}
}

func summarizeAntiDetect(a *analyzer.AntiDetectResult) map[string]any {
	if a == nil {
		return map[string]any{}
	}
	return map[string]any{
		"summary":         a.Summary,
		"root_sample":     firstDetectionFindings(a.RootDetection, 20),
		"frida_sample":    firstDetectionFindings(a.FridaDetection, 20),
		"emulator_sample": firstDetectionFindings(a.EmulatorDetection, 20),
		"debug_sample":    firstDetectionFindings(a.DebugDetection, 20),
		"tamper_sample":   firstDetectionFindings(a.TamperDetection, 20),
	}
}

func summarizeCallGraph(c *analyzer.CallGraphResult) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"stats":        c.Stats,
		"entry_points": firstStrings(c.EntryPoints, 30),
		"hot_methods":  firstHotMethods(c.HotMethods, 30),
		"taint_paths":  firstDataFlowPaths(c.Paths, 30),
		"nodes_sample": firstCallNodes(c.Nodes, 20),
		"edges_sample": firstCallEdges(c.Edges, 20),
	}
}

func summarizeAttackSurface(a *analyzer.AttackSurfaceResult) map[string]any {
	if a == nil {
		return map[string]any{}
	}
	entries := a.EntryPoints
	if len(entries) > 20 {
		entries = entries[:20]
	}
	deepLinks := a.DeepLinks
	if len(deepLinks) > 20 {
		deepLinks = deepLinks[:20]
	}
	providers := a.ContentURIs
	if len(providers) > 20 {
		providers = providers[:20]
	}
	tests := a.SuggestedTests
	if len(tests) > 20 {
		tests = tests[:20]
	}
	findings := a.Findings
	if len(findings) > 20 {
		findings = findings[:20]
	}
	return map[string]any{
		"summary":         a.Summary,
		"entry_points":    entries,
		"deep_links":      deepLinks,
		"content_uris":    providers,
		"suggested_tests": tests,
		"findings":        findings,
	}
}

func summarizeEntryTrace(e *analyzer.EntryTraceResult) map[string]any {
	if e == nil {
		return map[string]any{}
	}
	traces := e.Traces
	if len(traces) > 20 {
		traces = traces[:20]
	}
	return map[string]any{
		"package": e.Package,
		"summary": e.Summary,
		"traces":  traces,
	}
}

func summarizeHooks(hooks []fridapkg.GeneratedHook) map[string]any {
	out := make([]map[string]string, 0, minInt(len(hooks), 20))
	for i, h := range hooks {
		if i >= 20 {
			break
		}
		out = append(out, map[string]string{
			"id":          h.ID,
			"name":        h.Name,
			"category":    h.Category,
			"description": h.Description,
			"reason":      h.Reason,
		})
	}
	return map[string]any{"count": len(hooks), "sample": out}
}

func runtimePlanFlows(entryTrace *analyzer.EntryTraceResult, limit int) []map[string]any {
	if entryTrace == nil || limit <= 0 {
		return nil
	}
	var out []map[string]any
	for _, trace := range entryTrace.Traces {
		for _, flow := range trace.Flows {
			flowID := fmt.Sprintf("flow-%03d", len(out)+1)
			out = append(out, map[string]any{
				"flow_id":   flowID,
				"component": trace.Component,
				"kind":      trace.Kind,
				"method":    flow.Method,
				"risk":      flow.Risk,
				"reason":    flow.Reason,
				"file":      flow.File,
				"source": map[string]any{
					"kind":    flow.Source.Kind,
					"pattern": flow.Source.Pattern,
					"line":    flow.Source.Line,
				},
				"sink": map[string]any{
					"kind":    flow.Sink.Kind,
					"pattern": flow.Sink.Pattern,
					"line":    flow.Sink.Line,
				},
				"variables":       flow.Variables,
				"replay_commands": trace.Commands,
			})
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func runtimePlanReplayCommands(entryTrace *analyzer.EntryTraceResult, limit int) []string {
	if entryTrace == nil || limit <= 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, trace := range entryTrace.Traces {
		for _, cmd := range trace.Commands {
			if cmd == "" || seen[cmd] {
				continue
			}
			seen[cmd] = true
			out = append(out, cmd)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func runtimePlanHooks(hooks []fridapkg.GeneratedHook, serial, target string, limit int) []map[string]any {
	if limit <= 0 {
		return nil
	}
	var out []map[string]any
	for i, hook := range hooks {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{
			"id":          hook.ID,
			"name":        hook.Name,
			"category":    hook.Category,
			"description": hook.Description,
			"reason":      hook.Reason,
			"code":        hook.Code,
			"flow_ids":    hook.FlowIDs,
			"frida_hook_args": map[string]any{
				"serial":  serial,
				"target":  target,
				"script":  hook.Code,
				"timeout": 30,
			},
		})
	}
	return out
}

func runtimeValidationSteps(serial, target string, flows, hooks int) []string {
	steps := []string{
		"Run frida_server_status and confirm the target device is reachable.",
	}
	if serial == "" {
		steps = append(steps, "Pick a device serial from device_list and pass it to apk_runtime_plan for ready-to-run frida_hook args.")
	}
	if target == "" {
		steps = append(steps, "Resolve the target package name from apk_triage or apk_list before running Frida.")
	}
	if hooks > 0 {
		steps = append(steps, "Run the selected generated hook with frida_hook or frida_spawn before replaying entrypoint inputs.")
	}
	if flows > 0 {
		steps = append(steps, "Replay adb commands from adb_replay and watch [ENTRY_TRACE] Frida console output for source→sink evidence.")
	}
	steps = append(steps, "If no hook output appears, inspect the exact path:line from flows and retry with a narrower component or spawn-time hook.")
	return steps
}

func dangerousPermissionList(perms []string) []string {
	out := []string{}
	for _, p := range perms {
		switch p {
		case "android.permission.READ_SMS",
			"android.permission.SEND_SMS",
			"android.permission.RECEIVE_SMS",
			"android.permission.READ_CONTACTS",
			"android.permission.WRITE_CONTACTS",
			"android.permission.READ_CALL_LOG",
			"android.permission.WRITE_CALL_LOG",
			"android.permission.RECORD_AUDIO",
			"android.permission.CAMERA",
			"android.permission.ACCESS_FINE_LOCATION",
			"android.permission.ACCESS_BACKGROUND_LOCATION",
			"android.permission.READ_EXTERNAL_STORAGE",
			"android.permission.WRITE_EXTERNAL_STORAGE",
			"android.permission.SYSTEM_ALERT_WINDOW",
			"android.permission.REQUEST_INSTALL_PACKAGES",
			"android.permission.PACKAGE_USAGE_STATS",
			"android.permission.BIND_ACCESSIBILITY_SERVICE",
			"android.permission.BIND_DEVICE_ADMIN":
			out = append(out, p)
		}
	}
	return out
}

func exportedComponents(m *analyzer.ManifestResult) []map[string]any {
	if m == nil {
		return nil
	}
	out := []map[string]any{}
	add := func(kind string, comps []analyzer.Component) {
		for _, c := range comps {
			if c.Exported != nil && *c.Exported {
				out = append(out, map[string]any{
					"type":           kind,
					"name":           c.Name,
					"is_launcher":    c.IsLauncher,
					"intent_filters": len(c.IntentFilters),
				})
			}
		}
	}
	add("activity", m.Activities)
	add("service", m.Services)
	add("receiver", m.Receivers)
	add("provider", m.Providers)
	if len(out) > 50 {
		return out[:50]
	}
	return out
}

func firstStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstCodeFindings(in []analyzer.CodeFinding, n int) []analyzer.CodeFinding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstHosts(in []analyzer.ClassifiedHost, n int) []analyzer.ClassifiedHost {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstIPs(in []analyzer.ClassifiedIP, n int) []analyzer.ClassifiedIP {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstCryptoFindings(in []analyzer.CryptoFinding, n int) []analyzer.CryptoFinding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstConfigs(in []analyzer.ConfigFinding, n int) []analyzer.ConfigFinding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstDetectionFindings(in []analyzer.DetectionFinding, n int) []analyzer.DetectionFinding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstHotMethods(in []analyzer.HotMethod, n int) []analyzer.HotMethod {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstDataFlowPaths(in []analyzer.DataFlowPath, n int) []analyzer.DataFlowPath {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstCallNodes(in []analyzer.CallNode, n int) []analyzer.CallNode {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func firstCallEdges(in []analyzer.CallEdge, n int) []analyzer.CallEdge {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
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

func apkAttackSurfaceSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_attack_surface",
		Description: "Analyze an APK manifest for exported Android attack surface: activities, services, receivers, content providers, " +
			"deeplinks/app links, content:// authorities, and ready-to-replay adb test commands for entrypoint validation.",
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
			if err != nil || apk == nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			manifest, err := analyzer.ParseManifest(apk.FilePath)
			if err != nil {
				return "", err
			}
			result := analyzer.AnalyzeAttackSurface(manifest)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeManifest, manifest)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeAttackSurface, result)
			b, _ := json.Marshal(result)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkEntryTraceSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_entry_trace",
		Description: "Trace exported Android entrypoints from manifest attack surface into decompiled Java/Kotlin/smali handlers. " +
			"Returns matched source files, lifecycle/provider handler methods, external input reads, sink calls, method-local source→sink flow evidence, and adb replay commands.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id":    map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
				"component": map[string]any{"type": "string", "description": "Optional component class/name filter. Empty traces all exported components."},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			component := argString(args, "component")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			apk, err := apkStore.Get(id)
			if err != nil || apk == nil {
				return "", fmt.Errorf("APK not found: %s", id)
			}
			if apk.DecompiledPath == "" {
				return "", fmt.Errorf("APK must be decompiled first")
			}
			manifest, err := analyzer.ParseManifest(apk.FilePath)
			if err != nil {
				return "", err
			}
			result, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, component)
			if err != nil {
				return "", err
			}
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeManifest, manifest)
			saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeEntryTrace, result)
			b, _ := json.Marshal(result)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
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
			"crypto usage, Firebase config, and entry_trace source→sink flows to produce ready-to-run bypass and monitoring hooks.",
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
			var entryTrace *analyzer.EntryTraceResult
			if manifest, err := analyzer.ParseManifest(apk.FilePath); err == nil {
				if et, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, ""); err == nil {
					entryTrace = et
					saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeManifest, manifest)
					saveAPKAnalysis(apkStore, apk.ID, analyzer.TypeEntryTrace, et)
				}
			}
			hooks := fridapkg.GenerateHooksFromAnalysis(antiDetect, cryptoFindings, stringsResult, entryTrace)
			b, _ := json.Marshal(hooks)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkRuntimePlanSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_runtime_plan",
		Description: "Build an execution-ready Android dynamic validation plan from entry_trace source→sink flows, " +
			"ADB replay commands, and generated Frida hooks. It prepares frida_hook arguments but does not touch a device.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"apk_id": map[string]any{"type": "string", "description": "APK ID (from apk_list)."},
				"serial": map[string]any{
					"type":        "string",
					"description": "Optional device serial. If provided, generated frida_hook args are ready to run.",
				},
			},
			"required": []string{"apk_id"},
		},
		Run: func(ctx context.Context, args map[string]any) (string, error) {
			id := argString(args, "apk_id")
			if id == "" {
				return "", fmt.Errorf("apk_id required")
			}
			serial := argString(args, "serial")
			out, err := RunAPKRuntimePlan(apkStore, cfg, id, serial)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(out)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkEvidencePackageSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name: "apk_evidence_package",
		Description: "Export a final Android reverse-engineering evidence package for an APK. " +
			"Combines runtime_plan, persisted runtime_evidence, verified flow details, ADB replay commands, and Markdown/JSON artifacts for reporting.",
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
			out, err := RunAPKEvidencePackage(apkStore, cfg, id)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(out)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkReversePlanSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name:        "apk_reverse_plan",
		Description: "Build a structured Android reverse-engineering plan from available triage, attack surface, entry trace, runtime plan, and runtime evidence analyses. Returns an actionable checklist, confidence indicators, and prioritized next steps.",
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
			out, err := RunAPKReversePlan(apkStore, cfg, id)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(out)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func apkReverseValidateSkill(apkStore *store.APKStore, cfg *config.Config) Skill {
	return Skill{
		Name:        "apk_reverse_validate",
		Description: "Validate an Android reverse-engineering plan against saved analyses and runtime evidence. Returns objective-level verification status and next validation actions.",
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
			out, err := RunAPKReverseValidate(apkStore, cfg, id)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(out)
			return truncate(string(b), cfg.Skills.ShellMaxOutputBytes), nil
		},
	}
}

func RunAPKReversePlan(apkStore *store.APKStore, cfg *config.Config, id string) (map[string]any, error) {
	if apkStore == nil {
		return nil, fmt.Errorf("apk store unavailable")
	}
	apk, err := apkStore.Get(id)
	if err != nil {
		return nil, err
	}
	if apk == nil {
		return nil, fmt.Errorf("APK not found: %s", id)
	}
	pkg := map[string]any{
		"id":              apk.ID,
		"filename":        apk.Filename,
		"package_name":    apk.PackageName,
		"version_name":    apk.VersionName,
		"decompiled_path": apk.DecompiledPath,
		"decompiled_tool": apk.DecompiledTool,
	}
	manifest := (*analyzer.ManifestResult)(nil)
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeManifest); row != nil {
		var parsed analyzer.ManifestResult
		_ = json.Unmarshal([]byte(row.Result), &parsed)
		manifest = &parsed
		if s := strings.TrimSpace(parsed.Package); s != "" {
			pkg["package_name"] = s
		}
		if s := strings.TrimSpace(parsed.VersionName); s != "" {
			pkg["version_name"] = s
		}
	}
	triage := map[string]any{}
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeTriage); row != nil {
		triage = parseReversePlanTriage(row.Result)
	}
	objectives := reversePlanObjectives(triage, map[string]any{})
	for i := range objectives {
		objectives[i]["recommended_tool"] = reverseObjectiveRecommendedTool(objectives[i])
		objectives[i]["api_hint"] = reverseObjectiveAPIHint(fmt.Sprintf("%v", objectives[i]["recommended_tool"]))
		objectives[i]["expected_gain"] = reverseObjectiveExpectedGain(objectives[i])
	}
	sort.SliceStable(objectives, func(i, j int) bool { return reverseObjectivePriority(objectives[i]) > reverseObjectivePriority(objectives[j]) })
	missing := []string{}
	if apk.DecompiledPath == "" {
		missing = append(missing, "apk_decompile")
	}
	readyForValidate := false
	if v, ok := triage["runtime_evidence"]; ok {
		if m, ok2 := v.(map[string]any); ok2 && len(m) > 0 {
			readyForValidate = true
		}
	}
	if !readyForValidate {
		if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
			readyForValidate = true
		}
	}
	out := map[string]any{
		"apk":                  pkg,
		"decompiled_ready":     apk.DecompiledPath != "",
		"missing_analyses":     missing,
		"objectives":           objectives,
		"ready_for_validation": readyForValidate,
		"steps": []map[string]any{
			{"order": 1, "name": "triage_baseline", "tool": "apk_triage", "params": map[string]any{"apk_id": apk.ID}, "why": "Establish manifest/risk/attack-surface/entry-trace/runtime baseline in one pass."},
			{"order": 2, "name": "attack_surface_focus", "tool": "apk_attack_surface", "params": map[string]any{"apk_id": apk.ID}, "why": "Enumerate exported components, deeplinks, and replayable entry points."},
			{"order": 3, "name": "entry_trace_focus", "tool": "apk_entry_trace", "params": map[string]any{"apk_id": apk.ID}, "why": "Map input reads, sinks, and source→sink flows before dynamic work."},
			{"order": 4, "name": "runtime_plan", "tool": "apk_runtime_plan", "params": map[string]any{"apk_id": apk.ID}, "why": "Turn static evidence into ready-to-run replay commands and hook candidates."},
			{"order": 5, "name": "validate", "tool": "apk_reverse_validate", "params": map[string]any{"apk_id": apk.ID}, "why": "Attach runtime evidence to objectives and identify remaining gaps."},
			{"order": 6, "name": "package", "tool": "apk_evidence_package", "params": map[string]any{"apk_id": apk.ID}, "why": "Export markdown/JSON evidence after the plan is verified."},
		},
		"verification_strategy": "plan in narrow slices, validate one objective at a time, and only broaden scope when the current slice is backed by code/path evidence or runtime hits.",
	}
	if manifest != nil {
		out["manifest_hint"] = map[string]any{
			"debuggable":             manifest.Debuggable,
			"allow_backup":           manifest.AllowBackup,
			"uses_cleartext_traffic": manifest.UsesCleartextTraffic,
		}
	}
	return out, nil
}

func RunAPKReverseValidate(apkStore *store.APKStore, cfg *config.Config, id string) (map[string]any, error) {
	if apkStore == nil {
		return nil, fmt.Errorf("apk store unavailable")
	}
	apk, err := apkStore.Get(id)
	if err != nil {
		return nil, err
	}
	if apk == nil {
		return nil, fmt.Errorf("APK not found: %s", id)
	}
	triage := map[string]any{}
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeTriage); row != nil {
		triage = parseReversePlanTriage(row.Result)
	}
	runtimePlan := map[string]any{}
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan); row != nil {
		_ = json.Unmarshal([]byte(row.Result), &runtimePlan)
	}
	runtimeEvidence := map[string]any{}
	if row, _ := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
		if summary, _, ok := analyzer.SummarizeRuntimeEvidenceJSON(row.Result, 20); ok {
			runtimeEvidence = summary
		}
	}
	objectives := reversePlanObjectives(triage, runtimePlan)
	for i := range objectives {
		objectives[i]["recommended_tool"] = reverseObjectiveRecommendedTool(objectives[i])
		objectives[i]["api_hint"] = reverseObjectiveAPIHint(fmt.Sprintf("%v", objectives[i]["recommended_tool"]))
		objectives[i]["expected_gain"] = reverseObjectiveExpectedGain(objectives[i])
	}
	sort.SliceStable(objectives, func(i, j int) bool { return reverseObjectivePriority(objectives[i]) > reverseObjectivePriority(objectives[j]) })
	if len(runtimePlan) > 0 {
		triage["runtime_plan"] = runtimePlan
	}
	if len(runtimeEvidence) > 0 {
		triage["runtime_evidence"] = runtimeEvidence
	}
	verifiedFlows := evidenceStringList(triage["runtime_evidence"])
	if len(verifiedFlows) == 0 {
		verifiedFlows = evidenceStringList(runtimeEvidence["flow_ids"])
	}
	unresolved := []string{}
	for _, obj := range objectives {
		if obj["status"] == "pending" || obj["status"] == "needs_review" {
			unresolved = append(unresolved, fmt.Sprintf("%v", obj["objective"]))
		}
	}
	out := map[string]any{
		"apk": map[string]any{
			"id":           apk.ID,
			"filename":     apk.Filename,
			"package_name": apk.PackageName,
		},
		"objectives":       objectives,
		"unresolved_count": len(unresolved),
		"unresolved":       unresolved,
		"runtime_context": map[string]any{
			"verified_flow_count": len(verifiedFlows),
			"verified_flows":     verifiedFlows,
			"runtime_plan_ready": len(runtimePlan) > 0,
			"runtime_evidence":   runtimeEvidence,
		},
		"next_validation_actions": reversePlanNextValidationActions(objectives, runtimePlan, runtimeEvidence),
	}
	return out, nil
}

func parseReversePlanTriage(raw string) map[string]any {
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return map[string]any{}
	}
	return out
}

func reversePlanObjectives(triage map[string]any, runtimePlanFromRow map[string]any) []map[string]any {
	findings, _ := triage["findings"].(map[string]any)
	manifest, _ := findings[analyzer.TypeManifest].(map[string]any)
	risk, _ := findings[analyzer.TypeRisk].(map[string]any)
	attacks, _ := findings[analyzer.TypeAttackSurface].(map[string]any)
	summary, _ := attacks["summary"].(map[string]any)
	entry, _ := findings[analyzer.TypeEntryTrace].(map[string]any)
	entrySummary, _ := entry["summary"].(map[string]any)
	antiDetect, _ := findings[analyzer.TypeAntiDetect].(map[string]any)
	antiFindings, _ := antiDetect["findings"].([]any)
	entryFlows, _ := entry["flows"].([]any)

	objectives := []map[string]any{
		{"objective": "identify exported components and permissions", "category": "attack_surface", "status": reverseAttackSurfaceStatus(summary)},
		{"objective": "trace external input to sink calls", "category": "entry_trace", "status": reverseEntryTraceStatus(entrySummary)},
		{"objective": "confirm risk posture from manifest and code", "category": "risk", "status": reverseRiskStatus(manifest, risk)},
		{"objective": "build reproducible runtime plan", "category": "dynamic", "status": reverseDynamicPlanStatus(triage, runtimePlanFromRow)},
		{"objective": "validate runtime evidence against flows", "category": "validation", "status": reverseValidationStatus(triage, runtimePlanFromRow)},
	}
	if len(antiFindings) > 0 || len(entryFlows) > 0 {
		objectives = append(objectives, map[string]any{"objective": "address high-signal reverse findings first", "category": "priority", "status": "reviewed"})
	}
	return objectives
}

func reverseAttackSurfaceStatus(summary map[string]any) string {
	if summary == nil {
		return "reviewed"
	}
	if v, ok := toInt(summary["unprotected"]); ok && v > 0 {
		return "needs_review"
	}
	return "reviewed"
}

func reverseEntryTraceStatus(entrySummary map[string]any) string {
	if entrySummary == nil {
		return "reviewed"
	}
	if v, ok := toInt(entrySummary["flows_found"]); ok && v > 0 {
		return "reviewed"
	}
	if v, ok := toInt(entrySummary["handlers_found"]); ok && v > 0 {
		return "reviewed"
	}
	return "pending"
}

func reverseRiskStatus(manifest, risk map[string]any) string {
	if manifest == nil && risk == nil {
		return "reviewed"
	}
	flag := false
	if manifest != nil {
		if v, ok := manifest["debuggable"].(bool); ok {
			flag = flag || v
		}
		if v, ok := manifest["allow_backup"].(bool); ok {
			flag = flag || v
		}
		if v, ok := manifest["uses_cleartext_traffic"].(bool); ok {
			flag = flag || v
		}
	}
	score := 0.0
	if risk != nil {
		if v, ok := risk["score"].(float64); ok {
			score = v
		}
	}
	if flag || score >= 70 {
		return "needs_review"
	}
	if risk != nil {
		return "reviewed"
	}
	return "pending"
}

func reverseDynamicPlanStatus(triage map[string]any, runtimePlanFromRow map[string]any) string {
	if len(runtimePlanFromRow) > 0 {
		return "reviewed"
	}

	if v, ok := triage["runtime_plan"].(map[string]any); ok && len(v) > 0 {
		return "reviewed"
	}
	if v, ok := triage["runtime_evidence"].(map[string]any); ok && len(v) > 0 {
		return "reviewed"
	}
	return "pending"
}

func reverseValidationStatus(triage map[string]any, runtimePlanFromRow map[string]any) string {
	if len(runtimePlanFromRow) > 0 {
		return "verified"
	}

	if v, ok := triage["runtime_evidence"].(map[string]any); ok {
		if flows, ok2 := v["flow_ids"].([]any); ok2 && len(flows) > 0 {
			return "verified"
		}
	}
	return "pending"
}

func reverseObjectivePriority(obj map[string]any) int {
	switch fmt.Sprintf("%v", obj["status"]) {
	case "needs_review":
		return 3
	case "pending":
		return 2
	case "reviewed":
		return 1
	default:
		return 0
	}
}
func reverseObjectiveAPIHint(tool string) string {
	switch tool {
	case "apk_triage":
		return "/api/v1/apk/:id/analyze/triage"
	case "apk_attack_surface":
		return "/api/v1/apk/:id/analyze/attack_surface"
	case "apk_entry_trace":
		return "/api/v1/apk/:id/analyze/entry_trace"
	case "apk_runtime_plan":
		return "/api/v1/apk/:id/runtime_plan"
	case "apk_reverse_validate":
		return "/api/v1/apk/:id/reverse_validate"
	default:
		return "/api/v1/apk/:id/analyze/triage"
	}
}

func reverseObjectiveExpectedGain(obj map[string]any) int {
	status := fmt.Sprintf("%v", obj["status"])
	cat := fmt.Sprintf("%v", obj["category"])
	score := 0
	switch status {
	case "needs_review":
		score += 60
	case "pending":
		score += 40
	case "reviewed":
		score += 5
	default:
		score += 10
	}
	switch cat {
	case "attack_surface":
		score += 20
	case "entry_trace":
		score += 25
	case "risk":
		score += 15
	case "dynamic":
		score += 20
	case "validation":
		score += 15
	case "priority":
		score += 10
	}
	return score
}

func reverseObjectiveRecommendedTool(obj map[string]any) string {
	cat := fmt.Sprintf("%v", obj["category"])
	status := fmt.Sprintf("%v", obj["status"])
	switch cat {
	case "attack_surface":
		return "apk_attack_surface"
	case "entry_trace":
		return "apk_entry_trace"
	case "risk":
		return "apk_triage"
	case "dynamic":
		return "apk_runtime_plan"
	case "validation":
		return "apk_reverse_validate"
	case "priority":
		if status == "needs_review" {
			return "apk_entry_trace"
		}
		return "apk_triage"
	default:
		return "apk_triage"
	}
}

func reversePlanNextValidationActions(objectives []map[string]any, runtimePlan, runtimeEvidence map[string]any) []string {
	out := []string{}
	sorted := append([]map[string]any(nil), objectives...)
	sort.SliceStable(sorted, func(i, j int) bool { return reverseObjectivePriority(sorted[i]) > reverseObjectivePriority(sorted[j]) })
	for _, obj := range sorted {
		if obj["status"] == "needs_review" || obj["status"] == "pending" {
			out = append(out, fmt.Sprintf("resolve objective: %v", obj["objective"]))
		}
	}
	if len(runtimePlan) == 0 {
		out = append(out, "run apk_runtime_plan to generate replay commands and hook candidates")
	}
	if len(runtimeEvidence) == 0 {
		out = append(out, "run generated Frida hooks or replay commands and persist runtime evidence")
	}
	if len(out) == 0 {
		out = append(out, "package verified findings with apk_evidence_package")
	}
	return out
}
