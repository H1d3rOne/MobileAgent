package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobileagent/backend-go/internal/analyzer"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

func TestRegisterBuiltinsIncludesAPKTriage(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	skill, ok := reg.Get("apk_triage")
	if !ok {
		t.Fatal("expected apk_triage skill to be registered")
	}
	if skill.Description == "" {
		t.Fatal("expected apk_triage to have an LLM-facing description")
	}

	tools := reg.AsLLMTools()
	var found bool
	for _, tool := range tools {
		if tool.Function.Name != "apk_triage" {
			continue
		}
		found = true
		props, ok := tool.Function.Parameters["properties"].(map[string]any)
		if !ok {
			t.Fatalf("expected apk_triage properties schema, got %#v", tool.Function.Parameters["properties"])
		}
		if _, ok := props["apk_id"]; !ok {
			t.Fatal("expected apk_triage schema to require apk_id")
		}
		if _, ok := props["include_callgraph"]; !ok {
			t.Fatal("expected apk_triage schema to expose include_callgraph option")
		}
	}
	if !found {
		t.Fatal("expected apk_triage to be exposed as an LLM tool")
	}

	attackSurface, ok := reg.Get("apk_attack_surface")
	if !ok {
		t.Fatal("expected apk_attack_surface skill to be registered")
	}
	if attackSurface.Description == "" {
		t.Fatal("expected apk_attack_surface to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_attack_surface"); !ok {
		t.Fatal("expected apk_attack_surface metadata")
	}

	entryTrace, ok := reg.Get("apk_entry_trace")
	if !ok {
		t.Fatal("expected apk_entry_trace skill to be registered")
	}
	if entryTrace.Description == "" {
		t.Fatal("expected apk_entry_trace to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_entry_trace"); !ok {
		t.Fatal("expected apk_entry_trace metadata")
	}

	runtimePlan, ok := reg.Get("apk_runtime_plan")
	if !ok {
		t.Fatal("expected apk_runtime_plan skill to be registered")
	}
	if runtimePlan.Description == "" {
		t.Fatal("expected apk_runtime_plan to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_runtime_plan"); !ok {
		t.Fatal("expected apk_runtime_plan metadata")
	}

	evidencePackage, ok := reg.Get("apk_evidence_package")
	if !ok {
		t.Fatal("expected apk_evidence_package skill to be registered")
	}
	if evidencePackage.Description == "" {
		t.Fatal("expected apk_evidence_package to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_evidence_package"); !ok {
		t.Fatal("expected apk_evidence_package metadata")
	}
}

func TestRegisterBuiltinsMarksDangerousTools(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	for _, name := range []string{
		"device_shell",
		"device_install_apk",
		"local_shell",
		"termux_shell",
		"frida_hook",
		"frida_eval",
		"frida_spawn",
		"frida_run_script",
	} {
		if !reg.IsDangerous(name) {
			t.Fatalf("expected %s to be marked dangerous", name)
		}
		meta, ok := reg.Metadata(name)
		if !ok {
			t.Fatalf("expected metadata for %s", name)
		}
		if !meta.Builtin || meta.Source != "builtin" {
			t.Fatalf("expected builtin metadata for %s, got %#v", name, meta)
		}
	}

	for _, name := range []string{
		"apk_triage",
		"apk_attack_surface",
		"apk_entry_trace",
		"apk_strings",
		"apk_callgraph",
		"apk_generate_hooks",
		"apk_runtime_plan",
		"apk_evidence_package",
		"file_read",
		"code_search",
		"device_list",
	} {
		if reg.IsDangerous(name) {
			t.Fatalf("expected %s to stay non-dangerous", name)
		}
	}
}

func TestRegisterBuiltinsIncludesAPKReversePlanValidate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	for _, name := range []string{"apk_reverse_plan", "apk_reverse_validate"} {
		skill, ok := reg.Get(name)
		if !ok {
			t.Fatalf("expected %s skill to be registered", name)
		}
		if skill.Description == "" {
			t.Fatalf("expected %s to have an LLM-facing description", name)
		}
		if reg.IsDangerous(name) {
			t.Fatalf("expected %s to stay non-dangerous", name)
		}
	}
}

func TestRunAPKReversePlanBuildsChecklist(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()
	apkStore := store.NewAPKStore(s)

	apkPath := filepath.Join(tmp, "sample.apk")
	mustWriteFile(t, apkPath, "apk")
	apk := &model.APK{
		ID:          util.NewID(),
		Filename:    "sample.apk",
		FilePath:    apkPath,
		PackageName: "com.example.app",
		Status:      "uploaded",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:     util.NewID(),
		APKID:  apk.ID,
		Type:   analyzer.TypeTriage,
		Result: `{"findings":{"manifest":{"debuggable":false},"risk":{"score":30},"attack_surface":{"summary":{"exported":0,"unprotected":0}},"entry_trace":{"summary":{"handlers_found":1,"flows_found":1},"flows":[{"flow_id":"flow-001"}]},"runtime_evidence":{"flow_ids":["flow-001"]},"runtime_plan":{"flows":[{"flow_id":"flow-001"}]}},"runtime_plan":{"flows":[{"flow_id":"flow-001"}]},"runtime_evidence":{"flow_ids":["flow-001"]},"next_steps":["step"]}`,
	}); err != nil {
		t.Fatalf("create triage: %v", err)
	}

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.UploadDir = tmp

	out, err := RunAPKReversePlan(apkStore, cfg, apk.ID)
	if err != nil {
		t.Fatalf("RunAPKReversePlan: %v", err)
	}
	if out["decompiled_ready"] != false {
		t.Fatalf("expected decompiled_ready=false, got %#v", out["decompiled_ready"])
	}
	if out["ready_for_validation"] != true {
		t.Fatalf("expected ready_for_validation=true, got %#v", out["ready_for_validation"])
	}
	objectives, ok := out["objectives"].([]map[string]any)
	if !ok || len(objectives) < 5 {
		t.Fatalf("expected structured objectives, got %#v", out["objectives"])
	}
	for _, want := range []string{"identify exported components and permissions", "trace external input to sink calls", "confirm risk posture from manifest and code", "build reproducible runtime plan", "validate runtime evidence against flows"} {
		var found map[string]any
		for _, obj := range objectives {
			if obj["objective"] == want {
				found = obj
				break
			}
		}
		if found == nil {
			t.Fatalf("missing objective %q in %#v", want, objectives)
		}
		if found["status"] == "" {
			t.Fatalf("expected status for objective %q", want)
		}
	}
	steps, ok := out["steps"].([]map[string]any)
	if !ok || len(steps) == 0 {
		t.Fatalf("expected step plan, got %#v", out["steps"])
	}
	if steps[len(steps)-1]["name"] != "package" {
		t.Fatalf("expected last step to be package, got %#v", steps[len(steps)-1])
	}
}

func TestRunAPKReverseValidateMarksVerified(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()
	apkStore := store.NewAPKStore(s)

	apkPath := filepath.Join(tmp, "sample.apk")
	mustWriteFile(t, apkPath, "apk")
	apk := &model.APK{
		ID:          util.NewID(),
		Filename:    "sample.apk",
		FilePath:    apkPath,
		PackageName: "com.example.app",
		Status:      "uploaded",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:     util.NewID(),
		APKID:  apk.ID,
		Type:   analyzer.TypeTriage,
		Result: `{"findings":{"manifest":{"debuggable":false},"risk":{"score":30},"attack_surface":{"summary":{"exported":0,"unprotected":0}},"entry_trace":{"summary":{"handlers_found":1,"flows_found":1},"flows":[{"flow_id":"flow-001"}]},"runtime_evidence":{"flow_ids":["flow-001"]},"runtime_plan":{"flows":[{"flow_id":"flow-001"}]}},"runtime_plan":{"flows":[{"flow_id":"flow-001"}]},"runtime_evidence":{"flow_ids":["flow-001"]}}`,
	}); err != nil {
		t.Fatalf("create triage: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:     util.NewID(),
		APKID:  apk.ID,
		Type:   analyzer.TypeRuntimePlan,
		Result: `{"flows":[{"flow_id":"flow-001"}]}`,
	}); err != nil {
		t.Fatalf("create runtime plan: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:     util.NewID(),
		APKID:  apk.ID,
		Type:   analyzer.TypeRuntimeEvidence,
		Result: `{"evidence":{"summary":{"total":1,"flow_ids":["flow-001"]}}}`,
	}); err != nil {
		t.Fatalf("create runtime evidence: %v", err)
	}

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.UploadDir = tmp

	out, err := RunAPKReverseValidate(apkStore, cfg, apk.ID)
	if err != nil {
		t.Fatalf("RunAPKReverseValidate: %v", err)
	}
	if out["unresolved_count"] != 0 {
		t.Fatalf("expected unresolved_count=0, got %#v", out["unresolved_count"])
	}
	objectives, ok := out["objectives"].([]map[string]any)
	if !ok {
		t.Fatalf("expected objectives, got %#v", out["objectives"])
	}
	for _, obj := range objectives {
		if obj["objective"] == "validate runtime evidence against flows" && obj["status"] != "verified" {
			t.Fatalf("expected validation objective verified, got %#v", obj)
		}
	}
}

func TestRunAPKTriageAggregatesAndPersistsAnalyses(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	writeExecutable(t, filepath.Join(binDir, "aapt"), `#!/bin/sh
if [ "$1" = "dump" ] && [ "$2" = "badging" ]; then
cat <<'EOF'
package: name='com.example.app' versionCode='42' versionName='1.2.3'
sdkVersion:'21'
targetSdkVersion:'33'
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.SYSTEM_ALERT_WINDOW'
launchable-activity: name='com.example.MainActivity'
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "xmltree" ]; then
cat <<'EOF'
E: manifest (line=2)
  E: application (line=10)
    A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
    A: android:allowBackup(0x01010280)=(type 0x12)0xffffffff
    A: android:usesCleartextTraffic(0x01010527)=(type 0x12)0xffffffff
    E: activity (line=20)
      A: android:name(0x01010003)="com.example.MainActivity"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=21)
        E: action (line=22)
          A: android:name(0x01010003)="android.intent.action.VIEW"
        E: category (line=23)
          A: android:name(0x01010003)="android.intent.category.BROWSABLE"
        E: data (line=24)
          A: android:scheme(0x01010027)="demo"
          A: android:host(0x01010028)="open"
    E: provider (line=30)
      A: android:name(0x01010003)="com.example.PublicProvider"
      A: android:authorities(0x01010018)="com.example.app.public"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "permissions" ]; then
cat <<'EOF'
uses-permission: name='android.permission.CAMERA'
uses-permission: name='android.permission.SYSTEM_ALERT_WINDOW'
EOF
exit 0
fi
echo "unexpected args: $@" >&2
exit 1
`)

	writeExecutable(t, filepath.Join(binDir, "apksigner"), `#!/bin/sh
cat <<'EOF'
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Signer #1 certificate DN: CN=Android Debug, O=Android, C=US
Signer #1 certificate SHA-1 digest: AA:BB:CC:DD
Signer #1 certificate SHA-256 digest: 11:22:33:44
EOF
`)

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	decompiledDir := filepath.Join(tmp, "decompiled")
	mustMkdirAll(t, filepath.Join(decompiledDir, "sources", "com", "example"))
	mustMkdirAll(t, filepath.Join(decompiledDir, "sources", "com", "google", "firebase", "analytics"))
	mustMkdirAll(t, filepath.Join(decompiledDir, "assets"))
	mustMkdirAll(t, filepath.Join(decompiledDir, "lib", "arm64-v8a"))

	mustWriteFile(t, filepath.Join(decompiledDir, "classes.dex"), "dex")
	mustWriteFile(t, filepath.Join(decompiledDir, "lib", "arm64-v8a", "libjiagu.so"), "so")
	mustWriteFile(t, filepath.Join(decompiledDir, "sources", "com", "google", "firebase", "analytics", "Stub.java"), `package com.google.firebase.analytics;`)
	mustWriteFile(t, filepath.Join(decompiledDir, "assets", "google-services.json"), `{
  "project_info": {
    "project_number": "123456789",
    "project_id": "demo-project",
    "storage_bucket": "demo-project.appspot.com"
  },
  "client": [{
    "client_info": {
      "mobilesdk_app_id": "1:123456789:android:abcdef"
    },
    "api_key": [{
      "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }]
  }]
}`)
	mustWriteFile(t, filepath.Join(decompiledDir, "sources", "com", "example", "MainActivity.java"), `package com.example;

public class MainActivity {
  String api_key = "ABCDEFGHIJKLMNOPQRSTUV";
  String endpoint = "https://api.example.com/login";
  String ip = "8.8.8.8";

  protected void onCreate(android.os.Bundle b) throws Exception {
    String token = getIntent().getStringExtra("token");
    Runtime.getRuntime().exec(token);
    javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
    android.os.Debug.isDebuggerConnected();
    String frida = "frida-server";
    setJavaScriptEnabled(true);
  }

  private void setJavaScriptEnabled(boolean enabled) {}
}`)

	dbPath := filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()
	apkStore := store.NewAPKStore(s)

	apkPath := filepath.Join(tmp, "sample.apk")
	mustWriteFile(t, apkPath, "apk")
	apk := &model.APK{
		ID:             util.NewID(),
		Filename:       "sample.apk",
		FilePath:       apkPath,
		PackageName:    "com.example.app",
		VersionName:    "1.2.3",
		VersionCode:    42,
		DecompiledPath: decompiledDir,
		DecompiledTool: "jadx",
		Status:         "decompiled",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apk.ID,
		Type:      analyzer.TypeRuntimeEvidence,
		Result:    `{"apk_id":"` + apk.ID + `","hook_id":"gen-entry-trace-exec-monitor","evidence":{"summary":{"total":1,"entry_trace":1,"by_kind":{"exec":1}},"events":[{"kind":"exec","operation":"Runtime.exec(String)","value":"id","flow_ids":["flow-001"],"raw":"raw"}]}}`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create runtime evidence analysis: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apk.ID,
		Type:      analyzer.TypeRuntimePlan,
		Result:    `{"flows":[{"flow_id":"flow-001","component":"com.example.MainActivity","method":"onCreate","file":"sources/com/example/MainActivity.java","risk":"high","source":{"kind":"intent_extra","line":10},"sink":{"kind":"command_exec","pattern":"Runtime.exec","line":11},"variables":["token"]}]}`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create runtime plan analysis: %v", err)
	}

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.UploadDir = tmp

	out, err := RunAPKTriage(apkStore, cfg, apk.ID, false)
	if err != nil {
		t.Fatalf("RunAPKTriage: %v", err)
	}

	coverage, ok := out["coverage"].(map[string]string)
	if !ok {
		t.Fatalf("expected coverage map[string]string, got %#v", out["coverage"])
	}
	for _, typ := range []string{
		analyzer.TypeManifest,
		analyzer.TypeCertificate,
		analyzer.TypeRisk,
		analyzer.TypeAttackSurface,
		analyzer.TypeEntryTrace,
		analyzer.TypePacker,
		analyzer.TypeCode,
		analyzer.TypeSDK,
		analyzer.TypeStrings,
		analyzer.TypeAntiDetect,
		analyzer.TypeRuntimeEvidence,
	} {
		if coverage[typ] != "ok" {
			t.Fatalf("expected coverage[%s]=ok, got %q", typ, coverage[typ])
		}
	}
	if coverage[analyzer.TypeCallGraph] != "skipped: include_callgraph=false" {
		t.Fatalf("unexpected callgraph coverage: %q", coverage[analyzer.TypeCallGraph])
	}

	findings, ok := out["findings"].(map[string]any)
	if !ok {
		t.Fatalf("expected findings map, got %#v", out["findings"])
	}
	risk, ok := findings[analyzer.TypeRisk].(map[string]any)
	if !ok {
		t.Fatalf("expected risk summary, got %#v", findings[analyzer.TypeRisk])
	}
	if score, _ := risk["score"].(float64); score < 60 {
		t.Fatalf("expected elevated risk score, got %#v", risk["score"])
	}
	if attackSurface, ok := findings[analyzer.TypeAttackSurface].(map[string]any); !ok {
		t.Fatalf("expected attack surface summary, got %#v", findings[analyzer.TypeAttackSurface])
	} else if summary, ok := attackSurface["summary"].(analyzer.AttackSurfaceSummary); !ok || summary.Unprotected == 0 {
		t.Fatalf("expected unprotected attack surface, got %#v", attackSurface["summary"])
	}
	if entryTrace, ok := findings[analyzer.TypeEntryTrace].(map[string]any); !ok {
		t.Fatalf("expected entry trace summary, got %#v", findings[analyzer.TypeEntryTrace])
	} else if summary, ok := entryTrace["summary"].(analyzer.EntryTraceSummary); !ok || summary.Components == 0 || summary.FilesMatched == 0 || summary.FlowsFound == 0 {
		t.Fatalf("expected matched entry trace, got %#v", entryTrace["summary"])
	}
	if packer, ok := findings[analyzer.TypePacker].(map[string]any); !ok || packer["has_packer"] != true {
		t.Fatalf("expected packer detection, got %#v", findings[analyzer.TypePacker])
	}
	if hooks, ok := findings["generated_hooks"].(map[string]any); !ok || hooks["count"] == nil {
		t.Fatalf("expected generated hooks summary, got %#v", findings["generated_hooks"])
	} else {
		sample, _ := hooks["sample"].([]map[string]string)
		var foundEntryTraceHook bool
		for _, h := range sample {
			if h["id"] == "gen-entry-trace-exec-monitor" && h["category"] == "entry-trace" {
				foundEntryTraceHook = true
				break
			}
		}
		if !foundEntryTraceHook {
			t.Fatalf("expected generated entry-trace hook sample, got %#v", hooks)
		}
	}
	if runtimeEvidence, ok := findings[analyzer.TypeRuntimeEvidence].(map[string]any); !ok || runtimeEvidence["entry_trace"] != 1 {
		t.Fatalf("expected runtime evidence summary, got %#v", findings[analyzer.TypeRuntimeEvidence])
	} else if verified, _ := runtimeEvidence["verified_flows"].([]map[string]any); len(verified) != 1 || verified[0]["flow_id"] != "flow-001" {
		t.Fatalf("expected verified runtime flow, got %#v", runtimeEvidence["verified_flows"])
	}

	nextSteps, ok := out["next_steps"].([]string)
	if !ok || len(nextSteps) == 0 {
		t.Fatalf("expected non-empty next_steps, got %#v", out["next_steps"])
	}
	var foundEntryTraceHookStep bool
	for _, step := range nextSteps {
		if strings.Contains(step, "entry-trace Frida monitors") {
			foundEntryTraceHookStep = true
			break
		}
	}
	if !foundEntryTraceHookStep {
		t.Fatalf("expected entry-trace hook next step, got %#v", nextSteps)
	}

	plan, err := RunAPKRuntimePlan(apkStore, cfg, apk.ID, "emulator-5554")
	if err != nil {
		t.Fatalf("RunAPKRuntimePlan: %v", err)
	}
	target, ok := plan["target"].(map[string]any)
	if !ok || target["ready_to_run"] != true || target["serial"] != "emulator-5554" || target["package"] != "com.example.app" {
		t.Fatalf("expected ready runtime target, got %#v", plan["target"])
	}
	flows, ok := plan["flows"].([]map[string]any)
	if !ok || len(flows) == 0 {
		t.Fatalf("expected runtime plan flows, got %#v", plan["flows"])
	}
	if flows[0]["flow_id"] == "" {
		t.Fatalf("expected runtime plan flow_id, got %#v", flows[0])
	}
	replay, ok := plan["adb_replay"].([]string)
	if !ok || len(replay) == 0 {
		t.Fatalf("expected runtime plan adb replay commands, got %#v", plan["adb_replay"])
	}
	runtimeHooks, ok := plan["generated_hooks"].([]map[string]any)
	if !ok || len(runtimeHooks) == 0 {
		t.Fatalf("expected runtime plan generated hooks, got %#v", plan["generated_hooks"])
	}
	var foundReadyHook bool
	for _, h := range runtimeHooks {
		if h["id"] != "gen-entry-trace-exec-monitor" {
			continue
		}
		flowIDs, _ := h["flow_ids"].([]string)
		if len(flowIDs) == 0 || flowIDs[0] != flows[0]["flow_id"] {
			t.Fatalf("expected runtime hook flow_ids to align with runtime plan flows, hook=%#v flows=%#v", h, flows)
		}
		args, _ := h["frida_hook_args"].(map[string]any)
		if args["serial"] == "emulator-5554" && args["target"] == "com.example.app" && args["script"] != "" {
			foundReadyHook = true
			break
		}
	}
	if !foundReadyHook {
		t.Fatalf("expected ready entry-trace frida_hook args, got %#v", runtimeHooks)
	}

	evidencePackage, err := RunAPKEvidencePackage(apkStore, cfg, apk.ID)
	if err != nil {
		t.Fatalf("RunAPKEvidencePackage: %v", err)
	}
	if md := evidencePackage["markdown"].(string); !strings.Contains(md, "Verified Flows") || !strings.Contains(md, "flow-001") {
		t.Fatalf("expected evidence package markdown with verified flow, got:\n%s", md)
	}
	runtimeEvidence, ok := evidencePackage["runtime_evidence"].(map[string]any)
	if !ok || len(runtimeEvidence) == 0 {
		t.Fatalf("expected evidence package runtime evidence, got %#v", evidencePackage["runtime_evidence"])
	}
	artifacts, ok := evidencePackage["artifacts"].(map[string]string)
	if !ok || artifacts["markdown"] == "" || artifacts["json"] == "" {
		t.Fatalf("expected evidence package artifact paths, got %#v", evidencePackage["artifacts"])
	}
	if _, err := os.Stat(artifacts["markdown"]); err != nil {
		t.Fatalf("expected markdown artifact: %v", err)
	}
	if _, err := os.Stat(artifacts["json"]); err != nil {
		t.Fatalf("expected json artifact: %v", err)
	}

	for _, typ := range []string{
		analyzer.TypeManifest,
		analyzer.TypeCertificate,
		analyzer.TypeRisk,
		analyzer.TypeAttackSurface,
		analyzer.TypeEntryTrace,
		analyzer.TypePacker,
		analyzer.TypeCode,
		analyzer.TypeSDK,
		analyzer.TypeStrings,
		analyzer.TypeAntiDetect,
	} {
		row, err := apkStore.GetAnalysisByType(apk.ID, typ)
		if err != nil {
			t.Fatalf("get saved analysis %s: %v", typ, err)
		}
		if row == nil {
			t.Fatalf("expected saved analysis for %s", typ)
		}
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
