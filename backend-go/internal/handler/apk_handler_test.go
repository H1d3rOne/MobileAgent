package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mobileagent/backend-go/internal/analyzer"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

func TestAPKHandlerAnalyzeTriageEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	mustMkdirAllHandlerTest(t, binDir)
	writeExecutableHandlerTest(t, filepath.Join(binDir, "aapt"), `#!/bin/sh
if [ "$1" = "dump" ] && [ "$2" = "badging" ]; then
cat <<'EOF'
package: name='com.example.http' versionCode='7' versionName='0.7.0'
sdkVersion:'23'
targetSdkVersion:'34'
uses-permission: name='android.permission.CAMERA'
launchable-activity: name='com.example.MainActivity'
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "xmltree" ]; then
cat <<'EOF'
E: manifest (line=2)
  E: application (line=10)
    A: android:allowBackup(0x01010280)=(type 0x12)0xffffffff
    E: activity (line=20)
      A: android:name(0x01010003)="com.example.MainActivity"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=21)
        E: action (line=22)
          A: android:name(0x01010003)="android.intent.action.VIEW"
        E: category (line=23)
          A: android:name(0x01010003)="android.intent.category.BROWSABLE"
        E: data (line=24)
          A: android:scheme(0x01010027)="https"
          A: android:host(0x01010028)="example.test"
    E: provider (line=30)
      A: android:name(0x01010003)="com.example.PublicProvider"
      A: android:authorities(0x01010018)="com.example.http.public"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "permissions" ]; then
cat <<'EOF'
uses-permission: name='android.permission.CAMERA'
EOF
exit 0
fi
echo "unexpected aapt args: $@" >&2
exit 1
`)
	writeExecutableHandlerTest(t, filepath.Join(binDir, "apksigner"), `#!/bin/sh
cat <<'EOF'
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Signer #1 certificate DN: CN=Release, O=Example, C=US
Signer #1 certificate SHA-1 digest: AA:BB:CC
Signer #1 certificate SHA-256 digest: 11:22:33
EOF
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	decompiledDir := filepath.Join(tmp, "decompiled")
	mustMkdirAllHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example"))
	mustMkdirAllHandlerTest(t, filepath.Join(decompiledDir, "smali", "com", "example"))
	mustWriteFileHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example", "MainActivity.java"), `package com.example;
class MainActivity {
  String endpoint = "https://api.example.test/v1/login";
  void run() throws Exception {
    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    android.os.Debug.isDebuggerConnected();
  }
}`)
	mustWriteFileHandlerTest(t, filepath.Join(decompiledDir, "smali", "com", "example", "MainActivity.smali"), `.class public Lcom/example/MainActivity;
.super Ljava/lang/Object;
.method public onCreate()V
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    return-void
.end method
`)

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.UploadDir = filepath.Join(tmp, "uploads")
	cfg.Storage.DBPath = filepath.Join(tmp, "mobileagent.db")
	cfg.Skills.ShellMaxOutputBytes = 65536

	s, err := store.NewStore(cfg.Storage.DBPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()

	apkStore := store.NewAPKStore(s)
	apkPath := filepath.Join(tmp, "sample.apk")
	mustWriteFileHandlerTest(t, apkPath, "apk")
	apk := &model.APK{
		ID:             util.NewID(),
		Filename:       "sample.apk",
		FilePath:       apkPath,
		PackageName:    "com.example.http",
		DecompiledPath: decompiledDir,
		DecompiledTool: "jadx",
		Status:         "decompiled",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}

	h := NewAPKHandler(apkStore, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.POST("/api/v1/apk/:id/analyze/triage", h.AnalyzeTriage)

	body := bytes.NewBufferString(`{"include_callgraph":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/apk/"+apk.ID+"/analyze/triage", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success response, got %#v", resp)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %#v", resp.Data)
	}
	coverage, ok := data["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("expected coverage map, got %#v", data["coverage"])
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
		analyzer.TypeCallGraph,
	} {
		if coverage[typ] != "ok" {
			t.Fatalf("expected coverage[%s]=ok, got %#v", typ, coverage[typ])
		}
	}
	if steps, ok := data["next_steps"].([]any); !ok || len(steps) == 0 {
		t.Fatalf("expected non-empty next_steps, got %#v", data["next_steps"])
	}

	for _, typ := range []string{
		analyzer.TypeTriage,
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
		analyzer.TypeCallGraph,
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

func writeExecutableHandlerTest(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func mustMkdirAllHandlerTest(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFileHandlerTest(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func TestAPKHandlerBrowseFileScopedToWorkspace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	decompiledDir := filepath.Join(workspace, "decompiled", "sample")
	mustMkdirAllHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example"))
	mustWriteFileHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example", "MainActivity.java"), "class MainActivity {}")

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = workspace
	h := NewAPKHandler(nil, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.GET("/api/v1/apk/file", h.BrowseFile)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/apk/file?dir="+decompiledDir+"&file=sources/com/example/MainActivity.java", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success response, got %#v", resp)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %#v", resp.Data)
	}
	if got := data["content"]; got != "class MainActivity {}" {
		t.Fatalf("unexpected content: %#v", got)
	}
}

func TestAPKHandlerBrowseFileRejectsPathTraversal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	decompiledDir := filepath.Join(workspace, "decompiled", "sample")
	mustMkdirAllHandlerTest(t, decompiledDir)
	mustWriteFileHandlerTest(t, filepath.Join(workspace, "secret.txt"), "secret")

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = workspace
	h := NewAPKHandler(nil, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.GET("/api/v1/apk/file", h.BrowseFile)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/apk/file?dir="+decompiledDir+"&file=../../secret.txt", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPKHandlerBrowseFileRejectsDirOutsideWorkspace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	outside := filepath.Join(tmp, "outside")
	mustMkdirAllHandlerTest(t, outside)
	mustMkdirAllHandlerTest(t, workspace)
	mustWriteFileHandlerTest(t, filepath.Join(outside, "note.txt"), "outside")

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = workspace
	h := NewAPKHandler(nil, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.GET("/api/v1/apk/file", h.BrowseFile)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/apk/file?dir="+outside+"&file=note.txt", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPKHandlerAnalyzeAttackSurfaceEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	mustMkdirAllHandlerTest(t, binDir)
	writeExecutableHandlerTest(t, filepath.Join(binDir, "aapt"), `#!/bin/sh
if [ "$1" = "dump" ] && [ "$2" = "badging" ]; then
cat <<'EOF'
package: name='com.example.surface' versionCode='1' versionName='1.0'
sdkVersion:'23'
targetSdkVersion:'34'
launchable-activity: name='com.example.surface.MainActivity'
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "xmltree" ]; then
cat <<'EOF'
E: manifest (line=2)
  E: application (line=10)
    E: activity (line=20)
      A: android:name(0x01010003)=".DeepLinkActivity"
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
      A: android:name(0x01010003)=".PublicProvider"
      A: android:authorities(0x01010018)="com.example.surface.public"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "permissions" ]; then
exit 0
fi
echo "unexpected aapt args: $@" >&2
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.DBPath = filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(cfg.Storage.DBPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()

	apkStore := store.NewAPKStore(s)
	apkPath := filepath.Join(tmp, "surface.apk")
	mustWriteFileHandlerTest(t, apkPath, "apk")
	apk := &model.APK{ID: util.NewID(), Filename: "surface.apk", FilePath: apkPath}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}

	h := NewAPKHandler(apkStore, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.POST("/api/v1/apk/:id/analyze/attack_surface", h.AnalyzeAttackSurface)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/apk/"+apk.ID+"/analyze/attack_surface", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %#v", resp.Data)
	}
	summary, ok := data["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary map, got %#v", data["summary"])
	}
	if summary["exported_activities"] != float64(1) || summary["exported_providers"] != float64(1) {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if summary["deep_links"] != float64(1) {
		t.Fatalf("expected one deeplink, got %#v", summary)
	}
	row, err := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeAttackSurface)
	if err != nil {
		t.Fatalf("get saved analysis: %v", err)
	}
	if row == nil {
		t.Fatal("expected saved attack_surface analysis")
	}
}

func TestAPKHandlerAnalyzeEntryTraceEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	mustMkdirAllHandlerTest(t, binDir)
	writeExecutableHandlerTest(t, filepath.Join(binDir, "aapt"), `#!/bin/sh
if [ "$1" = "dump" ] && [ "$2" = "badging" ]; then
cat <<'EOF'
package: name='com.example.entry' versionCode='1' versionName='1.0'
sdkVersion:'23'
targetSdkVersion:'34'
launchable-activity: name='com.example.entry.MainActivity'
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "xmltree" ]; then
cat <<'EOF'
E: manifest (line=2)
  E: application (line=10)
    E: activity (line=20)
      A: android:name(0x01010003)=".DeepLinkActivity"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=21)
        E: action (line=22)
          A: android:name(0x01010003)="android.intent.action.VIEW"
        E: category (line=23)
          A: android:name(0x01010003)="android.intent.category.BROWSABLE"
        E: data (line=24)
          A: android:scheme(0x01010027)="entry"
          A: android:host(0x01010028)="open"
EOF
exit 0
fi
if [ "$1" = "dump" ] && [ "$2" = "permissions" ]; then
exit 0
fi
echo "unexpected aapt args: $@" >&2
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	decompiledDir := filepath.Join(tmp, "decompiled")
	mustMkdirAllHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example", "entry"))
	mustWriteFileHandlerTest(t, filepath.Join(decompiledDir, "sources", "com", "example", "entry", "DeepLinkActivity.java"), `package com.example.entry;
class DeepLinkActivity {
  Object webView;
  protected void onCreate(android.os.Bundle b) {
    android.net.Uri u = getIntent().getData();
    String token = u.getQueryParameter("token");
    webView.loadUrl(token);
  }
}`)

	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = tmp
	cfg.Storage.DBPath = filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(cfg.Storage.DBPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()

	apkStore := store.NewAPKStore(s)
	apkPath := filepath.Join(tmp, "entry.apk")
	mustWriteFileHandlerTest(t, apkPath, "apk")
	apk := &model.APK{
		ID:             util.NewID(),
		Filename:       "entry.apk",
		FilePath:       apkPath,
		DecompiledPath: decompiledDir,
		DecompiledTool: "jadx",
		Status:         "decompiled",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}

	h := NewAPKHandler(apkStore, runner.NewAPKRunner(cfg), cfg)
	r := gin.New()
	r.POST("/api/v1/apk/:id/analyze/entry_trace", h.AnalyzeEntryTrace)
	r.GET("/api/v1/apk/:id/hooks", h.GenerateHooks)
	r.POST("/api/v1/apk/:id/runtime_plan", h.RuntimePlan)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/apk/"+apk.ID+"/analyze/entry_trace", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success response, got %#v", resp)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %#v", resp.Data)
	}
	summary, ok := data["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary map, got %#v", data["summary"])
	}
	if summary["files_matched"] != float64(1) {
		t.Fatalf("expected one matched file, got %#v", summary)
	}
	if summary["handlers_found"] == float64(0) || summary["input_signals_found"] == float64(0) || summary["sink_signals_found"] == float64(0) {
		t.Fatalf("expected handler/input/sink signals, got %#v", summary)
	}
	if summary["flows_found"] == float64(0) {
		t.Fatalf("expected source-to-sink flows, got %#v", summary)
	}
	row, err := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeEntryTrace)
	if err != nil {
		t.Fatalf("get saved analysis: %v", err)
	}
	if row == nil {
		t.Fatal("expected saved entry_trace analysis")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/apk/"+apk.ID+"/hooks", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for generated hooks, got %d: %s", rec.Code, rec.Body.String())
	}
	resp = model.APIResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode hooks response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected hooks success response, got %#v", resp)
	}
	hooksData, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected hooks data map, got %#v", resp.Data)
	}
	hooks, ok := hooksData["hooks"].([]any)
	if !ok || len(hooks) == 0 {
		t.Fatalf("expected generated hooks list, got %#v", hooksData)
	}
	var foundEntryTraceHook bool
	for _, raw := range hooks {
		hook, _ := raw.(map[string]any)
		if hook["id"] == "gen-entry-trace-webview-monitor" && hook["category"] == "entry-trace" {
			foundEntryTraceHook = true
			break
		}
	}
	if !foundEntryTraceHook {
		t.Fatalf("expected entry-trace WebView monitor hook, got %#v", hooks)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/apk/"+apk.ID+"/runtime_plan", bytes.NewBufferString(`{"serial":"emulator-5554"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for runtime plan, got %d: %s", rec.Code, rec.Body.String())
	}
	resp = model.APIResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode runtime plan response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected runtime plan success response, got %#v", resp)
	}
	plan, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected runtime plan data map, got %#v", resp.Data)
	}
	target, ok := plan["target"].(map[string]any)
	if !ok || target["ready_to_run"] != true || target["serial"] != "emulator-5554" || target["package"] != "com.example.entry" {
		t.Fatalf("expected ready runtime target, got %#v", plan["target"])
	}
	flows, ok := plan["flows"].([]any)
	if !ok || len(flows) == 0 {
		t.Fatalf("expected runtime plan flows, got %#v", plan["flows"])
	}
	firstFlow, _ := flows[0].(map[string]any)
	if firstFlow["flow_id"] == "" {
		t.Fatalf("expected runtime plan flow_id, got %#v", firstFlow)
	}
	replay, ok := plan["adb_replay"].([]any)
	if !ok || len(replay) == 0 {
		t.Fatalf("expected runtime plan adb replay commands, got %#v", plan["adb_replay"])
	}
	planHooks, ok := plan["generated_hooks"].([]any)
	if !ok || len(planHooks) == 0 {
		t.Fatalf("expected runtime plan hooks, got %#v", plan["generated_hooks"])
	}
	var foundReadyArgs bool
	for _, raw := range planHooks {
		hook, _ := raw.(map[string]any)
		if hook["id"] != "gen-entry-trace-webview-monitor" {
			continue
		}
		args, _ := hook["frida_hook_args"].(map[string]any)
		if args["serial"] == "emulator-5554" && args["target"] == "com.example.entry" && args["script"] != "" {
			foundReadyArgs = true
			break
		}
	}
	if !foundReadyArgs {
		t.Fatalf("expected ready frida_hook args, got %#v", planHooks)
	}
	row, err = apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan)
	if err != nil {
		t.Fatalf("get saved runtime plan: %v", err)
	}
	if row == nil {
		t.Fatal("expected saved runtime_plan analysis")
	}
}

func TestAPKHandlerEvidencePackageBuildsMarkdown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.DBPath = filepath.Join(tmp, "mobileagent.db")
	s, err := store.NewStore(cfg.Storage.DBPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()
	apkStore := store.NewAPKStore(s)
	apk := &model.APK{
		ID:             util.NewID(),
		Filename:       "sample.apk",
		FilePath:       filepath.Join(tmp, "sample.apk"),
		PackageName:    "com.example.app",
		DecompiledPath: filepath.Join(tmp, "decompiled"),
		DecompiledTool: "jadx",
	}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apk.ID,
		Type:      analyzer.TypeRuntimePlan,
		Result:    `{"adb_replay":["adb shell am start -n com.example.app/.MainActivity"],"generated_hooks":[{"id":"gen-entry-trace-exec-monitor","name":"Exec","flow_ids":["flow-001"]}],"flows":[{"flow_id":"flow-001","component":"com.example.MainActivity","method":"onCreate","file":"MainActivity.java","source":{"kind":"intent_extra","line":10},"sink":{"kind":"command_exec","pattern":"Runtime.exec","line":11},"variables":["token"]}]}`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create runtime plan: %v", err)
	}
	if err := apkStore.CreateAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apk.ID,
		Type:      analyzer.TypeRuntimeEvidence,
		Result:    `{"hook_id":"gen-entry-trace-exec-monitor","evidence":{"summary":{"total":1,"entry_trace":1,"by_kind":{"exec":1}},"events":[{"kind":"exec","operation":"Runtime.exec(String)","value":"id","flow_ids":["flow-001"],"raw":"raw"}]}}`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create runtime evidence: %v", err)
	}

	h := NewAPKHandler(apkStore, runner.NewAPKRunner(cfg), cfg)
	pkg := h.buildEvidencePackage(apk)
	md := pkg["markdown"].(string)
	if !strings.Contains(md, "Verified Flows") || !strings.Contains(md, "flow-001") || !strings.Contains(md, "ADB Replay Commands") {
		t.Fatalf("unexpected evidence package markdown:\n%s", md)
	}
	runtimeEvidence := pkg["runtime_evidence"].(map[string]any)
	if verified := runtimeEvidence["verified_flows"].([]map[string]any); len(verified) != 1 {
		t.Fatalf("expected verified flow, got %#v", runtimeEvidence["verified_flows"])
	}
}
