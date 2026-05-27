package handler

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mobileagent/backend-go/internal/analyzer"
	fridapkg "github.com/mobileagent/backend-go/internal/frida"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

func TestFridaHandlerPersistsRuntimeEvidence(t *testing.T) {
	tmp := t.TempDir()
	s, err := store.NewStore(filepath.Join(tmp, "mobileagent.db"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()
	apkStore := store.NewAPKStore(s)
	apk := &model.APK{ID: util.NewID(), Filename: "sample.apk", FilePath: filepath.Join(tmp, "sample.apk")}
	if err := apkStore.Create(apk); err != nil {
		t.Fatalf("create apk: %v", err)
	}

	h := NewFridaHandler(nil, apkStore)
	evidence := fridapkg.ParseRuntimeEvidence("[ENTRY_TRACE][exec][flows=flow-001] Runtime.exec(String): id\n")
	saved, err := h.persistRuntimeEvidence(apk.ID, "emulator-5554", "com.example.app", "gen-entry-trace-exec-monitor", "", "raw output", evidence, nil)
	if err != nil {
		t.Fatalf("persist runtime evidence: %v", err)
	}
	if !saved {
		t.Fatal("expected runtime evidence to be saved")
	}
	row, err := apkStore.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence)
	if err != nil {
		t.Fatalf("get runtime evidence: %v", err)
	}
	if row == nil {
		t.Fatal("expected saved runtime_evidence analysis")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(row.Result), &payload); err != nil {
		t.Fatalf("decode runtime evidence payload: %v", err)
	}
	if payload["hook_id"] != "gen-entry-trace-exec-monitor" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	ev, _ := payload["evidence"].(map[string]any)
	summary, _ := ev["summary"].(map[string]any)
	if summary["total"] != float64(1) {
		t.Fatalf("expected one evidence event, got %#v", payload)
	}
}

func TestFridaHandlerSkipsEmptyRuntimeEvidence(t *testing.T) {
	h := NewFridaHandler(nil)
	saved, err := h.persistRuntimeEvidence("apk-id", "serial", "target", "hook", "", "no hits", fridapkg.ParseRuntimeEvidence("no hits"), nil)
	if err != nil {
		t.Fatalf("persist empty evidence: %v", err)
	}
	if saved {
		t.Fatal("expected empty evidence to be skipped")
	}
}
