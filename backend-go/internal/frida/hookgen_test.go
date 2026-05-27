package frida

import (
	"strings"
	"testing"

	"github.com/mobileagent/backend-go/internal/analyzer"
)

func TestGenerateHooksFromEntryTraceFlows(t *testing.T) {
	entryTrace := &analyzer.EntryTraceResult{
		Summary: analyzer.EntryTraceSummary{FlowsFound: 2},
		Traces: []analyzer.EntryTrace{
			{
				Component: "com.example.MainActivity",
				Flows: []analyzer.EntryFlow{
					{
						File:   "sources/com/example/MainActivity.java",
						Method: "onCreate",
						Source: analyzer.EntrySignal{
							Kind:    "intent_extra",
							Pattern: "getStringExtra",
							File:    "sources/com/example/MainActivity.java",
							Line:    10,
						},
						Sink: analyzer.EntrySignal{
							Kind:    "command_exec",
							Pattern: "Runtime.getRuntime().exec",
							File:    "sources/com/example/MainActivity.java",
							Line:    11,
						},
						Variables: []string{"token"},
						Risk:      "high",
					},
					{
						File:   "sources/com/example/MainActivity.java",
						Method: "onCreate",
						Source: analyzer.EntrySignal{
							Kind:    "intent_data",
							Pattern: "getData",
							File:    "sources/com/example/MainActivity.java",
							Line:    12,
						},
						Sink: analyzer.EntrySignal{
							Kind:    "webview",
							Pattern: "loadUrl",
							File:    "sources/com/example/MainActivity.java",
							Line:    13,
						},
						Variables: []string{"url"},
						Risk:      "high",
					},
				},
			},
		},
	}

	hooks := GenerateHooksFromAnalysis(nil, nil, nil, entryTrace)
	if len(hooks) != 2 {
		t.Fatalf("expected two entry-trace hooks, got %#v", hooks)
	}

	var execHook, webViewHook *GeneratedHook
	for i := range hooks {
		switch hooks[i].ID {
		case "gen-entry-trace-exec-monitor":
			execHook = &hooks[i]
		case "gen-entry-trace-webview-monitor":
			webViewHook = &hooks[i]
		}
	}
	if execHook == nil {
		t.Fatalf("expected Runtime.exec entry-trace hook, got %#v", hooks)
	}
	if webViewHook == nil {
		t.Fatalf("expected WebView entry-trace hook, got %#v", hooks)
	}
	if execHook.Category != "entry-trace" || !strings.Contains(execHook.Code, "Runtime.exec") || !strings.Contains(execHook.Code, "token") {
		t.Fatalf("unexpected exec hook: %#v", execHook)
	}
	if len(execHook.FlowIDs) != 1 || execHook.FlowIDs[0] != "flow-001" {
		t.Fatalf("expected exec hook flow ids, got %#v", execHook.FlowIDs)
	}
	if !strings.Contains(execHook.Code, "flow-001") || !strings.Contains(execHook.Code, "[ENTRY_TRACE][exec][flows=") {
		t.Fatalf("expected exec hook to include flow id in runtime logs: %s", execHook.Code)
	}
	if webViewHook.Category != "entry-trace" || !strings.Contains(webViewHook.Code, "loadUrl") || !strings.Contains(webViewHook.Code, "url") {
		t.Fatalf("unexpected WebView hook: %#v", webViewHook)
	}
	if len(webViewHook.FlowIDs) != 1 || webViewHook.FlowIDs[0] != "flow-002" {
		t.Fatalf("expected WebView hook flow ids, got %#v", webViewHook.FlowIDs)
	}
	if !strings.Contains(webViewHook.Code, "flow-002") || !strings.Contains(webViewHook.Code, "[ENTRY_TRACE][webview][flows=") {
		t.Fatalf("expected WebView hook to include flow id in runtime logs: %s", webViewHook.Code)
	}
}
