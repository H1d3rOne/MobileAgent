package analyzer

import "testing"

func TestSummarizeRuntimeEvidenceJSON(t *testing.T) {
	raw := `{
	  "apk_id":"apk1",
	  "serial":"emulator-5554",
	  "target":"com.example.app",
	  "hook_id":"gen-entry-trace-exec-monitor",
	  "evidence":{
	    "summary":{"total":2,"entry_trace":2,"by_kind":{"exec":1,"webview":1}},
	    "events":[
	      {"kind":"exec","operation":"Runtime.exec(String)","value":"id","flow_ids":["flow-001"],"raw":"raw1"},
	      {"kind":"webview","operation":"loadUrl","value":"https://example.test","flow_ids":["flow-002"],"raw":"raw2"}
	    ]
	  }
	}`
	summary, details, ok := SummarizeRuntimeEvidenceJSON(raw, 10)
	if !ok {
		t.Fatal("expected runtime evidence summary")
	}
	if summary["total"] != 2 || summary["entry_trace"] != 2 || summary["hook_id"] != "gen-entry-trace-exec-monitor" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	flows, _ := summary["flow_ids"].([]string)
	if len(flows) != 2 || flows[0] != "flow-001" || flows[1] != "flow-002" {
		t.Fatalf("unexpected flow ids: %#v", summary["flow_ids"])
	}
	if len(details) != 2 {
		t.Fatalf("unexpected details: %#v", details)
	}
	section := RuntimeEvidenceReportSection(summary, details)
	if section.Category != "DYNAMIC" || section.Status != "info" {
		t.Fatalf("unexpected report section: %#v", section)
	}
}

func TestRuntimeEvidenceVerifiedFlows(t *testing.T) {
	summary := map[string]any{
		"flow_ids": []string{"flow-001"},
		"events": []any{
			map[string]any{"kind": "exec", "operation": "Runtime.exec(String)", "value": "id", "flow_ids": []any{"flow-001"}},
		},
	}
	plan := `{"flows":[{"flow_id":"flow-001","component":"com.example.MainActivity","method":"onCreate","file":"MainActivity.java","risk":"high","source":{"kind":"intent_extra","line":10},"sink":{"kind":"command_exec","pattern":"Runtime.exec","line":11},"variables":["token"]}]}`
	verified := RuntimeEvidenceVerifiedFlows(summary, plan, 10)
	if len(verified) != 1 {
		t.Fatalf("expected one verified flow, got %#v", verified)
	}
	if verified[0]["flow_id"] != "flow-001" || verified[0]["component"] != "com.example.MainActivity" {
		t.Fatalf("unexpected verified flow: %#v", verified[0])
	}
	hits, _ := verified[0]["hit_events"].([]map[string]any)
	if len(hits) != 1 || hits[0]["operation"] != "Runtime.exec(String)" {
		t.Fatalf("unexpected hit events: %#v", verified[0]["hit_events"])
	}
	summary["verified_flows"] = verified
	section := RuntimeEvidenceReportSection(summary, []string{"[exec] flows=flow-001 Runtime.exec(String): id"})
	if len(section.Details) < 2 {
		t.Fatalf("expected verified flow detail in report section, got %#v", section)
	}
}

func TestSummarizeRuntimeEvidenceJSONSkipsEmpty(t *testing.T) {
	if _, _, ok := SummarizeRuntimeEvidenceJSON(`{"evidence":{"summary":{"total":0},"events":[]}}`, 10); ok {
		t.Fatal("expected empty runtime evidence to be skipped")
	}
}
